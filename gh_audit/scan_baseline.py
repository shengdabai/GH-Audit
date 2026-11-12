"""Private snapshots of complete scan fingerprints for --diff."""

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from gh_audit.models import Category, Finding
from gh_audit.sast_identity import CONTENT_ID


_DIRECTORY = ".scan-baselines"
_MAX_BYTES = 32 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_SECURE_STORAGE = (
    all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "getuid"))
    and all(operation in os.supports_dir_fd
            for operation in (os.open, os.mkdir, os.stat, os.rename, os.unlink))
    and os.stat in os.supports_follow_symlinks
)


class BaselineError(RuntimeError):
    """A baseline is unavailable or could not be updated safely."""


def fingerprint_counts(findings: list[Finding]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for finding in findings:
        identity = finding.compute_content_fingerprint()
        pattern = CONTENT_ID if finding.category == Category.SAST else _SHA256
        if isinstance(identity, str) and pattern.fullmatch(identity):
            counts[identity] += 1
    return counts


def _private_regular_file(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077


def _portable_stat(path: Path, *, directory: bool, private: bool = True) -> os.stat_result:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or not info.st_ino
            or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT):
        raise BaselineError("baseline path type or identity is unsafe")
    if hasattr(os, "getuid"):
        mode = 0o077 if private else 0o022
        if info.st_uid != os.getuid() or info.st_mode & mode:
            raise BaselineError("baseline path permissions are unsafe")
    return info


def _same_portable_path(path: Path, initial: os.stat_result, *, directory: bool,
                        private: bool = True) -> None:
    try:
        current = _portable_stat(path, directory=directory, private=private)
    except FileNotFoundError as exc:
        raise BaselineError("baseline path disappeared during access") from exc
    if not os.path.samestat(initial, current):
        raise BaselineError("baseline path changed during access")


def _read_bounded(stream) -> bytes:
    if os.fstat(stream.fileno()).st_size > _MAX_BYTES:
        raise BaselineError("baseline exceeds the size limit")
    payload = stream.read(_MAX_BYTES + 1)
    if len(payload) > _MAX_BYTES:
        raise BaselineError("baseline exceeds the size limit")
    return payload


def _unique_mapping(pairs: list[tuple]) -> dict:
    mapping = dict(pairs)
    if len(mapping) != len(pairs):
        raise ValueError("duplicate baseline fields")
    return mapping


class ScanBaseline:
    def __init__(self, results_dir: Path, repo: str, branch: str, modules: list[str]):
        self.results_dir = Path(results_dir)
        scope = json.dumps([repo, branch, sorted(set(modules))], separators=(",", ":"))
        self.scope = hashlib.sha256(scope.encode("ascii")).hexdigest()
        self.name = f"{self.scope}.json"

    @contextmanager
    def _directory(self, *, create: bool = False):
        if not _SECURE_STORAGE:
            raise BaselineError("private baseline storage is unavailable")
        if create:
            self.results_dir.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root = os.open(self.results_dir, flags)
        try:
            metadata = os.fstat(root)
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
                raise BaselineError("results directory is writable by another user")
            if create:
                try:
                    os.mkdir(_DIRECTORY, mode=0o700, dir_fd=root)
                except FileExistsError:
                    pass
            directory = os.open(_DIRECTORY, flags, dir_fd=root)
            try:
                metadata = os.fstat(directory)
                if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                    raise BaselineError("baseline directory is not private")
                yield directory
            finally:
                os.close(directory)
        finally:
            os.close(root)

    def load(self) -> Counter[str] | None:
        try:
            if _SECURE_STORAGE:
                with self._directory() as directory:
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    descriptor = os.open(self.name, flags, dir_fd=directory)
                    with os.fdopen(descriptor, "rb") as stream:
                        if not _private_regular_file(os.fstat(stream.fileno())):
                            raise BaselineError("baseline is not a private file")
                        payload = _read_bounded(stream)
            else:
                payload = self._load_portable()
            data = json.loads(payload, object_pairs_hook=_unique_mapping)
            if (not isinstance(data, dict) or set(data) != {"version", "scope", "counts"}
                    or type(data["version"]) is not int or data["version"] != 1
                    or data["scope"] != self.scope or not isinstance(data["counts"], dict)):
                raise BaselineError("baseline format or scope is invalid")
            counts = data["counts"]
            if any((not _SHA256.fullmatch(identity) and not CONTENT_ID.fullmatch(identity))
                   or type(count) is not int or not 0 < count <= _MAX_BYTES
                   for identity, count in counts.items()):
                raise BaselineError("baseline contains invalid fingerprint counts")
            return Counter(counts)
        except FileNotFoundError:
            return None
        except (OSError, ValueError, RecursionError) as exc:
            raise BaselineError("could not read the baseline") from exc

    def save(self, findings: list[Finding]) -> None:
        payload = json.dumps({
            "version": 1, "scope": self.scope, "counts": fingerprint_counts(findings),
        }, separators=(",", ":")).encode("ascii")
        if len(payload) > _MAX_BYTES:
            raise BaselineError("baseline exceeds the size limit")

        try:
            if not _SECURE_STORAGE:
                self._save_portable(payload)
                return
            with self._directory(create=True) as directory:
                try:
                    metadata = os.stat(self.name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if not _private_regular_file(metadata):
                        raise BaselineError("refusing to replace an unsafe baseline")
                self._replace(directory, payload)
        except OSError as exc:
            raise BaselineError("could not save the baseline") from exc

    def _portable_directory(self, *, create: bool = False):
        if create:
            self.results_dir.mkdir(parents=True, exist_ok=True)
        root = _portable_stat(self.results_dir, directory=True, private=False)
        directory = self.results_dir / _DIRECTORY
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        info = _portable_stat(directory, directory=True)
        return directory, root, info

    def _check_portable_directory(self, directory: Path, root: os.stat_result,
                                  info: os.stat_result) -> None:
        _same_portable_path(self.results_dir, root, directory=True, private=False)
        _same_portable_path(directory, info, directory=True)

    def _load_portable(self) -> bytes:
        directory, root, info = self._portable_directory()
        path = directory / self.name
        initial = _portable_stat(path, directory=False)
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not os.path.samestat(initial, os.fstat(stream.fileno())):
                raise BaselineError("opened baseline differs from the selected file")
            self._check_portable_directory(directory, root, info)
            _same_portable_path(path, initial, directory=False)
            payload = _read_bounded(stream)
            self._check_portable_directory(directory, root, info)
            _same_portable_path(path, initial, directory=False)
        return payload

    def _save_portable(self, payload: bytes) -> None:
        directory, root, info = self._portable_directory(create=True)
        path = directory / self.name
        try:
            initial = _portable_stat(path, directory=False)
        except FileNotFoundError:
            initial = None
        descriptor, temporary_name = tempfile.mkstemp(prefix=".pending-", dir=directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                temporary_info = os.fstat(stream.fileno())
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_portable_directory(directory, root, info)
            _same_portable_path(temporary, temporary_info, directory=False)
            if initial is None:
                try:
                    path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise BaselineError("baseline appeared during update")
            else:
                _same_portable_path(path, initial, directory=False)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _replace(self, directory: int, payload: bytes) -> None:
        temporary = f".pending-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(temporary, self.name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
