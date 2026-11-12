"""Local key and fingerprints for sensitive SAST match content."""

import hmac
import json
import os
import re
import secrets
import stat

from gh_audit import config


_KEY_NAME = "sast-identity-v1"
_KEY_BYTES = 32
_KEY_STORAGE_AVAILABLE = (
    all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "getuid"))
    and all(operation in os.supports_dir_fd for operation in (os.open, os.link, os.unlink, os.mkdir))
    and os.link in os.supports_follow_symlinks
)
CONTENT_ID = re.compile(r"sast-v1:[0-9a-f]{64}")


def _read_key(directory: int) -> bytes | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(_KEY_NAME, flags, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != _KEY_BYTES):
            return None
        key = stream.read(_KEY_BYTES + 1)
        return key if len(key) == _KEY_BYTES else None


def _create_key(directory: int) -> None:
    temporary = f".sast-identity-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(_KEY_BYTES))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, _KEY_NAME, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except FileExistsError:
            # A concurrent invocation already published its complete key.
            pass
    finally:
        os.unlink(temporary, dir_fd=directory)


def _open_config_directory() -> int:
    path = config._CONFIG_DIR
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(path.parent, flags)
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        return os.open(path.name, flags, dir_fd=parent)
    finally:
        os.close(parent)


def load_or_create_key() -> bytes | None:
    if not _KEY_STORAGE_AVAILABLE:
        return None
    try:
        directory = _open_config_directory()
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                return None
            try:
                return _read_key(directory)
            except FileNotFoundError:
                _create_key(directory)
                return _read_key(directory)
        finally:
            os.close(directory)
    except OSError:
        return None


def fingerprints(key: bytes, repo: str, branch: str, scanner: str, rule_id: str,
                 source: str, path: str, span: tuple[int, int, int, int] | None) -> tuple[str, str]:
    content_data = json.dumps(["sast-v1", repo.casefold(), branch, scanner, rule_id, source],
                              separators=(",", ":")).encode("ascii")
    content = "sast-v1:" + hmac.digest(key, content_data, "sha256").hex()
    location = ""
    if span is not None:
        location_data = json.dumps(["sast-location-v1", content, path, *span],
                                   separators=(",", ":")).encode("ascii")
        location = "sast-location-v1:" + hmac.digest(key, location_data, "sha256").hex()
    return location, content
