import os
import re
import stat
import uuid
from bisect import bisect_right
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path, PureWindowsPath

from git import Repo
from git.exc import BadName, BadObject, GitError

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.sast_identity import fingerprints, load_or_create_key
from gh_audit.scanners.base import (
    BaseScanner, ScanConfig, ScanIncompleteError, result_records, run_json_tool,
)


_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_SCAN_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_READS = 256
_MAX_SOURCE_LINES = 250_000
_SAFE_WORKTREE_OPEN = (
    all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
    and os.open in os.supports_dir_fd
)
_PROTECTED = (
    ".env*", "auth.json", "*.key", "*.pem", "id_rsa*", "credentials.*",
    "secrets.*", ".ssh", ".aws", ".npmrc", ".git",
)
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_NUMBERED_LINE = re.compile(r"([1-9][0-9]{0,11}) (.*)", re.DOTALL)


def _relative_path(root: Path, filename) -> str | None:
    if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
        return None
    path = Path(filename)
    if path.is_absolute():
        if not path.is_relative_to(root):
            return None
        path = path.relative_to(root)
    normalized = path.as_posix()
    if not path.parts or ".." in path.parts or PureWindowsPath(path).anchor or "\\" in normalized:
        return None
    return normalized


def _protected(path: str) -> bool:
    return any(fnmatchcase(part.casefold(), pattern)
               for part in path.split("/") for pattern in _PROTECTED)


def _line(position: dict) -> int:
    number = position.get("line")
    return number if type(number) is int and number > 0 else 0


def _position_matches(content: bytes, lines: tuple[int, ...], offset: int, position: dict) -> bool:
    line = bisect_right(lines, offset)
    if line != _line(position):
        return False
    if "col" not in position:
        return True
    column = position["col"]
    if type(column) is not int or column < 1:
        return False
    width = offset - lines[line - 1]
    if column == width + 1:
        return True
    if width > 4096:
        return False
    return column == len(content[lines[line - 1]:offset].decode("utf-8")) + 1


def _read_worktree(root: Path, path: str, size: int) -> bytes | None:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    parts = path.split("/")
    directory = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        file = os.open(parts[-1], file_flags, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(file, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size == size:
            return stream.read(size + 1)
    return None


def _verified_sources(root: Path, commit_sha: str):
    """Cache selected files for this scanner invocation and bound total reads."""
    bytes_left, reads_left = _MAX_SCAN_SOURCE_BYTES, _MAX_SOURCE_READS
    available = (_SAFE_WORKTREE_OPEN and isinstance(commit_sha, str)
                 and re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha) is not None)

    @lru_cache(maxsize=4)
    def get(path: str) -> tuple[bytes, tuple[int, ...]] | None:
        nonlocal bytes_left, reads_left
        if not available or not reads_left or not bytes_left or _protected(path):
            return None
        reads_left -= 1
        try:
            if not stat.S_ISDIR(root.lstat().st_mode):
                return None
            with Repo(root) as repo, repo.git.custom_environment(
                GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
            ):
                commit = repo.commit(commit_sha)
                if commit.hexsha != commit_sha.lower():
                    return None
                blob = commit.tree / path
                if blob.type != "blob" or blob.mode & 0o170000 != 0o100000:
                    return None
                size = blob.size
                if not 0 < size <= _MAX_SOURCE_BYTES or size * 2 > bytes_left:
                    return None
                bytes_left -= size * 2
                content = _read_worktree(root, path, size)
                if content is None or len(content) != size or content != blob.data_stream.read(size + 1):
                    return None
            if content.count(b"\n") <= _MAX_SOURCE_LINES:
                return content, (0, *(match.end() for match in re.finditer(b"\n", content)))
        except (BadName, BadObject, GitError, KeyError, OSError, ValueError):
            pass
        return None

    return get


def _semgrep_source(source, start: dict, end: dict):
    if source is None:
        return None, None
    content, lines = source
    first, last = start.get("offset"), end.get("offset")
    if type(first) is not int or type(last) is not int or not 0 <= first < last <= len(content):
        return None, None
    try:
        if (_position_matches(content, lines, first, start)
                and _position_matches(content, lines, last, end)):
            return content[first:last].decode("utf-8"), (_line(start), _line(end), first, last)
    except UnicodeError:
        pass
    return None, None


def _source_text(value) -> str | None:
    if not isinstance(value, str) or len(value) > _MAX_SOURCE_BYTES:
        return None
    if value.strip().casefold() in {"", "requires login", "<requires login>", "[redacted]"}:
        return None
    return value


def _bandit_source(result: dict, source):
    if source is None:
        return None, None
    content, starts = source
    code = _source_text(result.get("code"))
    if code is None:
        return None, None
    numbered = [_NUMBERED_LINE.fullmatch(line) for line in code.splitlines(keepends=True)]
    if not all(numbered):
        return None, None
    lines = {int(match[1]): match[2] for match in numbered}
    first = min(lines)
    if list(lines) != list(range(first, first + len(numbered))):
        return None, None
    line = result.get("line_number")
    matched = result.get("line_range", [line])
    if (not isinstance(matched, list) or not matched
            or any(type(number) is not int or number not in lines or number > len(starts)
                   for number in matched)
            or line not in matched or sorted(set(matched)) != matched
            or matched[-1] - matched[0] + 1 != len(matched)):
        return None, None
    first, last = matched[0], matched[-1]
    start_of_line = starts[first - 1]
    end_of_line = starts[last] if last < len(starts) else len(content)
    try:
        committed = content[start_of_line:end_of_line].decode("utf-8")
        if "".join(lines[number] for number in matched) != committed:
            return None, None
        first_column, last_column = result.get("col_offset"), result.get("end_col_offset")
        last_line_start = starts[last - 1]
        first_line_end = starts[first] if first < len(starts) else len(content)
        if (line == first and type(first_column) is int and type(last_column) is int
                and 0 <= first_column < first_line_end - start_of_line
                and 0 < last_column <= end_of_line - last_line_start):
            start, end = start_of_line + first_column, last_line_start + last_column
            if start < end:
                return content[start:end].decode("utf-8"), (first, last, start, end)
        return _source_text(committed), None
    except UnicodeError:
        return None, None


def _finding(config: ScanConfig, key: bytes | None, *, scanner: str, path: str | None,
             start: int, end: int, rule, severity: Severity, source: str | None,
             span: tuple[int, int, int, int] | None, standard_mapping: list[str]) -> Finding:
    rule_id = rule if isinstance(rule, str) and _RULE_ID.fullmatch(rule) else scanner
    location_id, content_id = "", None
    if key is not None and path and start and source is not None and rule_id == rule:
        location_id, content_id = fingerprints(
            key, config.repo, config.branch, scanner, rule_id, source, path, span,
        )
    return Finding(
        finding_id=str(uuid.uuid4()), fingerprint=location_id,
        repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
        file_path=path or "(unknown file)", line_start=start, line_end=end,
        category=Category.SAST, rule_id=rule_id,
        title=f"{scanner} rule {rule_id}", severity=severity, confidence=Confidence.LIKELY,
        evidence_redacted="Matched source omitted",
        recommendation="Review and remediate the flagged code pattern",
        standard_mapping=standard_mapping, scanner=scanner,
        discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
        sast_content_id=content_id,
    )


class SastScanner(BaseScanner):
    name = "sast"

    def is_available(self) -> bool:
        return self._external_tool_available("semgrep") or self._external_tool_available("bandit")

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            path = Path(repo_path).absolute()
            root = path.parent.resolve() / path.name
            if self._external_tool_available("semgrep"):
                return self._run_semgrep(root, config)
            if self._external_tool_available("bandit"):
                return self._run_bandit(root, config)
            raise ScanIncompleteError("scan incomplete: no sast tool found")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError) as exc:
            raise ScanIncompleteError("scan incomplete: sast returned invalid or unreadable data") from exc

    def _run_semgrep(self, root: Path, config: ScanConfig) -> list[Finding]:
        # Semgrep rejects auto with metrics disabled. Its default Registry pack
        # can be requested explicitly without enabling usage metrics.
        data = run_json_tool([
            "semgrep", "--config=p/default", "--metrics=off", "--disable-version-check",
            "--json", str(root),
        ])
        if data.get("errors"):
            raise ScanIncompleteError("scan incomplete: semgrep reported scan errors")
        records = result_records(data, "results")
        key = load_or_create_key() if records else None
        verified = _verified_sources(root, config.commit_sha)
        findings = []
        severity = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        for record in records:
            extra = record.get("extra")
            extra = extra if isinstance(extra, dict) else {}
            start, end = record.get("start"), record.get("end")
            start = start if isinstance(start, dict) else {}
            end = end if isinstance(end, dict) else {}
            path = _relative_path(root, record.get("path"))
            source, span = _semgrep_source(verified(path) if key is not None and path else None, start, end)
            findings.append(_finding(
                config, key, scanner="semgrep", path=path, start=_line(start),
                end=max(_line(start), _line(end)), rule=record.get("check_id"),
                severity=severity.get(extra.get("severity"), Severity.LOW), source=source, span=span,
                standard_mapping=[],
            ))
        return findings

    def _run_bandit(self, root: Path, config: ScanConfig) -> list[Finding]:
        data = run_json_tool(["bandit", "-r", str(root), "-f", "json"])
        if data.get("errors"):
            raise ScanIncompleteError("scan incomplete: bandit reported scan errors")
        records = result_records(data, "results")
        key = load_or_create_key() if records else None
        verified = _verified_sources(root, config.commit_sha)
        findings = []
        severity = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        for record in records:
            line = _line({"line": record.get("line_number")})
            path = _relative_path(root, record.get("filename"))
            cwe = record.get("issue_cwe")
            cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
            source, span = _bandit_source(record, verified(path) if key is not None and path else None)
            findings.append(_finding(
                config, key, scanner="bandit", path=path, start=line, end=span[1] if span else line,
                rule=record.get("test_id"), severity=severity.get(record.get("issue_severity"), Severity.LOW),
                source=source, span=span, standard_mapping=[str(cwe_id)] if type(cwe_id) is int else [],
            ))
        return findings
