import os
import json
import shutil
import subprocess
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass
from gh_audit.models import Finding

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", "dist", "build",
})


class ScanIncompleteError(RuntimeError):
    """A requested scan could not finish; an empty result would be misleading."""


def result_records(data, key, *, optional=False, nullable=False):
    value = data.get(key, []) if optional else data[key]
    if nullable and value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"invalid {key} records")
    return value


def run_json_tool(command, *, success_codes=(0, 1)):
    tool = command[0]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanIncompleteError(f"scan incomplete: {tool} could not run ({type(exc).__name__})") from exc
    if result.returncode not in success_codes:
        raise ScanIncompleteError(f"scan incomplete: {tool} exited {result.returncode}")
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        raise ScanIncompleteError(f"scan incomplete: {tool} returned invalid JSON") from exc
    if not isinstance(data, (dict, list)):
        raise ScanIncompleteError(f"scan incomplete: {tool} returned an invalid JSON structure")
    return data


def iter_repo_files(repo_path: str):
    """Walk repository files without following links or entering excluded trees."""
    for directory, dirs, files in os.walk(repo_path, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS
                   and not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file():
                yield path


@dataclass
class ScanConfig:
    repo: str
    branch: str
    commit_sha: str
    is_public: bool
    history_depth: int = 100


class BaseScanner(ABC):
    name: str = "base"

    def is_available(self) -> bool:
        return True

    @abstractmethod
    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        ...

    def _external_tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None
