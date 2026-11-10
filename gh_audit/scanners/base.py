import os
import shutil
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass
from gh_audit.models import Finding

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", "dist", "build",
})


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
