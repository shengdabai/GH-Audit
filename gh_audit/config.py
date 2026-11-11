import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

_CONFIG_DIR = Path.home() / ".gh-audit"
_CONFIG_FILE = _CONFIG_DIR / "config.json"


@dataclass
class Config:
    token: str | None = field(default=None, repr=False)
    modules: list[str] = field(default_factory=lambda: ["secrets", "pii", "governance"])
    output_formats: list[str] = field(default_factory=lambda: ["terminal"])
    min_severity: str = "low"
    history_depth: int = 100
    results_dir: Path = field(default_factory=lambda: _CONFIG_DIR / "results")

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        if _CONFIG_FILE.exists():
            try:
                data = json.loads(_CONFIG_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                data = {}
            cfg.token = data.get("token")
            cfg.modules = data.get("modules", cfg.modules)
            cfg.output_formats = data.get("output_formats", cfg.output_formats)
            cfg.min_severity = data.get("min_severity", cfg.min_severity)
            cfg.history_depth = data.get("history_depth", cfg.history_depth)
        return cfg

    @property
    def effective_token(self) -> str | None:
        """Use the session token for requests without saving it to disk."""
        return os.environ.get("GITHUB_TOKEN") or self.token

    def save(self) -> None:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(_CONFIG_DIR, stat.S_IRWXU)  # 0o700: owner only
        data = {
            "token": self.token,
            "modules": self.modules,
            "output_formats": self.output_formats,
            "min_severity": self.min_severity,
            "history_depth": self.history_depth,
        }
        # Set owner-only permissions before writing any credential bytes.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(_CONFIG_FILE, flags, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as stream:
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), stat.S_IRUSR | stat.S_IWUSR)
            else:
                os.chmod(_CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
            stream.write(json.dumps(data, indent=2))

    def set(self, key: str, value: str) -> None:
        if key == "token":
            self.token = value
        elif key == "min_severity":
            self.min_severity = value
        elif key == "history_depth":
            self.history_depth = int(value)
        else:
            raise ValueError(f"Unknown config key: {key}")
        self.save()
