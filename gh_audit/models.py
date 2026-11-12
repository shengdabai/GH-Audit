import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Category(str, Enum):
    SECRETS = "secrets"
    PII = "pii"
    SAST = "sast"
    SCA = "sca"
    IAC = "iac"
    GOVERNANCE = "governance"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class Status(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"


@dataclass
class Finding:
    finding_id: str
    fingerprint: str
    repo: str
    branch: str
    commit_sha: str
    file_path: str
    line_start: int
    line_end: int
    category: Category
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    evidence_redacted: str
    recommendation: str
    standard_mapping: list[str]
    scanner: str
    discovered_at: datetime
    status: Status
    sast_content_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Location-aware fingerprint for within-scan deduplication."""
        if self.category == Category.SAST:
            return self.fingerprint or f"sast-unavailable:{self.finding_id}"
        raw = f"{self.category}:{self.file_path}:{self.line_start}:{self.rule_id}:{self.evidence_redacted}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def compute_content_fingerprint(self) -> str | None:
        """Content-only fingerprint for cross-scan diff (location-independent)."""
        if self.category == Category.SAST:
            return self.sast_content_id
        raw = f"{self.category}:{self.rule_id}:{self.evidence_redacted}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "content_fingerprint": self.compute_content_fingerprint(),
            "repo": self.repo,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "category": self.category.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence_redacted": self.evidence_redacted,
            "recommendation": self.recommendation,
            "standard_mapping": self.standard_mapping,
            "scanner": self.scanner,
            "discovered_at": self.discovered_at.isoformat(),
            "status": self.status.value,
        }
