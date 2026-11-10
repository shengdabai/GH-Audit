import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import redact_email, redact_id_number, redact_phone, redact_secret
from gh_audit.scanners.base import BaseScanner, ScanConfig, iter_repo_files

_TEXT_EXTENSIONS = {
    ".txt", ".csv", ".json", ".log", ".sql", ".md",
    ".yml", ".yaml", ".xml", ".env", ".conf", ".properties",
    ".ini", ".toml", ".config",
}

_TEXT_NAME_PREFIXES = (".env",)  # catches .env.production, .env.local, etc.

def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PII_PATTERNS = [
    ("cn-phone",     r"(?<!\d)1[3-9]\d{9}(?!\d)",                          Severity.HIGH,   redact_phone,     "Replace with faker-generated data"),
    ("cn-id-number", r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
                                                                            Severity.HIGH,   redact_id_number, "Remove or anonymise PII"),
    ("email",        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", Severity.MEDIUM, redact_email,     "Use anonymised test emails"),
    ("cn-bank-card", r"(?<!\d)\d{16,19}(?!\d)",                            Severity.LOW,    redact_secret,    "Remove financial data from repo"),
]


def _is_text_file(path: Path) -> bool:
    if any(path.name.startswith(prefix) for prefix in _TEXT_NAME_PREFIXES):
        return True
    return path.suffix.lower() in _TEXT_EXTENSIONS


class PiiScanner(BaseScanner):
    name = "pii"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_repo_files(repo_path):
            if not _is_text_file(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(repo_path))
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_id, pattern, severity, redact_fn, rec in _PII_PATTERNS:
                    for match in re.finditer(pattern, line):
                        raw = match.group(0)
                        # Luhn check for bank cards to reduce false positives
                        if rule_id == "cn-bank-card" and not _luhn_check(raw):
                            continue
                        redacted = redact_fn(raw)
                        f = Finding(
                            finding_id=str(uuid.uuid4()), fingerprint="",
                            repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                            file_path=rel, line_start=lineno, line_end=lineno,
                            category=Category.PII, rule_id=rule_id,
                            title=f"PII detected: {rule_id}",
                            severity=severity, confidence=Confidence.LIKELY,
                            evidence_redacted=redacted, recommendation=rec,
                            standard_mapping=["GDPR-Art5", "OWASP-A02"],
                            scanner=self.name, discovered_at=datetime.now(timezone.utc),
                            status=Status.OPEN,
                        )
                        f.fingerprint = f.compute_fingerprint()
                        findings.append(f)
        return findings
