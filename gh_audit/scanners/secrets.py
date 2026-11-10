import math
import re
import uuid
from datetime import datetime, timezone

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import redact_secret
from gh_audit.scanners.base import BaseScanner, ScanConfig, iter_repo_files

_PATTERNS = [
    ("aws-access-key",     r"AKIA[0-9A-Z]{16}",                        Severity.CRITICAL, "Rotate in AWS IAM console",              Confidence.CONFIRMED),
    ("github-token",       r"gh[ps]_[A-Za-z0-9]{36}",                   Severity.CRITICAL, "Revoke at github.com/settings/tokens",    Confidence.CONFIRMED),
    ("openai-api-key",     r"sk-[A-Za-z0-9]{40,}",                      Severity.CRITICAL, "Revoke at platform.openai.com",           Confidence.CONFIRMED),
    ("stripe-key",         r"sk_live_[0-9a-zA-Z]{24,}",                 Severity.CRITICAL, "Revoke in Stripe dashboard",              Confidence.CONFIRMED),
    ("generic-api-key",    r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]?([A-Za-z0-9\-_]{20,})", Severity.HIGH, "Move to environment variable",  Confidence.LIKELY),
    ("db-password",        r"(?i)(password|passwd|pwd)\s*=\s*['\"]?([^\s'\"]{8,})",        Severity.HIGH, "Use secrets manager",             Confidence.LIKELY),
    ("private-key-header", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",              Severity.CRITICAL, "Remove from repo, regenerate key", Confidence.CONFIRMED),
]

_BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
                       ".exe", ".bin", ".pyc", ".so", ".dylib", ".whl"}

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _redact_entropy_token(value: str) -> str:
    """More aggressive redaction for unclassified high-entropy tokens."""
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


class SecretsScanner(BaseScanner):
    name = "secrets"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_repo_files(repo_path):
            if path.suffix.lower() in _BINARY_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(repo_path))
            findings.extend(self._scan_text(text, rel, config))
        return findings

    def _scan_text(self, text: str, file_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            matched_spans: list[tuple[int, int]] = []
            for rule_id, pattern, severity, rec, confidence in _PATTERNS:
                if match := re.search(pattern, line):
                    # For generic password/key patterns, skip low-entropy placeholders
                    if rule_id in ("db-password", "generic-api-key"):
                        value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
                        if _shannon_entropy(value) < 3.0:
                            continue
                    matched_spans.append((match.start(), match.end()))
                    raw = match.group(0)
                    findings.append(self._make_finding(rule_id, severity, rec, file_path, lineno, raw, config, confidence=confidence))
            # Entropy check — skip tokens overlapping with already-matched spans
            for token_match in re.finditer(r"[A-Za-z0-9+/=_\-]{20,}", line):
                ts, te = token_match.start(), token_match.end()
                if any(ts < me and te > ms for ms, me in matched_spans):
                    continue
                token = token_match.group(0)
                if _shannon_entropy(token) > 4.5:
                    findings.append(self._make_finding(
                        "high-entropy-string", Severity.MEDIUM,
                        "Review whether this is a secret; move to env var if so",
                        file_path, lineno, token, config,
                        redact_fn=_redact_entropy_token,
                        confidence=Confidence.POSSIBLE,
                    ))
        return findings

    def _make_finding(self, rule_id: str, severity: Severity, rec: str,
                      file_path: str, lineno: int, raw: str, config: ScanConfig,
                      redact_fn=None, confidence: Confidence = Confidence.LIKELY) -> Finding:
        redact = redact_fn or redact_secret
        redacted = redact(raw)
        f = Finding(
            finding_id=str(uuid.uuid4()),
            fingerprint="",
            repo=config.repo,
            branch=config.branch,
            commit_sha=config.commit_sha,
            file_path=file_path,
            line_start=lineno,
            line_end=lineno,
            category=Category.SECRETS,
            rule_id=rule_id,
            title=f"Potential secret: {rule_id}",
            severity=severity,
            confidence=confidence,
            evidence_redacted=redacted,
            recommendation=rec,
            standard_mapping=["CWE-798", "OWASP-A02"],
            scanner=self.name,
            discovered_at=datetime.now(timezone.utc),
            status=Status.OPEN,
        )
        f.fingerprint = f.compute_fingerprint()
        return f
