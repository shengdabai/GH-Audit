# gh-audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI tool that audits GitHub repositories for secrets, PII, code vulnerabilities, dependency risks, IaC issues, and governance gaps, outputting terminal/JSON/HTML reports.

**Architecture:** Mixed-mode Python — core secrets/PII/governance implemented natively in Python, optional external tools (gitleaks, semgrep, trivy, osv-scanner) detected at runtime and used when available, with graceful degradation when absent. All findings flow through a unified `Finding` dataclass → normalizer → scorer → reporter pipeline.

**Tech Stack:** Python 3.11+, Click, Rich, PyGithub, GitPython, presidio-analyzer, requests

---

## File Map

```
gh-audit/
├── gh_audit/
│   ├── __init__.py
│   ├── cli.py               # Click CLI: scan, doctor, history, suppress, config
│   ├── config.py            # Config dataclass + ~/.gh-audit/config.json r/w
│   ├── models.py            # Finding dataclass + enums
│   ├── discovery.py         # GitHub API: list repos/branches, clone to /tmp
│   ├── normalizer.py        # Deduplicate by fingerprint, redact evidence
│   ├── scorer.py            # Five-dimension risk scoring → severity
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py          # BaseScanner ABC with scan() interface
│   │   ├── secrets.py       # Entropy + regex patterns + optional gitleaks
│   │   ├── pii.py           # Presidio + Chinese regex rules
│   │   ├── governance.py    # GitHub API checks (branch protection, etc.)
│   │   ├── sast.py          # Optional semgrep / bandit
│   │   ├── sca.py           # Optional osv-scanner / OSV API fallback
│   │   └── iac.py           # Optional trivy / checkov
│   └── reporters/
│       ├── __init__.py
│       ├── terminal.py      # Rich colored output
│       ├── json_report.py   # Structured JSON with metadata
│       └── html_report.py   # Self-contained static HTML
├── tests/
│   ├── fixtures/
│   │   ├── fake_secrets.txt
│   │   ├── fake_pii.csv
│   │   └── fake_repo/       # Minimal fake git repo for integration tests
│   ├── test_models.py
│   ├── test_normalizer.py
│   ├── test_scorer.py
│   ├── test_secrets_scanner.py
│   ├── test_pii_scanner.py
│   ├── test_governance_scanner.py
│   └── test_reporters.py
├── pyproject.toml
└── README.md
```

---

## Task 1: Project Scaffold & pyproject.toml

**Files:**
- Create: `gh_audit/__init__.py`
- Create: `pyproject.toml`
- Create: `tests/__init__.py`
- Create: `tests/fixtures/fake_secrets.txt`
- Create: `tests/fixtures/fake_pii.csv`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "gh-audit"
version = "0.1.0"
description = "GitHub repository security audit tool"
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "PyGithub>=2.1",
    "gitpython>=3.1",
    "presidio-analyzer>=2.2",
    "presidio-nlp-engine-provider>=0.0.1",
    "spacy>=3.7",
    "requests>=2.31",
]

[project.scripts]
gh-audit = "gh_audit.cli:cli"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-mock>=3.12",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create package init**

```python
# gh_audit/__init__.py
__version__ = "0.1.0"
```

- [ ] **Step 3: Create test fixtures**

`tests/fixtures/fake_secrets.txt`:
```
# This file contains FAKE secrets for testing only
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234
OPENAI_API_KEY=sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
DATABASE_URL=postgresql://admin:password123@localhost:5432/mydb
```

`tests/fixtures/fake_pii.csv`:
```
name,phone,email,id_number
张三,13812345678,zhangsan@example.com,110101199001011234
李四,15987654321,lisi@test.com,310115198505052345
```

- [ ] **Step 4: Install in dev mode**

```bash
cd ~/Desktop/gh-audit
pip install -e ".[dev]"
```

Expected: Successfully installed gh-audit-0.1.0

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git init
git add pyproject.toml gh_audit/__init__.py tests/
git commit -m "chore: scaffold project with pyproject.toml and test fixtures"
```

---

## Task 2: Core Data Models

**Files:**
- Create: `gh_audit/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_models.py
from datetime import datetime
from gh_audit.models import Finding, Category, Severity, Confidence, Status

def test_finding_fingerprint_is_deterministic():
    f = Finding(
        finding_id="test-id",
        fingerprint="",
        repo="org/repo",
        branch="main",
        commit_sha="abc123",
        file_path="config/.env",
        line_start=1,
        line_end=1,
        category=Category.SECRETS,
        rule_id="aws-access-key",
        title="AWS Access Key",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate this key immediately",
        standard_mapping=["CWE-798"],
        scanner="builtin",
        discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    fp1 = f.compute_fingerprint()
    fp2 = f.compute_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex

def test_finding_to_dict_has_all_fields():
    f = Finding(
        finding_id="test-id",
        fingerprint="abc",
        repo="org/repo",
        branch="main",
        commit_sha="abc123",
        file_path="config/.env",
        line_start=1,
        line_end=1,
        category=Category.SECRETS,
        rule_id="aws-access-key",
        title="AWS Access Key",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate key",
        standard_mapping=[],
        scanner="builtin",
        discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    d = f.to_dict()
    assert d["repo"] == "org/repo"
    assert d["severity"] == "critical"
    assert d["category"] == "secrets"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_models.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement models.py**

```python
# gh_audit/models.py
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Literal


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

    def compute_fingerprint(self) -> str:
        raw = f"{self.category}:{self.file_path}:{self.line_start}:{self.rule_id}:{self.evidence_redacted}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_models.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/models.py tests/test_models.py
git commit -m "feat: add Finding dataclass with fingerprinting and serialization"
```

---

## Task 3: Normalizer & Scorer

**Files:**
- Create: `gh_audit/normalizer.py`
- Create: `gh_audit/scorer.py`
- Create: `tests/test_normalizer.py`
- Create: `tests/test_scorer.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_normalizer.py
from datetime import datetime
from gh_audit.models import Finding, Category, Severity, Confidence, Status
from gh_audit.normalizer import deduplicate, redact_secret, redact_phone, redact_email, redact_id_number

def _make_finding(**kwargs):
    defaults = dict(
        finding_id="id1", fingerprint="", repo="org/r", branch="main",
        commit_sha="abc", file_path="f.py", line_start=1, line_end=1,
        category=Category.SECRETS, rule_id="rule", title="T",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        evidence_redacted="", recommendation="fix", standard_mapping=[],
        scanner="builtin", discovered_at=datetime(2026,4,21), status=Status.OPEN,
    )
    defaults.update(kwargs)
    return Finding(**defaults)

def test_deduplicate_removes_same_fingerprint():
    f1 = _make_finding(fingerprint="same")
    f2 = _make_finding(fingerprint="same")
    result = deduplicate([f1, f2])
    assert len(result) == 1

def test_deduplicate_keeps_different_fingerprints():
    f1 = _make_finding(fingerprint="aaa")
    f2 = _make_finding(fingerprint="bbb")
    result = deduplicate([f1, f2])
    assert len(result) == 2

def test_redact_secret_masks_middle():
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

def test_redact_phone():
    assert redact_phone("13812345678") == "138****5678"

def test_redact_email():
    assert redact_email("user@example.com") == "u***@example.com"

def test_redact_id_number():
    assert redact_id_number("110101199001011234") == "1101***********1234"
```

```python
# tests/test_scorer.py
from gh_audit.models import Severity, Confidence
from gh_audit.scorer import score_finding

def test_critical_confirmed_scores_highest():
    score = score_finding(Severity.CRITICAL, Confidence.CONFIRMED, is_public=True)
    assert score >= 90

def test_low_possible_scores_lowest():
    score = score_finding(Severity.LOW, Confidence.POSSIBLE, is_public=False)
    assert score <= 30

def test_public_repo_scores_higher_than_private():
    pub = score_finding(Severity.HIGH, Confidence.LIKELY, is_public=True)
    priv = score_finding(Severity.HIGH, Confidence.LIKELY, is_public=False)
    assert pub > priv
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_normalizer.py tests/test_scorer.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement normalizer.py**

```python
# gh_audit/normalizer.py
import re
from gh_audit.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            result.append(f)
    return result


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def redact_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11:
        return digits[:3] + "****" + digits[-4:]
    return "***"


def redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "***"
    return local[0] + "***@" + domain


def redact_id_number(value: str) -> str:
    if len(value) == 18:
        return value[:4] + "*" * 10 + value[-4:]
    return "***"
```

- [ ] **Step 4: Implement scorer.py**

```python
# gh_audit/scorer.py
from gh_audit.models import Severity, Confidence

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_CONFIDENCE_WEIGHT = {
    Confidence.CONFIRMED: 1.0,
    Confidence.LIKELY: 0.7,
    Confidence.POSSIBLE: 0.4,
}


def score_finding(severity: Severity, confidence: Confidence, is_public: bool) -> int:
    sev = _SEVERITY_WEIGHT[severity]
    conf = _CONFIDENCE_WEIGHT[confidence]
    exposure = 1.2 if is_public else 1.0
    raw = sev * conf * exposure * 4  # scale to ~0-24, then normalise to 0-100
    return min(100, int(raw / 24 * 100))
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_normalizer.py tests/test_scorer.py -v
```

Expected: 8 passed

- [ ] **Step 6: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/normalizer.py gh_audit/scorer.py tests/test_normalizer.py tests/test_scorer.py
git commit -m "feat: add normalizer (dedup+redaction) and risk scorer"
```

---

## Task 4: BaseScanner

**Files:**
- Create: `gh_audit/scanners/__init__.py`
- Create: `gh_audit/scanners/base.py`

- [ ] **Step 1: Implement base scanner ABC**

```python
# gh_audit/scanners/__init__.py
```

```python
# gh_audit/scanners/base.py
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from gh_audit.models import Finding


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
```

- [ ] **Step 2: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/scanners/
git commit -m "feat: add BaseScanner ABC with ScanConfig"
```

---

## Task 5: Secrets Scanner

**Files:**
- Create: `gh_audit/scanners/secrets.py`
- Create: `tests/test_secrets_scanner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_secrets_scanner.py
import os, tempfile
from gh_audit.scanners.secrets import SecretsScanner
from gh_audit.scanners.base import ScanConfig

def _make_config():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc123", is_public=False)

def test_detects_aws_key_pattern(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    scanner = SecretsScanner()
    findings = scanner.scan(str(tmp_path), _make_config())
    assert any("aws" in f.rule_id.lower() for f in findings)

def test_detects_high_entropy_string(tmp_path):
    (tmp_path / "secret.txt").write_text("TOKEN=xK9mP2qR7nL4wB6vY1sZ3hA8cE5jF0uG\n")
    scanner = SecretsScanner()
    findings = scanner.scan(str(tmp_path), _make_config())
    assert len(findings) >= 1

def test_skips_binary_files(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    scanner = SecretsScanner()
    findings = scanner.scan(str(tmp_path), _make_config())
    assert len(findings) == 0

def test_redacts_evidence(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    scanner = SecretsScanner()
    findings = scanner.scan(str(tmp_path), _make_config())
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence_redacted
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_secrets_scanner.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement secrets.py**

```python
# gh_audit/scanners/secrets.py
import math
import re
import uuid
from datetime import datetime
from pathlib import Path

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import redact_secret
from gh_audit.scanners.base import BaseScanner, ScanConfig

_PATTERNS = [
    ("aws-access-key",     r"AKIA[0-9A-Z]{16}",                       Severity.CRITICAL, "Rotate in AWS IAM console"),
    ("github-token",       r"gh[ps]_[A-Za-z0-9]{36}",                  Severity.CRITICAL, "Revoke at github.com/settings/tokens"),
    ("openai-api-key",     r"sk-[A-Za-z0-9]{40,}",                     Severity.CRITICAL, "Revoke at platform.openai.com"),
    ("stripe-key",         r"sk_live_[0-9a-zA-Z]{24,}",                Severity.CRITICAL, "Revoke in Stripe dashboard"),
    ("generic-api-key",    r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]?([A-Za-z0-9\-_]{20,})", Severity.HIGH, "Move to environment variable"),
    ("db-password",        r"(?i)(password|passwd|pwd)\s*=\s*['\"]?([^\s'\"]{8,})",        Severity.HIGH, "Use secrets manager"),
    ("private-key-header", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",             Severity.CRITICAL, "Remove from repo, regenerate key"),
]

_BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
                       ".exe", ".bin", ".pyc", ".so", ".dylib", ".whl"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


class SecretsScanner(BaseScanner):
    name = "secrets"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path in Path(repo_path).rglob("*"):
            if not path.is_file():
                continue
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
            for rule_id, pattern, severity, rec in _PATTERNS:
                if re.search(pattern, line):
                    match = re.search(pattern, line)
                    raw = match.group(0) if match else line[:40]
                    f = self._make_finding(rule_id, severity, rec, file_path, lineno, raw, config)
                    findings.append(f)
            # Entropy check for long tokens
            for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", line):
                if _shannon_entropy(token) > 4.5:
                    f = self._make_finding(
                        "high-entropy-string", Severity.MEDIUM,
                        "Review whether this is a secret; move to env var if so",
                        file_path, lineno, token, config,
                    )
                    findings.append(f)
        return findings

    def _make_finding(self, rule_id: str, severity: Severity, rec: str,
                      file_path: str, lineno: int, raw: str, config: ScanConfig) -> Finding:
        redacted = redact_secret(raw)
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
            confidence=Confidence.LIKELY,
            evidence_redacted=redacted,
            recommendation=rec,
            standard_mapping=["CWE-798", "OWASP-A02"],
            scanner=self.name,
            discovered_at=datetime.utcnow(),
            status=Status.OPEN,
        )
        f.fingerprint = f.compute_fingerprint()
        return f
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_secrets_scanner.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/scanners/secrets.py tests/test_secrets_scanner.py
git commit -m "feat: add secrets scanner with regex patterns and entropy detection"
```

---

## Task 6: PII Scanner

**Files:**
- Create: `gh_audit/scanners/pii.py`
- Create: `tests/test_pii_scanner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_pii_scanner.py
from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.base import ScanConfig

def _cfg():
    return ScanConfig(repo="org/r", branch="main", commit_sha="abc", is_public=False)

def test_detects_chinese_phone(tmp_path):
    (tmp_path / "data.csv").write_text("name,phone\n张三,13812345678\n")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "cn-phone" for f in findings)

def test_detects_chinese_id_number(tmp_path):
    (tmp_path / "data.txt").write_text("id=110101199001011234\n")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "cn-id-number" for f in findings)

def test_detects_email(tmp_path):
    (tmp_path / "users.txt").write_text("email: user@example.com\n")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    assert any(f.rule_id == "email" for f in findings)

def test_redacts_phone_in_evidence(tmp_path):
    (tmp_path / "data.csv").write_text("13812345678\n")
    findings = PiiScanner().scan(str(tmp_path), _cfg())
    for f in findings:
        assert "13812345678" not in f.evidence_redacted
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_pii_scanner.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement pii.py**

```python
# gh_audit/scanners/pii.py
import re
import uuid
from datetime import datetime
from pathlib import Path

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.normalizer import redact_email, redact_id_number, redact_phone, redact_secret
from gh_audit.scanners.base import BaseScanner, ScanConfig

_TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".sql", ".md", ".yml", ".yaml", ".xml", ".env"}

_PII_PATTERNS = [
    ("cn-phone",    r"(?<!\d)1[3-9]\d{9}(?!\d)",                         Severity.HIGH,   redact_phone,     "Replace with faker-generated data"),
    ("cn-id-number",r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
                                                                          Severity.HIGH,   redact_id_number, "Remove or anonymise PII"),
    ("email",       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", Severity.MEDIUM, redact_email,     "Use anonymised test emails"),
    ("cn-bank-card",r"(?<!\d)\d{16,19}(?!\d)",                            Severity.HIGH,   redact_secret,    "Remove financial data from repo"),
]


class PiiScanner(BaseScanner):
    name = "pii"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path in Path(repo_path).rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _TEXT_EXTENSIONS:
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
                        redacted = redact_fn(raw)
                        f = Finding(
                            finding_id=str(uuid.uuid4()),
                            fingerprint="",
                            repo=config.repo,
                            branch=config.branch,
                            commit_sha=config.commit_sha,
                            file_path=rel,
                            line_start=lineno,
                            line_end=lineno,
                            category=Category.PII,
                            rule_id=rule_id,
                            title=f"PII detected: {rule_id}",
                            severity=severity,
                            confidence=Confidence.LIKELY,
                            evidence_redacted=redacted,
                            recommendation=rec,
                            standard_mapping=["GDPR-Art5", "OWASP-A02"],
                            scanner=self.name,
                            discovered_at=datetime.utcnow(),
                            status=Status.OPEN,
                        )
                        f.fingerprint = f.compute_fingerprint()
                        findings.append(f)
        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_pii_scanner.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/scanners/pii.py tests/test_pii_scanner.py
git commit -m "feat: add PII scanner with Chinese phone/ID/bank-card and email detection"
```

---

## Task 7: Governance Scanner

**Files:**
- Create: `gh_audit/scanners/governance.py`
- Create: `tests/test_governance_scanner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_governance_scanner.py
from unittest.mock import MagicMock, patch
from gh_audit.scanners.governance import GovernanceScanner
from gh_audit.scanners.base import ScanConfig

def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="HEAD", is_public=False)

def test_no_branch_protection_is_high_finding():
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.protected = False
    mock_repo.get_branch.return_value = mock_branch
    mock_repo.default_branch = "main"
    mock_repo.get_contents.side_effect = Exception("404")

    with patch("gh_audit.scanners.governance.Github") as MockGH:
        MockGH.return_value.get_repo.return_value = mock_repo
        scanner = GovernanceScanner(token="fake")
        findings = scanner.scan("", _cfg())

    branch_findings = [f for f in findings if f.rule_id == "no-branch-protection"]
    assert len(branch_findings) == 1
    assert branch_findings[0].severity.value in ("high", "medium")

def test_missing_security_md_is_finding():
    mock_repo = MagicMock()
    mock_branch = MagicMock()
    mock_branch.protected = True
    mock_repo.get_branch.return_value = mock_branch
    mock_repo.default_branch = "main"
    mock_repo.get_contents.side_effect = Exception("404")

    with patch("gh_audit.scanners.governance.Github") as MockGH:
        MockGH.return_value.get_repo.return_value = mock_repo
        scanner = GovernanceScanner(token="fake")
        findings = scanner.scan("", _cfg())

    assert any(f.rule_id == "missing-security-md" for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_governance_scanner.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement governance.py**

```python
# gh_audit/scanners/governance.py
import uuid
from datetime import datetime

from github import Github, GithubException

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig


class GovernanceScanner(BaseScanner):
    name = "governance"

    def __init__(self, token: str | None = None):
        self._token = token

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        gh = Github(self._token)
        try:
            repo = gh.get_repo(config.repo)
        except GithubException as e:
            return [self._make(config, "github-api-error", f"Cannot access repo: {e}",
                               Severity.INFO, "Check token permissions")]

        findings: list[Finding] = []

        # Branch protection
        try:
            branch = repo.get_branch(repo.default_branch)
            if not branch.protected:
                findings.append(self._make(
                    config, "no-branch-protection",
                    f"Default branch '{repo.default_branch}' has no protection rules",
                    Severity.HIGH, "Enable branch protection in Settings → Branches",
                ))
        except GithubException:
            pass

        # SECURITY.md
        for fname in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            try:
                repo.get_contents(fname)
                break
            except Exception:
                continue
        else:
            findings.append(self._make(
                config, "missing-security-md",
                "No SECURITY.md found",
                Severity.LOW, "Add SECURITY.md with vulnerability reporting instructions",
            ))

        # CODEOWNERS
        for fname in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            try:
                repo.get_contents(fname)
                break
            except Exception:
                continue
        else:
            findings.append(self._make(
                config, "missing-codeowners",
                "No CODEOWNERS file found",
                Severity.LOW, "Add CODEOWNERS to enforce review requirements",
            ))

        return findings

    def _make(self, config: ScanConfig, rule_id: str, title: str,
              severity: Severity, rec: str) -> Finding:
        f = Finding(
            finding_id=str(uuid.uuid4()),
            fingerprint="",
            repo=config.repo,
            branch=config.branch,
            commit_sha=config.commit_sha,
            file_path="(repository)",
            line_start=0,
            line_end=0,
            category=Category.GOVERNANCE,
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence_redacted=title,
            recommendation=rec,
            standard_mapping=["SLSA-L1", "OpenSSF-Scorecard"],
            scanner=self.name,
            discovered_at=datetime.utcnow(),
            status=Status.OPEN,
        )
        f.fingerprint = f.compute_fingerprint()
        return f
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_governance_scanner.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/scanners/governance.py tests/test_governance_scanner.py
git commit -m "feat: add governance scanner (branch protection, SECURITY.md, CODEOWNERS)"
```

---

## Task 8: Optional Scanners (SAST / SCA / IaC)

**Files:**
- Create: `gh_audit/scanners/sast.py`
- Create: `gh_audit/scanners/sca.py`
- Create: `gh_audit/scanners/iac.py`

- [ ] **Step 1: Implement sast.py (semgrep wrapper)**

```python
# gh_audit/scanners/sast.py
import json
import subprocess
import uuid
from datetime import datetime

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig


class SastScanner(BaseScanner):
    name = "sast"

    def is_available(self) -> bool:
        return self._external_tool_available("semgrep") or self._external_tool_available("bandit")

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        if self._external_tool_available("semgrep"):
            return self._run_semgrep(repo_path, config)
        if self._external_tool_available("bandit"):
            return self._run_bandit(repo_path, config)
        return []

    def _run_semgrep(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", repo_path],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
        except Exception:
            return []
        findings = []
        for r in data.get("results", []):
            sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
            sev = sev_map.get(r.get("extra", {}).get("severity", "INFO"), Severity.LOW)
            f = Finding(
                finding_id=str(uuid.uuid4()), fingerprint="",
                repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                file_path=r.get("path", ""), line_start=r.get("start", {}).get("line", 0),
                line_end=r.get("end", {}).get("line", 0),
                category=Category.SAST, rule_id=r.get("check_id", "semgrep"),
                title=r.get("extra", {}).get("message", "SAST finding"),
                severity=sev, confidence=Confidence.LIKELY,
                evidence_redacted=r.get("extra", {}).get("lines", "")[:80],
                recommendation="Review and remediate the flagged code pattern",
                standard_mapping=[], scanner="semgrep",
                discovered_at=datetime.utcnow(), status=Status.OPEN,
            )
            f.fingerprint = f.compute_fingerprint()
            findings.append(f)
        return findings

    def _run_bandit(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
        except Exception:
            return []
        findings = []
        for r in data.get("results", []):
            sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
            sev = sev_map.get(r.get("issue_severity", "LOW"), Severity.LOW)
            f = Finding(
                finding_id=str(uuid.uuid4()), fingerprint="",
                repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                file_path=r.get("filename", ""), line_start=r.get("line_number", 0),
                line_end=r.get("line_number", 0),
                category=Category.SAST, rule_id=r.get("test_id", "bandit"),
                title=r.get("issue_text", "Bandit finding"),
                severity=sev, confidence=Confidence.LIKELY,
                evidence_redacted=r.get("code", "")[:80],
                recommendation=r.get("more_info", "Review bandit finding"),
                standard_mapping=[r.get("issue_cwe", {}).get("id", "")],
                scanner="bandit",
                discovered_at=datetime.utcnow(), status=Status.OPEN,
            )
            f.fingerprint = f.compute_fingerprint()
            findings.append(f)
        return findings
```

- [ ] **Step 2: Implement sca.py (osv-scanner wrapper + API fallback)**

```python
# gh_audit/scanners/sca.py
import json
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

import requests

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig


class ScaScanner(BaseScanner):
    name = "sca"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        if self._external_tool_available("osv-scanner"):
            return self._run_osv_scanner(repo_path, config)
        return self._osv_api_fallback(repo_path, config)

    def _run_osv_scanner(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["osv-scanner", "--format=json", repo_path],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
        except Exception:
            return []
        findings = []
        for r in data.get("results", []):
            for pkg in r.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    f = Finding(
                        finding_id=str(uuid.uuid4()), fingerprint="",
                        repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                        file_path=r.get("source", {}).get("path", ""),
                        line_start=0, line_end=0,
                        category=Category.SCA,
                        rule_id=vuln.get("id", "unknown-vuln"),
                        title=f"Vulnerable dependency: {pkg.get('package', {}).get('name', '?')} - {vuln.get('id', '?')}",
                        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        evidence_redacted=f"{pkg.get('package', {}).get('name')}@{pkg.get('package', {}).get('version')}",
                        recommendation="Upgrade to a patched version",
                        standard_mapping=[vuln.get("id", "")],
                        scanner="osv-scanner",
                        discovered_at=datetime.utcnow(), status=Status.OPEN,
                    )
                    f.fingerprint = f.compute_fingerprint()
                    findings.append(f)
        return findings

    def _osv_api_fallback(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        lock_files = list(Path(repo_path).rglob("requirements*.txt")) + \
                     list(Path(repo_path).rglob("package-lock.json"))
        findings = []
        for lock in lock_files[:5]:  # limit to 5 lock files
            try:
                text = lock.read_text(encoding="utf-8", errors="ignore")
                packages = self._parse_requirements(text)
                for pkg, version in packages[:20]:  # limit API calls
                    vulns = self._query_osv_api(pkg, version)
                    for v in vulns:
                        f = Finding(
                            finding_id=str(uuid.uuid4()), fingerprint="",
                            repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                            file_path=str(lock.relative_to(repo_path)),
                            line_start=0, line_end=0,
                            category=Category.SCA,
                            rule_id=v.get("id", "osv-vuln"),
                            title=f"Vulnerable dependency: {pkg}=={version} ({v.get('id', '?')})",
                            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            evidence_redacted=f"{pkg}=={version}",
                            recommendation="Upgrade to a patched version (check osv.dev)",
                            standard_mapping=[v.get("id", "")],
                            scanner="osv-api",
                            discovered_at=datetime.utcnow(), status=Status.OPEN,
                        )
                        f.fingerprint = f.compute_fingerprint()
                        findings.append(f)
            except Exception:
                continue
        return findings

    def _parse_requirements(self, text: str) -> list[tuple[str, str]]:
        import re
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
            if m:
                results.append((m.group(1), m.group(2)))
        return results

    def _query_osv_api(self, package: str, version: str) -> list[dict]:
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": package, "ecosystem": "PyPI"}},
                timeout=5,
            )
            return resp.json().get("vulns", [])
        except Exception:
            return []
```

- [ ] **Step 3: Implement iac.py (trivy wrapper)**

```python
# gh_audit/scanners/iac.py
import json
import subprocess
import uuid
from datetime import datetime

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig


class IacScanner(BaseScanner):
    name = "iac"

    def is_available(self) -> bool:
        return self._external_tool_available("trivy") or self._external_tool_available("checkov")

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        if self._external_tool_available("trivy"):
            return self._run_trivy(repo_path, config)
        if self._external_tool_available("checkov"):
            return self._run_checkov(repo_path, config)
        return []

    def _run_trivy(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["trivy", "config", "--format=json", repo_path],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
        except Exception:
            return []
        findings = []
        for result_item in data.get("Results", []):
            for misc in result_item.get("Misconfigurations", []):
                sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                           "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                sev = sev_map.get(misc.get("Severity", "LOW"), Severity.LOW)
                f = Finding(
                    finding_id=str(uuid.uuid4()), fingerprint="",
                    repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                    file_path=result_item.get("Target", ""),
                    line_start=misc.get("CauseMetadata", {}).get("StartLine", 0),
                    line_end=misc.get("CauseMetadata", {}).get("EndLine", 0),
                    category=Category.IAC,
                    rule_id=misc.get("ID", "trivy-iac"),
                    title=misc.get("Title", "IaC misconfiguration"),
                    severity=sev, confidence=Confidence.CONFIRMED,
                    evidence_redacted=misc.get("Message", "")[:100],
                    recommendation=misc.get("Resolution", "Review IaC configuration"),
                    standard_mapping=[misc.get("ID", "")],
                    scanner="trivy",
                    discovered_at=datetime.utcnow(), status=Status.OPEN,
                )
                f.fingerprint = f.compute_fingerprint()
                findings.append(f)
        return findings

    def _run_checkov(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["checkov", "-d", repo_path, "--output", "json"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
        except Exception:
            return []
        findings = []
        checks = data if isinstance(data, list) else [data]
        for check_result in checks:
            for r in check_result.get("results", {}).get("failed_checks", []):
                f = Finding(
                    finding_id=str(uuid.uuid4()), fingerprint="",
                    repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                    file_path=r.get("repo_file_path", ""),
                    line_start=r.get("file_line_range", [0, 0])[0],
                    line_end=r.get("file_line_range", [0, 0])[1],
                    category=Category.IAC,
                    rule_id=r.get("check_id", "checkov"),
                    title=r.get("check_name", "Checkov finding"),
                    severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                    evidence_redacted=r.get("check_id", "")[:80],
                    recommendation="Review and fix the IaC misconfiguration",
                    standard_mapping=[r.get("check_id", "")],
                    scanner="checkov",
                    discovered_at=datetime.utcnow(), status=Status.OPEN,
                )
                f.fingerprint = f.compute_fingerprint()
                findings.append(f)
        return findings
```

- [ ] **Step 4: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/scanners/sast.py gh_audit/scanners/sca.py gh_audit/scanners/iac.py
git commit -m "feat: add optional SAST/SCA/IaC scanners with external tool wrappers"
```

---

## Task 9: Reporters

**Files:**
- Create: `gh_audit/reporters/__init__.py`
- Create: `gh_audit/reporters/terminal.py`
- Create: `gh_audit/reporters/json_report.py`
- Create: `gh_audit/reporters/html_report.py`
- Create: `tests/test_reporters.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_reporters.py
import json
from datetime import datetime
from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.html_report import HtmlReporter

def _finding():
    f = Finding(
        finding_id="abc", fingerprint="fp1",
        repo="org/repo", branch="main", commit_sha="abc123",
        file_path="app/config.py", line_start=10, line_end=10,
        category=Category.SECRETS, rule_id="aws-key",
        title="AWS Key", severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate key",
        standard_mapping=["CWE-798"],
        scanner="builtin",
        discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    return f

def test_json_reporter_produces_valid_json(tmp_path):
    out = tmp_path / "report.json"
    JsonReporter().write([_finding()], str(out), repo="org/repo")
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["severity"] == "critical"

def test_html_reporter_produces_html_file(tmp_path):
    out = tmp_path / "report.html"
    HtmlReporter().write([_finding()], str(out), repo="org/repo")
    content = out.read_text()
    assert "<!DOCTYPE html>" in content
    assert "AWS Key" in content
    assert "AKIAIOSFODNN7EXAMPLE" not in content  # must be redacted
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_reporters.py -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement reporters**

```python
# gh_audit/reporters/__init__.py
```

```python
# gh_audit/reporters/json_report.py
import json
from datetime import datetime
from gh_audit.models import Finding, Severity


class JsonReporter:
    def write(self, findings: list[Finding], output_path: str, repo: str) -> None:
        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        }
        data = {
            "repo": repo,
            "scanned_at": datetime.utcnow().isoformat(),
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
```

```python
# gh_audit/reporters/html_report.py
from datetime import datetime
from gh_audit.models import Finding, Severity

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#6b7280",
}


class HtmlReporter:
    def write(self, findings: list[Finding], output_path: str, repo: str) -> None:
        rows = ""
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity.value, "#6b7280")
            rows += f"""
            <tr>
              <td><span style="color:{color};font-weight:bold">{f.severity.value.upper()}</span></td>
              <td>{f.category.value}</td>
              <td>{f.title}</td>
              <td><code>{f.file_path}:{f.line_start}</code></td>
              <td><code>{f.evidence_redacted}</code></td>
              <td>{f.recommendation}</td>
            </tr>"""

        summary_counts = {s: sum(1 for f in findings if f.severity.value == s)
                          for s in ("critical", "high", "medium", "low")}

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>gh-audit: {repo}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #1f2937; }}
    h1 {{ color: #111827; }}
    .summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
    .badge {{ padding: .4rem .8rem; border-radius: .4rem; color: white; font-weight: bold; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #e5e7eb; padding: .5rem .75rem; text-align: left; font-size:.875rem; }}
    th {{ background: #f9fafb; }}
    code {{ background: #f3f4f6; padding: .1rem .3rem; border-radius: .2rem; }}
  </style>
</head>
<body>
  <h1>gh-audit Report: {repo}</h1>
  <p>Scanned at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
  <div class="summary">
    <span class="badge" style="background:#dc2626">{summary_counts['critical']} Critical</span>
    <span class="badge" style="background:#ea580c">{summary_counts['high']} High</span>
    <span class="badge" style="background:#d97706">{summary_counts['medium']} Medium</span>
    <span class="badge" style="background:#65a30d">{summary_counts['low']} Low</span>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Evidence</th><th>Recommendation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
```

```python
# gh_audit/reporters/terminal.py
from rich.console import Console
from rich.table import Table
from rich import box
from gh_audit.models import Finding, Severity

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "green",
    "info": "dim",
}

console = Console()


class TerminalReporter:
    def print(self, findings: list[Finding], repo: str) -> None:
        console.rule(f"[bold]gh-audit: {repo}[/bold]")

        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Category", width=12)
        table.add_column("Title", width=30)
        table.add_column("Location", width=30)
        table.add_column("Evidence", width=25)
        table.add_column("Recommendation", width=35)

        for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
            style = _SEVERITY_STYLE.get(f.severity.value, "")
            table.add_row(
                f"[{style}]{f.severity.value.upper()}[/{style}]",
                f.category.value,
                f.title,
                f"{f.file_path}:{f.line_start}",
                f.evidence_redacted,
                f.recommendation,
            )

        console.print(table)

        counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
        console.rule()
        console.print(
            f"[bold red]{counts['critical']} critical[/] · "
            f"[bold orange1]{counts['high']} high[/] · "
            f"[bold yellow]{counts['medium']} medium[/] · "
            f"[green]{counts['low']} low[/]"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Desktop/gh-audit && pytest tests/test_reporters.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/reporters/ tests/test_reporters.py
git commit -m "feat: add terminal/JSON/HTML reporters"
```

---

## Task 10: Config & Discovery

**Files:**
- Create: `gh_audit/config.py`
- Create: `gh_audit/discovery.py`

- [ ] **Step 1: Implement config.py**

```python
# gh_audit/config.py
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

_CONFIG_DIR = Path.home() / ".gh-audit"
_CONFIG_FILE = _CONFIG_DIR / "config.json"


@dataclass
class Config:
    token: str | None = None
    modules: list[str] = field(default_factory=lambda: ["secrets", "pii", "governance"])
    output_formats: list[str] = field(default_factory=lambda: ["terminal"])
    min_severity: str = "low"
    history_depth: int = 100
    results_dir: Path = field(default_factory=lambda: _CONFIG_DIR / "results")

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        cfg.token = os.environ.get("GITHUB_TOKEN")
        if _CONFIG_FILE.exists():
            data = json.loads(_CONFIG_FILE.read_text())
            if not cfg.token:
                cfg.token = data.get("token")
            cfg.modules = data.get("modules", cfg.modules)
            cfg.output_formats = data.get("output_formats", cfg.output_formats)
            cfg.min_severity = data.get("min_severity", cfg.min_severity)
            cfg.history_depth = data.get("history_depth", cfg.history_depth)
        return cfg

    def save(self) -> None:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "token": self.token,
            "modules": self.modules,
            "output_formats": self.output_formats,
            "min_severity": self.min_severity,
            "history_depth": self.history_depth,
        }
        _CONFIG_FILE.write_text(json.dumps(data, indent=2))

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
```

- [ ] **Step 2: Implement discovery.py**

```python
# gh_audit/discovery.py
import shutil
import tempfile
from dataclasses import dataclass

import git
from github import Github, GithubException


@dataclass
class RepoInfo:
    full_name: str
    default_branch: str
    is_public: bool
    clone_url: str
    head_sha: str


def list_org_repos(org_name: str, token: str | None = None) -> list[RepoInfo]:
    gh = Github(token)
    org = gh.get_organization(org_name)
    repos = []
    for repo in org.get_repos():
        try:
            branch = repo.get_branch(repo.default_branch)
            repos.append(RepoInfo(
                full_name=repo.full_name,
                default_branch=repo.default_branch,
                is_public=not repo.private,
                clone_url=repo.clone_url,
                head_sha=branch.commit.sha,
            ))
        except GithubException:
            continue
    return repos


def get_repo_info(repo_name: str, token: str | None = None) -> RepoInfo:
    gh = Github(token)
    repo = gh.get_repo(repo_name)
    branch = repo.get_branch(repo.default_branch)
    return RepoInfo(
        full_name=repo.full_name,
        default_branch=repo.default_branch,
        is_public=not repo.private,
        clone_url=repo.clone_url,
        head_sha=branch.commit.sha,
    )


def clone_repo(repo_info: RepoInfo, token: str | None = None) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="gh-audit-")
    clone_url = repo_info.clone_url
    if token:
        clone_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
    git.Repo.clone_from(clone_url, tmp_dir, depth=1)
    return tmp_dir


def cleanup_repo(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
```

- [ ] **Step 3: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/config.py gh_audit/discovery.py
git commit -m "feat: add config management and repo discovery/cloning"
```

---

## Task 11: CLI Entry Point

**Files:**
- Create: `gh_audit/cli.py`

- [ ] **Step 1: Implement cli.py**

```python
# gh_audit/cli.py
import json
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console

from gh_audit.config import Config
from gh_audit.discovery import cleanup_repo, clone_repo, get_repo_info, list_org_repos
from gh_audit.models import Severity
from gh_audit.normalizer import deduplicate
from gh_audit.reporters.html_report import HtmlReporter
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.terminal import TerminalReporter
from gh_audit.scanners.base import ScanConfig
from gh_audit.scanners.governance import GovernanceScanner
from gh_audit.scanners.iac import IacScanner
from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.secrets import SecretsScanner

console = Console()

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_ALL_SCANNERS = {
    "secrets": SecretsScanner,
    "pii": PiiScanner,
    "sast": SastScanner,
    "sca": ScaScanner,
    "iac": IacScanner,
}


@click.group()
def cli():
    """GitHub repository security audit tool."""


@cli.command()
@click.argument("repo", required=False)
@click.option("--org", help="Scan all repos in this GitHub org")
@click.option("--branch", default=None, help="Branch to scan (default: default branch)")
@click.option("--modules", default=None, help="Comma-separated modules: secrets,pii,sast,sca,iac,governance")
@click.option("--output", default="terminal", help="Comma-separated: terminal,json,html")
@click.option("--min-severity", default="low", type=click.Choice(["info","low","medium","high","critical"]))
@click.option("--diff", is_flag=True, help="Only report new findings vs last scan")
def scan(repo, org, branch, modules, output, min_severity, diff):
    """Scan a repo or org for security issues."""
    cfg = Config.load()
    output_formats = [o.strip() for o in output.split(",")]
    enabled_modules = [m.strip() for m in modules.split(",")] if modules else cfg.modules

    repos = []
    if org:
        console.print(f"[bold]Discovering repos in org:[/bold] {org}")
        repos = list_org_repos(org, cfg.token)
    elif repo:
        repos = [get_repo_info(repo, cfg.token)]
    else:
        raise click.UsageError("Provide REPO or --org")

    min_sev_idx = _SEVERITY_ORDER.index(min_severity)

    for repo_info in repos:
        console.print(f"\n[bold cyan]Scanning:[/bold cyan] {repo_info.full_name}")
        scan_cfg = ScanConfig(
            repo=repo_info.full_name,
            branch=branch or repo_info.default_branch,
            commit_sha=repo_info.head_sha,
            is_public=repo_info.is_public,
            history_depth=cfg.history_depth,
        )

        all_findings = []
        repo_path = None
        try:
            repo_path = clone_repo(repo_info, cfg.token)

            for mod_name in enabled_modules:
                if mod_name == "governance":
                    scanner = GovernanceScanner(token=cfg.token)
                elif mod_name in _ALL_SCANNERS:
                    scanner = _ALL_SCANNERS[mod_name]()
                else:
                    console.print(f"[yellow]Unknown module: {mod_name}[/yellow]")
                    continue

                if not scanner.is_available():
                    console.print(f"[dim][SKIP] {mod_name} — tool not found[/dim]")
                    continue

                findings = scanner.scan(repo_path, scan_cfg)
                all_findings.extend(findings)
                console.print(f"  [green]✓[/green] {mod_name}: {len(findings)} findings")

        finally:
            if repo_path:
                cleanup_repo(repo_path)

        all_findings = deduplicate(all_findings)
        filtered = [f for f in all_findings
                    if _SEVERITY_ORDER.index(f.severity.value) >= min_sev_idx]

        _write_reports(filtered, repo_info.full_name, output_formats, cfg)


def _write_reports(findings, repo_name, output_formats, cfg):
    safe_name = repo_name.replace("/", "_")
    from datetime import datetime
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_dir = cfg.results_dir / safe_name
    results_dir.mkdir(parents=True, exist_ok=True)

    if "terminal" in output_formats:
        TerminalReporter().print(findings, repo_name)

    if "json" in output_formats:
        out = results_dir / f"{ts}.json"
        JsonReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]JSON → {out}[/dim]")

    if "html" in output_formats:
        out = results_dir / f"{ts}.html"
        HtmlReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]HTML → {out}[/dim]")


@cli.command()
def doctor():
    """Check tool availability and token status."""
    from github import Github
    cfg = Config.load()

    console.print("\n[bold]gh-audit doctor[/bold]\n")

    # Token
    if cfg.token:
        try:
            gh = Github(cfg.token)
            rate = gh.get_rate_limit().core
            console.print(f"[green]✓[/green] GitHub token   valid (rate limit: {rate.remaining}/{rate.limit})")
        except Exception as e:
            console.print(f"[red]✗[/red] GitHub token   invalid: {e}")
    else:
        console.print("[yellow]![/yellow] GitHub token   not set (set GITHUB_TOKEN or gh-audit config set token <tok>)")

    # Modules
    checks = [
        ("secrets", ["gitleaks", "trufflehog"]),
        ("pii", ["presidio-analyzer"]),
        ("sast", ["semgrep", "bandit"]),
        ("sca", ["osv-scanner"]),
        ("iac", ["trivy", "checkov"]),
        ("governance", []),
    ]
    for mod, tools in checks:
        found = [t for t in tools if shutil.which(t)]
        if mod == "governance":
            console.print(f"[green]✓[/green] governance     GitHub API (always available)")
        elif found:
            console.print(f"[green]✓[/green] {mod:<14} {', '.join(found)}")
        else:
            install = f"pip install {tools[0]}" if tools else ""
            console.print(f"[dim]○[/dim] {mod:<14} builtin only ({install})")


@cli.command()
@click.argument("repo")
def history(repo):
    """Show past scan results for a repo."""
    cfg = Config.load()
    safe_name = repo.replace("/", "_")
    results_dir = cfg.results_dir / safe_name
    if not results_dir.exists():
        console.print(f"[yellow]No scan history found for {repo}[/yellow]")
        return
    files = sorted(results_dir.glob("*.json"), reverse=True)[:10]
    for f in files:
        data = json.loads(f.read_text())
        s = data.get("summary", {})
        console.print(
            f"[dim]{f.stem}[/dim]  "
            f"[red]{s.get('critical',0)}c[/red] "
            f"[orange1]{s.get('high',0)}h[/orange1] "
            f"[yellow]{s.get('medium',0)}m[/yellow] "
            f"[green]{s.get('low',0)}l[/green]"
        )


@cli.command()
@click.argument("finding_id")
@click.option("--reason", required=True)
@click.option("--expires", default="30d", help="e.g. 30d, 90d")
def suppress(finding_id, reason, expires):
    """Mark a finding as suppressed (false positive)."""
    cfg = Config.load()
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    data = json.loads(suppress_file.read_text()) if suppress_file.exists() else {}
    data[finding_id] = {"reason": reason, "expires": expires}
    suppress_file.parent.mkdir(parents=True, exist_ok=True)
    suppress_file.write_text(json.dumps(data, indent=2))
    console.print(f"[green]✓[/green] Finding {finding_id} suppressed ({expires}): {reason}")


@cli.group()
def config():
    """Manage gh-audit configuration."""


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value."""
    cfg = Config.load()
    cfg.set(key, value)
    console.print(f"[green]✓[/green] Set {key}={value}")
```

- [ ] **Step 2: Verify CLI entry point works**

```bash
cd ~/Desktop/gh-audit
pip install -e ".[dev]"
gh-audit --help
gh-audit doctor
```

Expected: help text prints, doctor runs without crash

- [ ] **Step 3: Commit**

```bash
cd ~/Desktop/gh-audit
git add gh_audit/cli.py
git commit -m "feat: add Click CLI with scan/doctor/history/suppress/config commands"
```

---

## Task 12: Full Test Suite Run & README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Run full test suite**

```bash
cd ~/Desktop/gh-audit && pytest tests/ -v --tb=short
```

Expected: All tests pass (≥15 tests)

- [ ] **Step 2: Write README.md**

```markdown
# gh-audit

GitHub repository security audit tool. Scans for secrets, PII, code vulnerabilities, dependency risks, IaC misconfigurations, and governance gaps.

## Install

```bash
pipx install gh-audit
# or
pip install gh-audit
```

## Quick Start

```bash
export GITHUB_TOKEN=ghp_yourtoken

# Scan a repo
gh-audit scan owner/repo

# Scan an org, output HTML + JSON
gh-audit scan --org myorg --output terminal,json,html

# Check tool availability
gh-audit doctor
```

## Detection Modules

| Module | Built-in | Enhanced with |
|--------|---------|---------------|
| secrets | ✓ entropy + regex | gitleaks, trufflehog |
| pii | ✓ CN phone/ID/bank + email | - |
| governance | ✓ GitHub API | - |
| sast | - | semgrep, bandit |
| sca | ✓ OSV API fallback | osv-scanner |
| iac | - | trivy, checkov |

## Optional Tools

```bash
pip install semgrep bandit          # SAST
brew install osv-scanner trivy      # SCA + IaC
```
```

- [ ] **Step 3: Final commit**

```bash
cd ~/Desktop/gh-audit
git add README.md
git commit -m "docs: add README with install and quick start"
```
