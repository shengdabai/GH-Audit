import re
from collections import Counter
from gh_audit.models import Category, Finding
from gh_audit.sast_identity import CONTENT_ID


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result = []
    for f in findings:
        if f.category == Category.SAST and not f.fingerprint.startswith("sast-location-v1:"):
            result.append(f)
            continue
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
    masked_local = (local[0] + "***") if local else "***"
    return masked_local + "@" + domain


def redact_id_number(value: str) -> str:
    if len(value) == 18:
        return value[:4] + "*" * 11 + value[-4:]
    return "***"


def diff_findings(
    current: list[Finding], previous_content_fps: set[str] | Counter[str], *,
    show_grown_sast_groups: bool = False,
) -> list[Finding]:
    """Match SAST occurrences one to one, and keep other modules' content set behavior."""
    unmatched = Counter(previous_content_fps)
    grown = set()
    if show_grown_sast_groups:
        current_counts = Counter(
            identity for finding in current
            if finding.category == Category.SAST
            and (identity := finding.compute_content_fingerprint()) is not None
        )
        grown = {identity for identity, count in current_counts.items() if count > unmatched[identity]}
    new = []
    for finding in current:
        identity = finding.compute_content_fingerprint()
        if identity is None or identity not in previous_content_fps:
            new.append(finding)
        elif finding.category == Category.SAST:
            if identity in grown:
                new.append(finding)
            elif unmatched[identity]:
                unmatched[identity] -= 1
            else:
                new.append(finding)
    return new


def _report_content_fingerprints(data):
    for finding in data.get("findings", []):
        identity = finding.get("content_fingerprint")
        if not isinstance(identity, str):
            continue
        if finding.get("category") == Category.SAST and not CONTENT_ID.fullmatch(identity):
            continue
        yield identity


def load_previous_content_fingerprints(
    results_dir, repo_name: str, *, count_occurrences: bool = False,
) -> set[str] | Counter[str]:
    """Load content fingerprints from the most recent previous scan JSON."""
    import json
    from pathlib import Path
    safe_name = repo_name.replace("/", "_")
    repo_dir = Path(results_dir) / safe_name
    files = sorted(repo_dir.glob("*.json"), reverse=True)
    counts = Counter()
    try:
        if files:
            data = json.loads(files[0].read_text())
            counts = Counter(_report_content_fingerprints(data))
    except Exception:
        pass
    return counts if count_occurrences else set(counts)


def known_sast_content_id(results_dir, identity: str) -> bool:
    """Accept a scoped SAST suppression ID only from a local JSON report."""
    import json
    from pathlib import Path

    root = Path(results_dir)
    if root.is_symlink():
        return False
    for directory in root.glob("*"):
        if directory.is_symlink() or not directory.is_dir():
            continue
        for report in directory.glob("*.json"):
            if (not re.fullmatch(r"[0-9]{8}_[0-9]{6}\.json", report.name)
                    or report.is_symlink() or not report.is_file()):
                continue
            try:
                data = json.loads(report.read_text())
                if any(finding.get("category") == Category.SAST
                       and finding.get("content_fingerprint") == identity
                       for finding in data.get("findings", [])):
                    return True
            except (AttributeError, OSError, TypeError, ValueError):
                continue
    return False


def load_suppressions() -> set[str]:
    """Load suppressed content fingerprints, skipping expired entries."""
    import json
    from datetime import datetime, timezone, timedelta
    from pathlib import Path
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    if not suppress_file.exists():
        return set()
    try:
        data = json.loads(suppress_file.read_text())
        now = datetime.now(timezone.utc)
        active = set()
        for fp, meta in data.items():
            expires_str = meta.get("expires", "")
            created_str = meta.get("created_at", "")
            if expires_str and created_str:
                try:
                    # Accept "30d" or "30" (plain integer days)
                    days = int(re.sub(r"[^0-9]", "", expires_str))
                    created = datetime.fromisoformat(created_str)
                    if now > created + timedelta(days=days):
                        continue  # expired, skip
                except (ValueError, TypeError):
                    pass  # malformed expires, treat as non-expiring
            active.add(fp)
        return active
    except Exception:
        return set()
