import uuid
from datetime import datetime, timezone

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import (
    BaseScanner, ScanConfig, ScanIncompleteError, result_records, run_json_tool,
)


class SastScanner(BaseScanner):
    name = "sast"

    def is_available(self) -> bool:
        return self._external_tool_available("semgrep") or self._external_tool_available("bandit")

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            if self._external_tool_available("semgrep"):
                return self._run_semgrep(repo_path, config)
            if self._external_tool_available("bandit"):
                return self._run_bandit(repo_path, config)
            raise ScanIncompleteError("scan incomplete: no sast tool found")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError) as exc:
            raise ScanIncompleteError("scan incomplete: sast returned invalid or unreadable data") from exc

    def _run_semgrep(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        data = run_json_tool(["semgrep", "--config=auto", "--json", repo_path])
        findings = []
        if data.get("errors"):
            raise ScanIncompleteError("scan incomplete: semgrep reported scan errors")
        for r in result_records(data, "results"):
            sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
            sev = sev_map.get(r.get("extra", {}).get("severity", "INFO"), Severity.LOW)
            f = Finding(
                finding_id=str(uuid.uuid4()), fingerprint="",
                repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                file_path=r.get("path", ""),
                line_start=r.get("start", {}).get("line", 0),
                line_end=r.get("end", {}).get("line", 0),
                category=Category.SAST, rule_id=r.get("check_id", "semgrep"),
                title=r.get("extra", {}).get("message", "SAST finding"),
                severity=sev, confidence=Confidence.LIKELY,
                evidence_redacted=r.get("extra", {}).get("lines", "")[:80],
                recommendation="Review and remediate the flagged code pattern",
                standard_mapping=[], scanner="semgrep",
                discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
            )
            f.fingerprint = f.compute_fingerprint()
            findings.append(f)
        return findings

    def _run_bandit(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        data = run_json_tool(["bandit", "-r", repo_path, "-f", "json"])
        findings = []
        if data.get("errors"):
            raise ScanIncompleteError("scan incomplete: bandit reported scan errors")
        for r in result_records(data, "results"):
            sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
            sev = sev_map.get(r.get("issue_severity", "LOW"), Severity.LOW)
            f = Finding(
                finding_id=str(uuid.uuid4()), fingerprint="",
                repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                file_path=r.get("filename", ""),
                line_start=r.get("line_number", 0),
                line_end=r.get("line_number", 0),
                category=Category.SAST, rule_id=r.get("test_id", "bandit"),
                title=r.get("issue_text", "Bandit finding"),
                severity=sev, confidence=Confidence.LIKELY,
                evidence_redacted=r.get("code", "")[:80],
                recommendation=r.get("more_info", "Review bandit finding"),
                standard_mapping=[str(r.get("issue_cwe", {}).get("id", ""))],
                scanner="bandit",
                discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
            )
            f.fingerprint = f.compute_fingerprint()
            findings.append(f)
        return findings
