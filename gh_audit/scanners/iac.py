import uuid
from datetime import datetime, timezone

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import (
    BaseScanner, ScanConfig, ScanIncompleteError, result_records, run_json_tool,
)


class IacScanner(BaseScanner):
    name = "iac"

    def is_available(self) -> bool:
        return self._external_tool_available("trivy") or self._external_tool_available("checkov")

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            if self._external_tool_available("trivy"):
                return self._run_trivy(repo_path, config)
            if self._external_tool_available("checkov"):
                return self._run_checkov(repo_path, config)
            raise ScanIncompleteError("scan incomplete: no iac tool found")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError) as exc:
            raise ScanIncompleteError("scan incomplete: iac returned invalid or unreadable data") from exc

    def _run_trivy(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        data = run_json_tool(["trivy", "config", "--format=json", repo_path], success_codes=(0,))
        findings = []
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        for result_item in result_records(data, "Results", optional="SchemaVersion" in data, nullable=True):
            for misc in result_records(result_item, "Misconfigurations", optional=True, nullable=True):
                sev = sev_map.get(misc.get("Severity", "LOW"), Severity.LOW)
                f = Finding(
                    finding_id=str(uuid.uuid4()), fingerprint="",
                    repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                    file_path=result_item.get("Target", ""),
                    line_start=misc.get("CauseMetadata", {}).get("StartLine", 0),
                    line_end=misc.get("CauseMetadata", {}).get("EndLine", 0),
                    category=Category.IAC, rule_id=misc.get("ID", "trivy-iac"),
                    title=misc.get("Title", "IaC misconfiguration"),
                    severity=sev, confidence=Confidence.CONFIRMED,
                    evidence_redacted=misc.get("Message", "")[:100],
                    recommendation=misc.get("Resolution", "Review IaC configuration"),
                    standard_mapping=[misc.get("ID", "")],
                    scanner="trivy",
                    discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
                )
                f.fingerprint = f.compute_fingerprint()
                findings.append(f)
        return findings

    def _run_checkov(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        data = run_json_tool(["checkov", "-d", repo_path, "--output", "json"])
        findings = []
        checks = data if isinstance(data, list) else [data]
        for check_result in checks:
            results = check_result.get("results")
            if (check_result.get("summary", {}).get("parsing_errors", 0)
                    or check_result.get("parsing_errors")
                    or (isinstance(results, dict) and results.get("parsing_errors"))):
                raise ScanIncompleteError("scan incomplete: checkov reported parsing errors")
            if results is None and isinstance(check_result.get("summary"), dict):
                summary = check_result["summary"]
                if summary.get("failed") == 0 and isinstance(summary.get("passed"), int):
                    continue
            for r in result_records(results, "failed_checks"):
                f = Finding(
                    finding_id=str(uuid.uuid4()), fingerprint="",
                    repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                    file_path=r.get("repo_file_path", ""),
                    line_start=r.get("file_line_range", [0, 0])[0],
                    line_end=r.get("file_line_range", [0, 0])[1],
                    category=Category.IAC, rule_id=r.get("check_id", "checkov"),
                    title=r.get("check_name", "Checkov finding"),
                    severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                    evidence_redacted=r.get("check_id", "")[:80],
                    recommendation="Review and fix the IaC misconfiguration",
                    standard_mapping=[r.get("check_id", "")],
                    scanner="checkov",
                    discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
                )
                f.fingerprint = f.compute_fingerprint()
                findings.append(f)
        return findings
