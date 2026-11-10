import json
import subprocess
from unittest.mock import patch

import pytest
import requests
from click.testing import CliRunner

from gh_audit.cli import cli
from gh_audit.config import Config
from gh_audit.discovery import RepoInfo
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError
from gh_audit.scanners.iac import IacScanner
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.sca import ScaScanner


TOOLS = [(SastScanner, "semgrep"), (SastScanner, "bandit"),
         (IacScanner, "trivy"), (IacScanner, "checkov"),
         (ScaScanner, "osv-scanner")]
CFG = ScanConfig("org/repo", "main", "abc", True)


@pytest.mark.parametrize("scanner,tool", TOOLS)
@pytest.mark.parametrize("failure", ["exit", "json", "shape", "nested", "missing", "timeout"])
def test_tool_failure_is_explicit(scanner, tool, failure, tmp_path):
    payloads = {
        "semgrep": {"results": [None]}, "bandit": {"results": [None]},
        "trivy": {"Results": [None]}, "checkov": [{"results": None}],
        "osv-scanner": {"results": [None]},
    }
    result = subprocess.CompletedProcess([tool], 2 if failure == "exit" else 0,
                                         "invalid" if failure == "json" else
                                         json.dumps(payloads[tool] if failure == "nested" else {}), "")
    error = (FileNotFoundError(tool) if failure == "missing" else
             subprocess.TimeoutExpired(tool, 120) if failure == "timeout" else None)
    with patch("shutil.which", side_effect=lambda name: tool if name == tool else None), \
         patch("subprocess.run", return_value=result, side_effect=error):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            scanner().scan(str(tmp_path), CFG)


@pytest.mark.parametrize("scanner", [SastScanner, IacScanner])
def test_missing_tools_are_incomplete(scanner, tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            scanner().scan(str(tmp_path), CFG)


@pytest.mark.parametrize("scanner,tool,payload", [
    (SastScanner, "semgrep", {"results": [], "errors": [{"message": "failed"}]}),
    (SastScanner, "bandit", {"results": [], "errors": [{"reason": "failed"}]}),
    (IacScanner, "checkov", {"results": {"failed_checks": [], "parsing_errors": ["bad.tf"]}}),
    (IacScanner, "checkov", {"summary": {"failed": 0, "passed": 0}, "parsing_errors": ["bad.tf"]}),
    (IacScanner, "checkov", {"summary": {"failed": 0, "passed": 0, "parsing_errors": 1}}),
])
def test_tool_reported_partial_scan_is_incomplete(scanner, tool, payload, tmp_path):
    result = subprocess.CompletedProcess([tool], 0, json.dumps(payload), "")
    with patch("shutil.which", side_effect=lambda name: tool if name == tool else None), \
         patch("subprocess.run", return_value=result):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            scanner().scan(str(tmp_path), CFG)


@pytest.mark.parametrize("scanner,tool,payload,code", [
    (SastScanner, "semgrep", {"results": []}, 0),
    (SastScanner, "bandit", {"results": []}, 0),
    (IacScanner, "trivy", {"SchemaVersion": 2}, 0),
    (IacScanner, "trivy", {"SchemaVersion": 2, "Results": None}, 0),
    (IacScanner, "checkov", [], 0),
    (IacScanner, "checkov", {"summary": {"failed": 0, "passed": 0}}, 0),
    (ScaScanner, "osv-scanner", {"results": []}, 0),
    (ScaScanner, "osv-scanner", {"results": None}, 0),
])
def test_valid_empty_scan_stays_successful(scanner, tool, payload, code, tmp_path):
    result = subprocess.CompletedProcess([tool], code, json.dumps(payload), "")
    with patch("shutil.which", side_effect=lambda name: tool if name == tool else None), \
         patch("subprocess.run", return_value=result):
        assert scanner().scan(str(tmp_path), CFG) == []


@pytest.mark.parametrize("payload", [{}, [], {"results": []}, {"results": [None]},
                                     {"results": [{"vulns": "invalid"}]},
                                     {"results": [{}, {}]}])
def test_osv_api_rejects_malformed_or_incomplete_batch(payload):
    with patch("requests.post") as post:
        post.return_value.json.return_value = payload
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            ScaScanner()._query_osv_api_batch([("example", "1.0.0")])


def test_osv_api_network_failure_is_incomplete(tmp_path):
    (tmp_path / "requirements.txt").write_text("example==1.0.0\n")
    with patch("shutil.which", return_value=None), \
         patch("requests.post", side_effect=requests.ConnectionError("offline")):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            ScaScanner().scan(str(tmp_path), CFG)


def test_unreadable_dependency_file_is_incomplete(tmp_path):
    (tmp_path / "requirements.txt").write_text("example==1.0.0\n")
    with patch("pathlib.Path.read_text", side_effect=PermissionError("denied")):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete"):
            ScaScanner()._osv_api_fallback(str(tmp_path), CFG)


def test_trivy_exit_one_is_a_failure_even_with_valid_json(tmp_path):
    result = subprocess.CompletedProcess(["trivy"], 1, '{"SchemaVersion": 2}', "")
    with patch("shutil.which", return_value="trivy"), patch("subprocess.run", return_value=result):
        with pytest.raises(ScanIncompleteError, match="(?i)incomplete.*exited 1"):
            IacScanner().scan(str(tmp_path), CFG)


@pytest.mark.parametrize("module", ["sast", "iac", "sca"])
@pytest.mark.parametrize("failure", ["missing", "runtime"])
def test_cli_fails_incomplete_repo_and_continues_org(tmp_path, module, failure):
    scanner = {"sast": SastScanner, "iac": IacScanner, "sca": ScaScanner}[module]
    repos = [RepoInfo(f"org/{name}", "main", True, "https://github.com/org/repo.git", "abc")
             for name in ("incomplete", "complete")]
    with patch("gh_audit.cli.Config.load", return_value=Config(results_dir=tmp_path)), \
         patch("gh_audit.cli.list_org_repos", return_value=repos), \
         patch("gh_audit.cli.clone_repo", return_value=str(tmp_path)), \
         patch("gh_audit.cli.checkout_sha", return_value="abc"), \
         patch.object(scanner, "is_available", side_effect=[failure != "missing", True]), \
         patch.object(scanner, "scan", side_effect=[RuntimeError("scan incomplete"), []]
                      if failure == "runtime" else [[]]) as scan, \
         patch("gh_audit.cli.cleanup_repo") as cleanup, \
         patch("gh_audit.cli._write_reports") as report:
        result = CliRunner().invoke(cli, ["scan", "--org", "org", "--modules", module,
                                         "--output", "json,html", "--diff", "--min-severity", "critical"])
    assert result.exit_code == 1
    assert "INCOMPLETE" in result.output
    assert cleanup.call_count == 2
    assert scan.call_count == (2 if failure == "runtime" else 1)
    if failure == "runtime":
        # A repository-level failure (clone, checkout, unexpected error) skips its report.
        report.assert_called_once()
        assert report.call_args.args[1] == "org/complete"
    else:
        # A module that cannot run is reported as INCOMPLETE; the repository still
        # gets a report with the other modules' findings.
        assert [c.args[1] for c in report.call_args_list] == ["org/incomplete", "org/complete"]
