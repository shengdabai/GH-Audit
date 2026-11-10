import json
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.base import ScanConfig


def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc", is_public=False)


def test_sca_available_by_default():
    # ScaScanner has no is_available override — defaults to True (fallback to API mode)
    with patch("shutil.which", return_value=None):
        assert ScaScanner().is_available() is True


def test_osv_scanner_returns_findings(tmp_path):
    osv_output = {
        "results": [{
            "source": {"path": "requirements.txt"},
            "packages": [{
                "package": {"name": "requests", "version": "2.20.0"},
                "vulnerabilities": [{"id": "GHSA-1234-5678-abcd"}]
            }]
        }]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(osv_output)
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", return_value=mock_result):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234-5678-abcd"
    assert "requests" in findings[0].evidence_redacted


def test_osv_scanner_timeout_returns_empty(tmp_path):
    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("osv-scanner", 120)):
            findings = ScaScanner().scan(str(tmp_path), _cfg())
    assert findings == []


def test_osv_api_fallback_parses_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\nflask==1.0.0\n")

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "results": [
            {"vulns": [{"id": "GHSA-1234"}]},  # requests has vuln
            {"vulns": []},                       # flask is clean
        ]
    }

    with patch("shutil.which", return_value=None):
        with patch("requests.post", return_value=mock_resp):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234"


def test_osv_api_fallback_handles_network_error(tmp_path):
    import requests as req_lib
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")

    with patch("shutil.which", return_value=None):
        with patch("requests.post", side_effect=req_lib.RequestException("timeout")):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert findings == []


@pytest.mark.parametrize("version", [1, 2, 3])
def test_npm_lockfiles_use_npm_ecosystem(tmp_path, version):
    packages = {"old-package": {"version": "1.0.0", "dependencies": {
        "@scope/nested": {"version": "2.0.0"}}}}
    lock = {"lockfileVersion": version, "dependencies": packages}
    if version >= 2:
        lock["packages"] = {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/old-package": {"version": "1.0.0"},
            "node_modules/old-package/node_modules/@scope/nested": {"version": "2.0.0"},
            "node_modules/local": {"version": "file:../local"},
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    response = MagicMock()
    response.json.return_value = {"results": [{"vulns": [{"id": "GHSA-test"}]}, {}]}
    with patch("shutil.which", return_value=None), patch("requests.post", return_value=response) as post:
        findings = ScaScanner().scan(str(tmp_path), _cfg())
    assert post.call_args.kwargs["json"]["queries"] == [
        {"version": "1.0.0", "package": {"name": "old-package", "ecosystem": "npm"}},
        {"version": "2.0.0", "package": {"name": "@scope/nested", "ecosystem": "npm"}},
    ]
    assert len(findings) == 1
    assert findings[0].file_path == "package-lock.json"
    assert findings[0].rule_id == "GHSA-test"


def test_fallback_checks_beyond_old_file_and_package_limits(tmp_path):
    for number in range(6):
        (tmp_path / f"requirements-{number}.txt").write_text(
            "\n".join(f"package-{index}==1.0.0" for index in range(105)))
    with patch.object(ScaScanner, "_query_osv_api_batch", return_value={}) as query:
        ScaScanner()._osv_api_fallback(str(tmp_path), _cfg())
    assert query.call_count == 12
    assert sum(len(call.args[0]) for call in query.call_args_list) == 630
    assert all(len(call.args[0]) <= 100 for call in query.call_args_list)


def test_osv_http_error_does_not_produce_findings():
    import requests
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError("server error")
    with patch("requests.post", return_value=response):
        assert ScaScanner()._query_osv_api_batch([("package", "1.0.0")]) == {}
    response.json.assert_not_called()


@pytest.mark.parametrize("lock", [[], {"packages": []}, {"dependencies": []}])
def test_malformed_lockfile_does_not_crash_fallback(tmp_path, lock):
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    assert ScaScanner()._osv_api_fallback(str(tmp_path), _cfg()) == []
