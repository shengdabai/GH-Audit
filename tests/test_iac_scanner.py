import json
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from gh_audit.scanners.iac import IacScanner
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError
from gh_audit.models import Severity


def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc", is_public=False)


def test_iac_not_available_when_no_tools():
    with patch("shutil.which", return_value=None):
        assert IacScanner().is_available() is False


def test_iac_available_when_trivy_present():
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/trivy" if t == "trivy" else None):
        assert IacScanner().is_available() is True


def test_trivy_returns_findings(tmp_path):
    trivy_output = {
        "Results": [{
            "Target": "terraform/main.tf",
            "Misconfigurations": [{
                "ID": "AVD-AWS-0001",
                "Title": "S3 bucket not encrypted",
                "Severity": "HIGH",
                "Message": "Bucket does not have encryption enabled",
                "Resolution": "Enable server-side encryption",
                "CauseMetadata": {"StartLine": 5, "EndLine": 10},
            }]
        }]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(trivy_output)
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/trivy" if t == "trivy" else None):
        with patch("subprocess.run", return_value=mock_result):
            findings = IacScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "AVD-AWS-0001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "terraform/main.tf"


def test_trivy_timeout_raises_incomplete(tmp_path):
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/trivy" if t == "trivy" else None):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trivy", 120)):
            with pytest.raises(ScanIncompleteError):
                IacScanner().scan(str(tmp_path), _cfg())


def test_trivy_invalid_json_raises_incomplete(tmp_path):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "not json"
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/trivy" if t == "trivy" else None):
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(ScanIncompleteError):
                IacScanner().scan(str(tmp_path), _cfg())


def test_checkov_returns_findings(tmp_path):
    checkov_output = [{
        "results": {
            "failed_checks": [{
                "check_id": "CKV_AWS_18",
                "check_name": "S3 access logging not enabled",
                "repo_file_path": "terraform/s3.tf",
                "file_line_range": [1, 15],
            }]
        }
    }]
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = json.dumps(checkov_output)
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/checkov" if t == "checkov" else None):
        with patch("subprocess.run", return_value=mock_result):
            findings = IacScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "CKV_AWS_18"
    assert findings[0].severity == Severity.MEDIUM


def test_checkov_timeout_raises_incomplete(tmp_path):
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/checkov" if t == "checkov" else None):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("checkov", 120)):
            with pytest.raises(ScanIncompleteError):
                IacScanner().scan(str(tmp_path), _cfg())


def test_checkov_invalid_json_raises_incomplete(tmp_path):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "not valid json {"
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/checkov" if t == "checkov" else None):
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(ScanIncompleteError):
                IacScanner().scan(str(tmp_path), _cfg())
