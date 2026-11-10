import json
from unittest.mock import MagicMock, patch
import subprocess
import pytest
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError
from gh_audit.models import Severity


def _cfg():
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc", is_public=False)


def _semgrep_output(findings=None):
    return json.dumps({
        "results": findings or [],
        "errors": [],
        "stats": {},
    })


def test_sast_not_available_when_no_tools():
    with patch("shutil.which", return_value=None):
        assert SastScanner().is_available() is False


def test_sast_available_when_semgrep_present():
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/semgrep" if t == "semgrep" else None):
        assert SastScanner().is_available() is True


def test_semgrep_returns_findings(tmp_path):
    semgrep_result = {
        "results": [{
            "check_id": "python.lang.security.dangerous-eval",
            "path": "app/main.py",
            "start": {"line": 10},
            "end": {"line": 10},
            "extra": {
                "severity": "ERROR",
                "message": "Use of eval() is dangerous",
                "lines": "eval(user_input)",
            }
        }],
        "errors": [],
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(semgrep_result)
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/semgrep" if t == "semgrep" else None):
        with patch("subprocess.run", return_value=mock_result):
            findings = SastScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "python.lang.security.dangerous-eval"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "app/main.py"


def test_semgrep_timeout_raises_incomplete(tmp_path):
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/semgrep" if t == "semgrep" else None):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 120)):
            with pytest.raises(ScanIncompleteError):
                SastScanner().scan(str(tmp_path), _cfg())


def test_semgrep_invalid_json_raises_incomplete(tmp_path):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "not valid json {"
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/semgrep" if t == "semgrep" else None):
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(ScanIncompleteError):
                SastScanner().scan(str(tmp_path), _cfg())


def test_semgrep_nonzero_returncode_raises_incomplete(tmp_path):
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stdout = ""
    mock_result.stderr = "fatal error"

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/semgrep" if t == "semgrep" else None):
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(ScanIncompleteError):
                SastScanner().scan(str(tmp_path), _cfg())


def test_bandit_returns_findings(tmp_path):
    bandit_result = {
        "results": [{
            "test_id": "B602",
            "issue_text": "subprocess call with shell=True",
            "issue_severity": "HIGH",
            "filename": "app/utils.py",
            "line_number": 5,
            "code": "subprocess.run(cmd, shell=True)",
            "more_info": "https://bandit.readthedocs.io/...",
            "issue_cwe": {"id": 78},
        }]
    }
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = json.dumps(bandit_result)
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=lambda t: "/usr/bin/bandit" if t == "bandit" else None):
        with patch("subprocess.run", return_value=mock_result):
            findings = SastScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "B602"
    assert findings[0].severity == Severity.HIGH
