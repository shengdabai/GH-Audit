import json
import os
from unittest.mock import MagicMock, patch
import subprocess
from io import StringIO
import pytest
from git import Actor, Repo
from rich.console import Console

from gh_audit import config
from gh_audit.normalizer import deduplicate, diff_findings
from gh_audit.reporters import terminal
from gh_audit.reporters.html_report import HtmlReporter
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.sast_identity import fingerprints
from gh_audit.scanners import sast
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError
from gh_audit.models import Severity


_TEST_KEY = b"f" * 32


@pytest.fixture(autouse=True)
def isolated_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path / "settings")
    monkeypatch.setattr(sast, "load_or_create_key", lambda: _TEST_KEY)


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


def _scan_records(root, scanner, records, config=None):
    with patch.object(SastScanner, "_external_tool_available", side_effect=lambda name: name == scanner), \
         patch.object(sast, "run_json_tool", return_value={"results": records}):
        return SastScanner().scan(str(root), config or _cfg())


def _semgrep_record(path="app.py", line=3, source=None):
    return {
        "check_id": "python.rule",
        "path": str(path),
        "start": {"line": line},
        "end": {"line": line},
        "extra": {"severity": "ERROR", "lines": source, "message": "interpolated-private-canary"},
    }


def _fixture_commit(checkout, files, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    checkout.mkdir(exist_ok=True)
    for name, content in files.items():
        (checkout / name).write_bytes(content)
    actor = Actor("Fixture", "fixture@example.test")
    with Repo.init(checkout) as repo:
        repo.index.add(list(files))
        commit = repo.index.commit("fixture", author=actor, committer=actor, skip_hooks=True)
    return ScanConfig("org/repo", "main", commit.hexsha, False)


def _exact_record(path, line, start, end, source=None):
    record = _semgrep_record(path, line, source)
    record["start"]["offset"] = start
    record["end"]["offset"] = end
    return record


def test_semgrep_uses_full_source_for_change_and_move_identity(tmp_path, monkeypatch):
    source = b"private-source-" + b"a" * 90
    first, second = source + b"first", source + b"second"
    checkout = tmp_path / "checkout"
    cfg = _fixture_commit(checkout, {"app.py": first, "moved.py": b"\n" + first}, monkeypatch)
    same, moved = _scan_records(checkout, "semgrep", [
        _exact_record(checkout.resolve() / "app.py", 1, 0, len(first), "unverified-short-snippet"),
        _exact_record("moved.py", 2, 1, len(first) + 1),
    ], cfg)
    cfg = _fixture_commit(checkout, {"app.py": second}, monkeypatch)
    [changed] = _scan_records(checkout, "semgrep", [_exact_record("app.py", 1, 0, len(second))], cfg)
    previous = {same.compute_content_fingerprint()}
    assert same.compute_content_fingerprint() is not None
    assert diff_findings([moved, changed], previous) == [changed]
    assert len(deduplicate([same, changed, moved])) == 3
    assert same.fingerprint != moved.fingerprint
    report = json.dumps([finding.to_dict() for finding in (same, changed, moved)])
    for value in (source.decode(), "interpolated-private-canary", "unverified-short-snippet",
                  str(checkout.resolve())):
        assert value not in report


def test_semgrep_same_line_offsets_keep_distinct_locations_and_added_copy(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    cfg = _fixture_commit(checkout, {"app.py": b"f(); f()\n"}, monkeypatch)
    first, second = _scan_records(checkout, "semgrep", [
        _exact_record("app.py", 1, 0, 3),
        _exact_record("app.py", 1, 5, 8),
    ], cfg)
    assert first.compute_content_fingerprint() == second.compute_content_fingerprint()
    assert first.compute_content_fingerprint() is not None
    assert first.fingerprint != second.fingerprint
    assert deduplicate([first, second]) == [first, second]
    assert diff_findings([first, second], {first.compute_content_fingerprint()}) == [second]


def test_bandit_identifies_matched_lines_independent_of_context_and_number(tmp_path, monkeypatch):
    def result(path, line, context_before, context_after, source):
        return {
            "test_id": "B602", "issue_severity": "HIGH", "filename": path,
            "line_number": line, "line_range": [line, line + 1],
            "code": f"{line - 1} {context_before}\n{line} {source}\n"
                    f"{line + 1} 77  literal-data\n{line + 2} {context_after}\n",
            "issue_text": "interpolated-private-canary", "more_info": "https://example.test/private-doc",
        }

    canary = "private-source-" + "x" * 90
    checkout = tmp_path / "checkout"
    cfg = _fixture_commit(checkout, {
        "app.py": f"\nbefore\n{canary}1\n77  literal-data\nafter\n".encode(),
        "moved.py": f"\n\nother before\n{canary}1\n77  literal-data\nother after\n".encode(),
        "new.py": f"\nbefore\n{canary}2\n77  literal-data\nafter\n".encode(),
    }, monkeypatch)
    first, moved, changed, repeated = _scan_records(checkout, "bandit", [
        result("app.py", 3, "before", "after", canary + "1"),
        result("moved.py", 4, "other before", "other after", canary + "1"),
        result("new.py", 3, "before", "after", canary + "2"),
        result("app.py", 3, "before", "after", canary + "1"),
    ], cfg)
    assert diff_findings([moved, changed], {first.compute_content_fingerprint()}) == [changed]
    _, expected = fingerprints(_TEST_KEY, "org/repo", "main", "bandit", "B602",
                               f"{canary}1\n77  literal-data\n", "app.py", None)
    assert first.compute_content_fingerprint() == expected
    assert first.fingerprint != repeated.fingerprint
    assert deduplicate([first, repeated]) == [first, repeated]
    report = json.dumps(first.to_dict())
    assert all(value not in report for value in (canary, "interpolated-private-canary", "private-doc"))


def test_bandit_same_line_offsets_distinguish_identical_matches(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    cfg = _fixture_commit(checkout, {"app.py": b"f(); f()\n"}, monkeypatch)
    record = {
        "test_id": "B602", "issue_severity": "HIGH", "filename": "app.py",
        "line_number": 1, "line_range": [1], "code": "1 f(); f()\n",
    }
    first, second, truncated = _scan_records(checkout, "bandit", [
        {**record, "col_offset": 0, "end_col_offset": 3},
        {**record, "col_offset": 5, "end_col_offset": 8},
        {**record, "code": "1 f();"},
    ], cfg)
    assert first.compute_content_fingerprint() == second.compute_content_fingerprint()
    assert first.compute_content_fingerprint() is not None
    assert first.fingerprint != second.fingerprint
    assert truncated.compute_content_fingerprint() is None


def test_semgrep_rejects_same_length_worktree_mutation(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    prefix, source = "header\nπ = ".encode(), "fixture-call('full match')"
    original = prefix + source.encode() + b"\n"
    cfg = _fixture_commit(checkout, {"app.py": original}, monkeypatch)
    record = _exact_record("app.py", 2, len(prefix), len(prefix) + len(source), "requires login")
    record["start"]["col"] = 5
    record["end"]["col"] = 5 + len(source)
    [finding] = _scan_records(checkout, "semgrep", [record], cfg)
    _, expected = fingerprints(_TEST_KEY, "org/repo", "main", "semgrep", "python.rule",
                               source, "app.py", (2, 2, len(prefix), len(prefix) + len(source)))
    assert finding.compute_content_fingerprint() == expected

    mutated = original.replace(b"full match", b"next match")
    assert len(mutated) == len(original)
    (checkout / "app.py").write_bytes(mutated)
    [mismatch] = _scan_records(checkout, "semgrep", [record], cfg)
    assert mismatch.compute_content_fingerprint() is None
    assert diff_findings([mismatch], {expected}) == [mismatch]

    (checkout / "app.py").write_bytes(original)
    record["end"]["line"] = 4
    [mismatch] = _scan_records(checkout, "semgrep", [record], cfg)
    assert mismatch.compute_content_fingerprint() is None


def test_sast_reporters_omit_source_messages_and_checkout_path(tmp_path, monkeypatch):
    source = b"private-source-report-canary"
    checkout = tmp_path / "checkout"
    cfg = _fixture_commit(checkout, {"app.py": source}, monkeypatch)
    [finding] = _scan_records(checkout, "semgrep", [
        _exact_record(checkout.resolve() / "app.py", 1, 0, len(source), source.decode()),
    ], cfg)
    html, json_path = tmp_path / "report.html", tmp_path / "report.json"
    HtmlReporter().write([finding], str(html), cfg.repo)
    JsonReporter().write([finding], str(json_path), cfg.repo)
    buffer = StringIO()
    monkeypatch.setattr(terminal, "console", Console(file=buffer, width=180, color_system=None))
    terminal.TerminalReporter().print([finding], cfg.repo)
    for report in (html.read_text(), json_path.read_text(), buffer.getvalue()):
        assert "Matched source omitted" in report
        assert "app.py" in report
        assert all(value not in report for value in (
            source.decode(), "interpolated-private-canary", str(checkout.resolve()),
        ))


@pytest.mark.skipif(os.name == "nt", reason="the Git symlink fixture requires symlink privileges")
def test_semgrep_blob_ignores_git_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "linked.py").symlink_to("outside.txt")
    actor = Actor("Fixture", "fixture@example.test")
    with Repo.init(checkout) as repo:
        repo.index.add(["linked.py"])
        commit = repo.index.commit("fixture", author=actor, committer=actor, skip_hooks=True)
        sha = commit.hexsha
    record = _semgrep_record("linked.py", 1)
    record["start"]["offset"] = 0
    record["end"]["offset"] = len("outside.txt")
    cfg = ScanConfig("org/repo", "main", sha, False)
    [finding] = _scan_records(checkout, "semgrep", [record], cfg)
    assert finding.compute_content_fingerprint() is None


@pytest.mark.parametrize("source", [None, {"not": "text"}, "requires login", "  "])
def test_unknown_source_stays_visible_even_for_same_location(tmp_path, source):
    record = _semgrep_record(source=source)
    findings = _scan_records(tmp_path, "semgrep", [record, record])
    assert len(deduplicate(findings)) == 2
    assert diff_findings(findings, set()) == findings
    assert all(f.to_dict()["content_fingerprint"] is None for f in findings)


def test_invalid_key_leaves_findings_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(sast, "load_or_create_key", lambda: None)
    [finding] = _scan_records(tmp_path, "semgrep", [_semgrep_record(source="private-source")])
    assert finding.to_dict()["content_fingerprint"] is None


def test_protected_or_outside_paths_never_reach_git_blob(tmp_path, monkeypatch):
    monkeypatch.setattr(sast, "Repo", MagicMock(side_effect=AssertionError))
    outside = tmp_path.parent.resolve() / "outside-canary.py"
    cfg = ScanConfig("org/repo", "main", "0" * 40, False)
    findings = _scan_records(tmp_path, "semgrep", [
        _semgrep_record("dir/.env.fixture"),
        _semgrep_record(outside),
        _semgrep_record("../outside-canary.py"),
        _semgrep_record("C:\\private\\outside-canary.py"),
    ], cfg)
    assert all(f.compute_content_fingerprint() is None for f in findings)
    assert all("outside-canary" not in f.file_path for f in findings)
