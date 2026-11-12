import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from gh_audit import config, scan_baseline
from gh_audit.cli import cli
from gh_audit.discovery import RepoInfo
from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scan_baseline import BaselineError, ScanBaseline
from gh_audit.scanners.base import ScanIncompleteError


def _finding(name, *, category=Category.SECRETS, occurrence=1):
    is_sast = category == Category.SAST
    return Finding(
        finding_id=f"{name}-{occurrence}",
        fingerprint=f"sast-location-v1:{occurrence:064x}" if is_sast else "",
        repo="org/example", branch="main", commit_sha="a" * 40,
        file_path="app.py", line_start=occurrence, line_end=occurrence,
        category=category, rule_id=name, title=name,
        severity=Severity.HIGH, confidence=Confidence.LIKELY,
        evidence_redacted="private-fixture-value", recommendation="Review",
        standard_mapping=[], scanner=category.value,
        discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
        sast_content_id="sast-v1:" + "a" * 64 if is_sast else None,
    )


@pytest.fixture
def scan_cli(tmp_path, monkeypatch):
    import importlib

    commands = importlib.import_module("gh_audit.cli")
    home = tmp_path / "home"
    home.mkdir()
    settings = home / ".gh-audit"
    results = settings / "results"
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(config, "_CONFIG_DIR", settings)
    monkeypatch.setattr(config, "_CONFIG_FILE", settings / "config.json")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    outcomes = {}
    calls = []

    def repo_info(name):
        return RepoInfo(name, "main", True, f"https://github.com/{name}.git", "a" * 40)

    def scanner(module):
        class FixtureScanner:
            def is_available(self):
                return True

            def scan(self, checkout, cfg):
                calls.append((cfg.repo, cfg.branch, module))
                outcome = outcomes.get(calls[-1], [])
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        return FixtureScanner

    monkeypatch.setattr(commands, "get_repo_info", lambda name, token: repo_info(name))
    monkeypatch.setattr(commands, "list_org_repos", lambda name, token: [
        repo_info(f"{name}/first"), repo_info(f"{name}/second"),
    ])
    monkeypatch.setattr(commands, "clone_repo", lambda *args, **kwargs: str(tmp_path / "fixture"))
    monkeypatch.setattr(commands, "checkout_sha", lambda path: "a" * 40)
    monkeypatch.setattr(commands, "cleanup_repo", lambda path: None)
    monkeypatch.setattr(commands, "_ALL_SCANNERS", {
        module: scanner(module) for module in ("secrets", "sast", "pii", "sca")
    })

    def run(*args):
        return CliRunner().invoke(cli, ["scan", *args])

    return run, results, outcomes, calls


@pytest.mark.parametrize("portable", [False, True])
def test_complete_baseline_precedes_filters_and_survives_repeated_diff(scan_cli, monkeypatch, portable):
    if portable:
        monkeypatch.setattr(scan_baseline, "_SECURE_STORAGE", False)
    run, results, outcomes, _ = scan_cli
    first, second = _finding("first finding"), _finding("second finding")
    second.severity = Severity.CRITICAL
    outcomes["org/example", "main", "secrets"] = [first, second]
    monkeypatch.setattr("gh_audit.cli.load_suppressions", lambda: {second.compute_content_fingerprint()})
    initial = run("org/example", "--modules", "secrets", "--min-severity", "critical")
    assert initial.exit_code == 0, initial.output
    assert "No findings." in initial.output

    monkeypatch.setattr("gh_audit.cli.load_suppressions", lambda: set())
    for output in ("html", "terminal"):
        comparison = run("org/example", "--modules", "secrets", "--diff", "--output", output)
        assert comparison.exit_code == 0, comparison.output
        assert "0 new or ambiguous findings" in comparison.output

    baseline = ScanBaseline(results, "org/example", "main", ["secrets"])
    path = results / scan_baseline._DIRECTORY / baseline.name
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    saved = json.loads(path.read_text())
    assert set(saved) == {"version", "scope", "counts"}
    assert saved["counts"] == {
        first.compute_content_fingerprint(): 1, second.compute_content_fingerprint(): 1,
    }
    assert "private-fixture-value" not in path.read_text()
    assert not list((results / "org_example").glob("*.json"))


def test_baseline_scopes_branch_module_set_and_repository(scan_cli):
    run, results, outcomes, calls = scan_cli
    for repo in ("org/example", "org/another"):
        for branch in ("main", "Main"):
            outcomes[repo, branch, "secrets"] = [_finding("fixture finding")]
    assert run("org/example", "--modules", "secrets,pii,secrets").exit_code == 0
    assert calls.count(("org/example", "main", "secrets")) == 1
    assert "0 new or ambiguous findings" in run("org/example", "--modules", "pii,secrets", "--diff").output
    for args in (("org/example", "--modules", "secrets"),
                 ("org/example", "--branch", "Main", "--modules", "secrets,pii"),
                 ("org/another", "--modules", "secrets,pii")):
        assert "no complete baseline" in run(*args, "--diff").output
    assert len(list((results / scan_baseline._DIRECTORY).glob("*.json"))) == 4


def test_sca_networking_mode_has_its_own_baseline(scan_cli):
    run, results, outcomes, _ = scan_cli
    outcomes["org/example", "main", "sca"] = [_finding("fixture dependency", category=Category.SCA)]
    command = ("org/example", "--modules", "sca")
    assert run(*command).exit_code == 0

    offline = run(*command, "--sca-network", "offline", "--diff")
    assert offline.exit_code == 0 and "no complete baseline" in offline.output

    for mode in ("online", "offline"):
        comparison = run(*command, "--sca-network", mode, "--diff")
        assert comparison.exit_code == 0 and "0 new or ambiguous findings" in comparison.output

    assert len(list((results / scan_baseline._DIRECTORY).glob("*.json"))) == 2


@pytest.mark.parametrize("new_first", [False, True])
def test_diff_displays_grown_sast_group_in_both_orders_and_ignores_pure_move(scan_cli, new_first):
    run, results, outcomes, _ = scan_cli
    first = _finding("copy", category=Category.SAST)
    moved = _finding("copy", category=Category.SAST, occurrence=2)
    added = _finding("copy", category=Category.SAST, occurrence=3)
    unknown = _finding("unidentified", category=Category.SAST, occurrence=4)
    unknown.sast_content_id = None
    outcomes["org/example", "main", "sast"] = [first]
    assert run("org/example", "--modules", "sast").exit_code == 0
    command = ("org/example", "--modules", "sast", "--diff")
    outcomes["org/example", "main", "sast"] = [moved]
    assert "0 new or ambiguous findings" in run(*command).output
    group = [added, moved] if new_first else [moved, added]
    outcomes["org/example", "main", "sast"] = [*group, unknown]
    assert "3 new or ambiguous findings" in run(*command, "--output", "json").output
    [report] = (results / "org_example").glob("*.json")
    assert {item["line_start"] for item in json.loads(report.read_text())["findings"]} == {2, 3, 4}
    assert "1 new or ambiguous findings" in run(*command).output


@pytest.mark.parametrize("failure_type", [ScanIncompleteError, RuntimeError])
def test_incomplete_repo_keeps_baseline_and_other_org_repo_advances(scan_cli, failure_type):
    run, results, outcomes, _ = scan_cli
    first, second, new = _finding("first safe finding"), _finding("second safe finding"), _finding("new finding")
    outcomes["org/first", "main", "secrets"] = [first]
    outcomes["org/first", "main", "pii"] = [_finding("first pii", category=Category.PII)]
    outcomes["org/second", "main", "secrets"] = [second]
    command = ("--org", "org", "--modules", "secrets,pii")
    assert run(*command).exit_code == 0
    first_snapshot = ScanBaseline(results, "org/first", "main", ["secrets", "pii"])
    second_snapshot = ScanBaseline(results, "org/second", "main", ["secrets", "pii"])
    previous = first_snapshot.load()

    outcomes["org/first", "main", "pii"] = failure_type("synthetic module failure")
    outcomes["org/second", "main", "secrets"] = [second, new]
    incomplete = run(*command, "--diff", "--output", "json")
    assert incomplete.exit_code == 1
    assert "--diff skipped for this incomplete scan" in incomplete.output
    [report] = (results / "org_first").glob("*.json")
    assert [item["title"] for item in json.loads(report.read_text())["findings"]] == [first.title]
    assert "1 new or ambiguous findings" in incomplete.output
    assert first_snapshot.load() == previous
    assert new.compute_content_fingerprint() in second_snapshot.load()


def test_legacy_json_is_ignored_and_malformed_sidecar_recovers(scan_cli):
    run, results, outcomes, _ = scan_cli
    finding = _finding("legacy fixture")
    outcomes["org/example", "main", "secrets"] = [finding]
    report = results / "org_example" / "20261112_120000.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"findings": [finding.to_dict()]}))
    command = ("org/example", "--modules", "secrets", "--diff")
    assert "no complete baseline" in run(*command).output
    baseline = ScanBaseline(results, "org/example", "main", ["secrets"])
    path = results / scan_baseline._DIRECTORY / baseline.name
    path.write_text("malformed fixture")
    comparison = run(*command)
    assert comparison.exit_code == 0
    assert "could not read the baseline" in comparison.output
    assert finding.title in comparison.output
    assert "0 new or ambiguous findings" in run(*command).output
    assert report.exists()


def test_failed_baseline_write_warns_and_keeps_next_diff_visible(scan_cli, monkeypatch):
    run, results, outcomes, _ = scan_cli
    old, new = _finding("older fixture"), _finding("baseline write fixture")
    outcomes["org/example", "main", "secrets"] = [old]
    command = ("org/example", "--modules", "secrets", "--diff")
    assert run(*command).exit_code == 0
    outcomes["org/example", "main", "secrets"] = [old, new]
    baseline = ScanBaseline(results, "org/example", "main", ["secrets"])

    def fail_save(self, findings):
        raise BaselineError("synthetic write failure")

    with monkeypatch.context() as patched:
        patched.setattr(ScanBaseline, "save", fail_save)
        comparison = run(*command, "--output", "json")
    assert comparison.exit_code == 0
    assert "Could not save the scan baseline" in comparison.output
    assert "next diff may show these findings again" in comparison.output
    [report] = (results / "org_example").glob("*.json")
    assert [item["title"] for item in json.loads(report.read_text())["findings"]] == [new.title]
    assert baseline.load() == {old.compute_content_fingerprint(): 1}
    assert "1 new or ambiguous findings" in run(*command).output


def test_partial_report_delivery_does_not_consume_new_findings(scan_cli, monkeypatch):
    run, results, outcomes, _ = scan_cli
    old, new = _finding("older fixture"), _finding("unseen fixture")
    outcomes["org/example", "main", "secrets"] = [old]
    command = ("org/example", "--modules", "secrets", "--diff")
    assert run(*command).exit_code == 0
    outcomes["org/example", "main", "secrets"] = [old, new]
    baseline = ScanBaseline(results, "org/example", "main", ["secrets"])

    def fail_html(self, findings, output_path, repo):
        raise OSError("synthetic report write failure")

    with monkeypatch.context() as patched:
        patched.setattr("gh_audit.cli.HtmlReporter.write", fail_html)
        failed = run(*command, "--output", "json,html")
    assert failed.exit_code == 1
    assert "Could not deliver all requested reports" in failed.output
    assert list((results / "org_example").glob("*.json"))
    assert baseline.load() == {old.compute_content_fingerprint(): 1}

    retry = run(*command, "--output", "json,html")
    assert retry.exit_code == 0
    assert "1 new or ambiguous findings" in retry.output
    latest = max((results / "org_example").glob("*.json"))
    assert [item["title"] for item in json.loads(latest.read_text())["findings"]] == [new.title]
    assert "0 new or ambiguous findings" in run(*command).output


@pytest.mark.parametrize("formats", ["", "json,unknown"])
def test_invalid_output_fails_before_scan_or_baseline_update(scan_cli, formats):
    run, results, outcomes, calls = scan_cli
    old, new = _finding("older fixture"), _finding("new fixture")
    outcomes["org/example", "main", "secrets"] = [old]
    command = ("org/example", "--modules", "secrets")
    assert run(*command).exit_code == 0
    outcomes["org/example", "main", "secrets"] = [old, new]
    calls_before = len(calls)
    rejected = run(*command, "--diff", "--output", formats)
    assert rejected.exit_code == 2
    assert "--output" in rejected.output
    assert len(calls) == calls_before
    baseline = ScanBaseline(results, "org/example", "main", ["secrets"])
    assert baseline.load() == {old.compute_content_fingerprint(): 1}
    assert "1 new or ambiguous findings" in run(*command, "--diff").output


@pytest.mark.skipif(os.name == "nt", reason="fixture requires symlink privileges")
@pytest.mark.parametrize("portable", [False, True])
def test_sidecar_refuses_symlink_and_rejects_invalid_counts(tmp_path, monkeypatch, portable):
    if portable:
        monkeypatch.setattr(scan_baseline, "_SECURE_STORAGE", False)
    baseline = ScanBaseline(tmp_path, "org/example", "main", ["sast"])
    baseline.save([])
    sidecar = tmp_path / scan_baseline._DIRECTORY / baseline.name
    sidecar.write_text(json.dumps({
        "version": 1, "scope": baseline.scope, "counts": {"source-canary": 1},
    }))
    with pytest.raises(BaselineError):
        baseline.load()
    sidecar.unlink()
    target = tmp_path / "target.json"
    target.write_text("untouched fixture")
    sidecar.symlink_to(target)
    with pytest.raises(BaselineError):
        baseline.load()
    with pytest.raises(BaselineError):
        baseline.save([])
    assert target.read_text() == "untouched fixture"


def test_portable_backend_rejects_changed_file_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_baseline, "_SECURE_STORAGE", False)
    baseline = ScanBaseline(tmp_path, "org/example", "main", ["sast"])
    baseline.save([])
    path = tmp_path / scan_baseline._DIRECTORY / baseline.name
    replacement = tmp_path / "replacement.json"
    replacement.write_text(path.read_text())
    replacement.chmod(0o600)
    real_open = os.open

    def replace_before_open(opened, flags):
        replacement.replace(path)
        return real_open(opened, flags)

    with monkeypatch.context() as patched:
        patched.setattr(scan_baseline.os, "open", replace_before_open)
        with pytest.raises(BaselineError, match="opened baseline differs"):
            baseline.load()


def test_portable_backend_rejects_reparse_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_baseline, "_SECURE_STORAGE", False)
    baseline = ScanBaseline(tmp_path, "org/example", "main", ["sast"])
    baseline.save([])
    directory = tmp_path / scan_baseline._DIRECTORY
    real_lstat = Path.lstat

    def mark_reparse(path):
        info = real_lstat(path)
        if path == directory:
            return SimpleNamespace(st_mode=info.st_mode, st_ino=info.st_ino,
                                   st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return info

    monkeypatch.setattr(Path, "lstat", mark_reparse)
    with pytest.raises(BaselineError, match="path type or identity"):
        baseline.load()
    with pytest.raises(BaselineError, match="path type or identity"):
        baseline.save([])
