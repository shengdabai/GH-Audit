from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import gh_audit.config as config
from gh_audit.cli import cli


@pytest.fixture(autouse=True)
def isolate_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


def test_scan_requires_repo_or_org():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    assert result.exit_code != 0
    assert "Provide REPO" in result.output or result.exit_code == 2


def test_scan_unknown_module_warns():
    """Unknown module names should produce a warning (not a hard failure)."""
    runner = CliRunner()
    from gh_audit.discovery import RepoInfo
    fake_repo = RepoInfo(
        full_name="org/repo",
        default_branch="main",
        is_public=True,
        clone_url="https://github.com/org/repo.git",
        head_sha="abc123",
    )
    with patch("gh_audit.cli.Config.load") as mock_cfg, \
         patch("gh_audit.cli.get_repo_info", return_value=fake_repo), \
         patch("gh_audit.cli.clone_repo", return_value="/tmp/fake"), \
         patch("gh_audit.cli.cleanup_repo"):
        cfg = MagicMock()
        cfg.effective_token = None
        cfg.modules = ["secrets"]
        cfg.results_dir = MagicMock()
        cfg.history_depth = 1
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["scan", "org/repo", "--modules", "invalid_module"])
    assert "Unknown module" in result.output or "invalid_module" in result.output


def test_doctor_runs_without_token():
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        cfg.effective_token = None
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "token" in result.output.lower()


def test_history_no_results(tmp_path):
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        cfg.results_dir = tmp_path
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["history", "org/repo"])
    assert result.exit_code == 0
    assert "No scan history" in result.output


def test_suppress_stores_fingerprint(tmp_path, monkeypatch):
    """suppress command writes fingerprint to suppressions.json."""
    suppress_dir = tmp_path / ".gh-audit"
    suppress_dir.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    runner = CliRunner()
    fake_fp = "a" * 64
    result = runner.invoke(cli, ["suppress", fake_fp, "--reason", "test data"])
    assert result.exit_code == 0
    suppress_file = suppress_dir / "suppressions.json"
    assert suppress_file.exists(), "suppressions.json should be created"
    import json
    data = json.loads(suppress_file.read_text())
    assert fake_fp in data
    assert data[fake_fp]["reason"] == "test data"
    assert "created_at" in data[fake_fp]


def test_config_set_token_warns(tmp_path):
    runner = CliRunner()
    with patch("gh_audit.cli.Config.load") as mock_cfg:
        cfg = MagicMock()
        mock_cfg.return_value = cfg
        result = runner.invoke(cli, ["config", "set", "token", "ghp_test"])
    assert result.exit_code == 0
    assert "GITHUB_TOKEN" in result.output or "token" in result.output.lower()


def test_failed_clone_returns_failure_and_continues_org_scan(tmp_path, monkeypatch):
    from gh_audit.config import Config
    from gh_audit.discovery import RepoInfo
    repos = [RepoInfo(f"org/{name}", "main", True, f"https://github.com/org/{name}.git", "abc")
             for name in ("failed", "successful")]
    monkeypatch.setenv("GITHUB_TOKEN", "session-config-canary")
    with patch("gh_audit.cli.Config.load", return_value=Config(results_dir=tmp_path)), \
         patch("gh_audit.cli.list_org_repos", return_value=repos) as discover, \
         patch("gh_audit.cli.clone_repo", side_effect=[RuntimeError("Clone failed"), str(tmp_path)]) as clone, \
         patch("gh_audit.cli.checkout_sha", return_value="abc"), \
         patch("gh_audit.cli.SecretsScanner.scan", return_value=[]), \
         patch("gh_audit.cli.cleanup_repo") as cleanup, \
         patch("gh_audit.cli._write_reports") as report:
        result = CliRunner().invoke(cli, ["scan", "--org", "org", "--modules", "secrets"])
    assert result.exit_code == 1
    assert "Clone failed" in result.output
    discover.assert_called_once_with("org", "session-config-canary")
    assert [call.args[1] for call in clone.call_args_list] == ["session-config-canary"] * 2
    report.assert_called_once()
    assert report.call_args.args[1] == "org/successful"
    cleanup.assert_called_once_with(str(tmp_path))
