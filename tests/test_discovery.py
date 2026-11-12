import base64
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import pytest
from gh_audit.discovery import clone_repo, cleanup_repo, get_repo_info, list_org_repos, RepoInfo


def _make_repo_info():
    return RepoInfo(
        full_name="org/repo",
        default_branch="main",
        is_public=True,
        clone_url="https://github.com/org/repo.git",
        head_sha="abc123",
    )


@pytest.mark.parametrize(("attributes", "public"), [
    ({"visibility": "public", "private": False}, True),
    ({"visibility": "private", "private": True}, False),
    ({"visibility": "internal", "private": False}, False),
    ({"visibility": "unknown", "private": False}, False),
    ({"private": False}, True),
    ({"visibility": None, "private": False}, True),
    ({"private": 0}, False),
    ({"private": "false"}, False),
    ({}, False),
])
def test_discovery_only_trusts_explicit_visibility_or_literal_legacy_boolean(attributes, public):
    repo = SimpleNamespace(
        full_name="org/repo", default_branch="main", clone_url="https://github.com/org/repo.git",
        get_branch=lambda branch: SimpleNamespace(commit=SimpleNamespace(sha="abc")),
        **attributes,
    )
    with patch("gh_audit.discovery.Github") as github:
        github.return_value.get_repo.return_value = repo
        github.return_value.get_organization.return_value.get_repos.return_value = [repo]
        assert get_repo_info("org/repo").is_public is public
        assert list_org_repos("org")[0].is_public is public


def test_clone_repo_redacts_token_on_failure():
    """Token must not appear in error message when clone fails."""
    import git
    secret_token = "ghp_SUPERSECRETTOKEN123456789012"
    repo_info = _make_repo_info()

    with patch("git.Repo.clone_from") as mock_clone:
        mock_clone.side_effect = git.exc.GitCommandError(
            "clone", 128,
            stderr=f"remote: Invalid username or password for https://x-access-token:{secret_token}@github.com"
        )
        with pytest.raises(RuntimeError) as exc_info:
            clone_repo(repo_info, token=secret_token)

    assert secret_token not in str(exc_info.value)
    assert "***" in str(exc_info.value)


def test_clone_repo_raises_runtime_error_on_git_failure():
    import git
    repo_info = _make_repo_info()

    with patch("git.Repo.clone_from") as mock_clone:
        mock_clone.side_effect = git.exc.GitCommandError("clone", 128, stderr="not found")
        with pytest.raises(RuntimeError, match="Clone failed"):
            clone_repo(repo_info, token=None)


def test_cleanup_repo_handles_missing_dir(tmp_path):
    missing = str(tmp_path / "nonexistent")
    cleanup_repo(missing)  # should not raise


def test_clone_credentials_are_ephemeral(tmp_path):
    token = "synthetic-token"
    with patch("git.Repo.clone_from") as clone, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        assert clone_repo(_make_repo_info(), token) == str(tmp_path)
    args, kwargs = clone.call_args
    assert args[0] == "https://github.com/org/repo.git"
    assert token not in repr(args)
    env = kwargs["env"]
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    encoded = env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: Basic ")
    assert base64.b64decode(encoded).decode() == f"x-access-token:{token}"
    assert env["GIT_CONFIG_KEY_1"] == "http.followRedirects"
    assert env["GIT_CONFIG_VALUE_1"] == "false"
    assert kwargs["branch"] == "main"


@pytest.mark.parametrize("url", [
    "https://example.com/org/repo.git", "http://github.com/org/repo.git",
    "https://github.com@example.com/repo.git", "file:///tmp/repo",
    "https://github.com/org/repo.git?redirect=1",
])
def test_clone_rejects_untrusted_destinations(url):
    repo = _make_repo_info()
    repo.clone_url = url
    with patch("git.Repo.clone_from") as clone, \
         pytest.raises(RuntimeError, match="Clone URL"):
        clone_repo(repo, "synthetic-token")
    clone.assert_not_called()


def test_clone_redacts_encoded_credentials_and_cleans_up(tmp_path):
    import git
    token = "synthetic-token"
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    destination = tmp_path / "clone"
    destination.mkdir()
    with patch("tempfile.mkdtemp", return_value=str(destination)), \
         patch("git.Repo.clone_from", side_effect=git.exc.GitCommandError("clone", 128, stderr=encoded)):
        with pytest.raises(RuntimeError) as error:
            clone_repo(_make_repo_info(), token)
    assert encoded not in str(error.value)
    assert not destination.exists()


def test_clone_cleans_up_on_non_git_exception(tmp_path):
    destination = tmp_path / "clone"
    destination.mkdir()
    with patch("tempfile.mkdtemp", return_value=str(destination)), \
         patch("git.Repo.clone_from", side_effect=ValueError("invalid branch")):
        with pytest.raises(ValueError):
            clone_repo(_make_repo_info())
    assert not destination.exists()
