import base64
import shutil
import tempfile
from dataclasses import dataclass
from urllib.parse import urlsplit

import git
from github import Github, GithubException


@dataclass
class RepoInfo:
    full_name: str
    default_branch: str
    is_public: bool
    clone_url: str
    head_sha: str


def _is_public(repo) -> bool:
    visibility = getattr(repo, "visibility", None)
    if visibility is not None:
        return isinstance(visibility, str) and visibility == "public"
    return getattr(repo, "private", None) is False


def list_org_repos(org_name: str, token: str | None = None) -> list[RepoInfo]:
    gh = Github(token)
    org = gh.get_organization(org_name)
    repos = []
    for repo in org.get_repos():
        try:
            branch = repo.get_branch(repo.default_branch)
            repos.append(RepoInfo(
                full_name=repo.full_name,
                default_branch=repo.default_branch,
                is_public=_is_public(repo),
                clone_url=repo.clone_url,
                head_sha=branch.commit.sha,
            ))
        except GithubException:
            continue
    return repos


def get_repo_info(repo_name: str, token: str | None = None) -> RepoInfo:
    gh = Github(token)
    repo = gh.get_repo(repo_name)
    branch = repo.get_branch(repo.default_branch)
    return RepoInfo(
        full_name=repo.full_name,
        default_branch=repo.default_branch,
        is_public=_is_public(repo),
        clone_url=repo.clone_url,
        head_sha=branch.commit.sha,
    )


def clone_repo(repo_info: RepoInfo, token: str | None = None, branch: str | None = None) -> str:
    clone_url = repo_info.clone_url
    url = urlsplit(clone_url)
    if (url.scheme != "https" or url.netloc != "github.com"
            or url.query or url.fragment):
        raise RuntimeError("Clone URL must use HTTPS on github.com without credentials")
    tmp_dir = tempfile.mkdtemp(prefix="gh-audit-")
    env = {"GIT_TERMINAL_PROMPT": "0"}
    authorization = ""
    if token:
        authorization = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        # Git reads these settings only for this process; no credential in argv or .git/config.
        env.update({
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {authorization}",
            "GIT_CONFIG_KEY_1": "http.followRedirects",
            "GIT_CONFIG_VALUE_1": "false",
        })
    try:
        requested_branch = branch or repo_info.default_branch
        git.Repo.clone_from(clone_url, tmp_dir, depth=1, branch=requested_branch,
                            single_branch=True, env=env)
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if not isinstance(e, git.exc.GitCommandError):
            raise
        # Redact token from error message before raising
        msg = str(e)
        if token:
            msg = msg.replace(token, "***").replace(authorization, "***")
        raise RuntimeError(f"Clone failed for {repo_info.full_name}: {msg}") from None
    return tmp_dir


def cleanup_repo(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def checkout_sha(path: str) -> str:
    """Report the commit actually scanned, not discovery-time default HEAD."""
    return git.Repo(path).head.commit.hexsha
