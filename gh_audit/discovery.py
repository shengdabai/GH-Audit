import shutil
import tempfile
from dataclasses import dataclass

import git
from github import Github, GithubException


@dataclass
class RepoInfo:
    full_name: str
    default_branch: str
    is_public: bool
    clone_url: str
    head_sha: str


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
                is_public=not repo.private,
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
        is_public=not repo.private,
        clone_url=repo.clone_url,
        head_sha=branch.commit.sha,
    )


def clone_repo(repo_info: RepoInfo, token: str | None = None, branch: str | None = None) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="gh-audit-")
    clone_url = repo_info.clone_url
    if token:
        clone_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
    try:
        requested_branch = branch or repo_info.default_branch
        git.Repo.clone_from(clone_url, tmp_dir, depth=1, branch=requested_branch, single_branch=True)
    except git.exc.GitCommandError as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        # Redact token from error message before raising
        msg = str(e)
        if token:
            msg = msg.replace(token, "***")
        raise RuntimeError(f"Clone failed for {repo_info.full_name}: {msg}") from None
    return tmp_dir


def cleanup_repo(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def checkout_sha(path: str) -> str:
    """Report the commit actually scanned, not discovery-time default HEAD."""
    return git.Repo(path).head.commit.hexsha
