from pathlib import Path
from unittest.mock import patch

import pytest

from gh_audit.scanners.base import ScanConfig
from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.secrets import SecretsScanner


@pytest.mark.parametrize("scanner", [SecretsScanner, PiiScanner, ScaScanner])
def test_scanners_never_read_symlink_targets(tmp_path, scanner):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic private content")
    (repo / "requirements.txt").symlink_to(outside)
    (repo / "linked-directory").symlink_to(tmp_path, target_is_directory=True)
    config = ScanConfig("org/repo", "main", "abc", True)
    with patch.object(Path, "read_text", side_effect=AssertionError("unexpected file read")), \
         patch.object(ScaScanner, "_external_tool_available", return_value=False), \
         patch("requests.post") as post:
        assert scanner().scan(str(repo), config) == []
    post.assert_not_called()


def test_walk_prunes_ignored_trees_but_not_repository_parents(tmp_path):
    from gh_audit.scanners.base import iter_repo_files
    repo = tmp_path / "build" / "repo"
    (repo / "node_modules" / "deep").mkdir(parents=True)
    (repo / "node_modules" / "deep" / "ignored.txt").write_text("ignored")
    (repo / "kept.txt").write_text("kept")
    assert list(iter_repo_files(str(repo))) == [repo / "kept.txt"]
