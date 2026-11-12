import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from gh_audit import config
from gh_audit.normalizer import load_previous_content_fingerprints
from gh_audit import sast_identity as identity


def test_fingerprints_are_scoped_to_install_repository_branch_scanner_and_rule():
    def fingerprint(key=b"x" * 32, repo="Org/Repo", branch="main", scanner="semgrep", rule="rule"):
        return identity.fingerprints(key, repo, branch, scanner, rule, "source-canary", "app.py", (1, 1, 0, 2))

    assert fingerprint() == fingerprint(repo="org/repo")
    assert all(fingerprint()[1] != other[1] for other in [
        fingerprint(key=b"y" * 32), fingerprint(repo="org/other"), fingerprint(branch="Main"),
        fingerprint(scanner="bandit"), fingerprint(rule="other"),
    ])


@pytest.fixture
def private_directory(tmp_path, monkeypatch):
    if not identity._KEY_STORAGE_AVAILABLE:
        pytest.skip("platform lacks descriptor-relative private key storage")
    directory = tmp_path / "config"
    monkeypatch.setattr(config, "_CONFIG_DIR", directory)
    return directory


def test_atomic_creation_returns_one_complete_key_for_concurrent_scans(private_directory):
    ready = Barrier(8)

    def read_key():
        ready.wait(timeout=10)
        return identity.load_or_create_key()

    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: read_key(), range(8)))
    assert keys[0] is not None and len(keys[0]) == 32
    assert len(set(keys)) == 1
    assert len(list(private_directory.iterdir())) == 1
    key_path = private_directory / identity._KEY_NAME
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert identity.load_or_create_key() == keys[0]


def test_unsafe_key_path_and_bad_mode_are_unavailable(private_directory):
    private_directory.mkdir(mode=0o700)
    target = private_directory.parent / "fixture.bin"
    target.write_bytes(b"x" * 32)
    path = private_directory / identity._KEY_NAME
    path.symlink_to(target)
    assert identity.load_or_create_key() is None
    assert target.read_bytes() == b"x" * 32
    path.unlink()
    path.write_bytes(b"y" * 32)
    os.chmod(path, 0o644)
    assert identity.load_or_create_key() is None
    os.chmod(path, 0o600)
    path.write_bytes(b"incomplete")
    assert identity.load_or_create_key() is None
    assert path.read_bytes() == b"incomplete"


def test_symlinked_config_directory_is_unavailable(private_directory):
    target = private_directory.parent / "target"
    target.mkdir(mode=0o700)
    private_directory.symlink_to(target, target_is_directory=True)
    assert identity.load_or_create_key() is None
    assert list(target.iterdir()) == []


def test_legacy_sast_ids_are_ignored_without_invalidating_other_scanners(tmp_path):
    repo = tmp_path / "org_repo"
    repo.mkdir()
    keyed = "sast-v1:" + "a" * 64
    legacy_sast = "b" * 64
    other = "c" * 64
    (repo / "20261112_120000.json").write_text(json.dumps({"findings": [
        {"category": "sast", "content_fingerprint": legacy_sast},
        {"category": "sast", "content_fingerprint": None},
        {"category": "sast", "content_fingerprint": keyed},
        {"category": "secrets", "content_fingerprint": other},
    ]}))
    assert load_previous_content_fingerprints(tmp_path, "org/repo") == {keyed, other}


def test_previous_reports_count_identical_sast_occurrences(tmp_path):
    repo = tmp_path / "org_repo"
    repo.mkdir()
    identity_value = "sast-v1:" + "a" * 64
    finding = {"category": "sast", "content_fingerprint": identity_value}
    (repo / "20261112_120000.json").write_text(json.dumps({"findings": [finding, finding]}))
    assert load_previous_content_fingerprints(tmp_path, "org/repo", count_occurrences=True)[identity_value] == 2
