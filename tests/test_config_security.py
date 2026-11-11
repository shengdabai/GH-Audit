import json
import os
import stat

import pytest

import gh_audit.config as config


@pytest.mark.parametrize("stored_token", [None, "stored-config-canary"])
def test_unrelated_config_updates_do_not_persist_environment_token(
    tmp_path, monkeypatch, stored_token,
):
    path = tmp_path / "config.json"
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", path)
    monkeypatch.setenv("GITHUB_TOKEN", "session-config-canary")
    if stored_token is not None:
        path.write_text(json.dumps({"token": stored_token}))

    cfg = config.Config.load()
    assert cfg.effective_token == "session-config-canary"
    cfg.set("history_depth", "25")
    assert json.loads(path.read_text())["token"] == stored_token
    assert "session-config-canary" not in path.read_text()

    monkeypatch.delenv("GITHUB_TOKEN")
    assert config.Config.load().effective_token == stored_token


def test_explicit_token_update_persists_even_with_environment_override(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", path)
    monkeypatch.setenv("GITHUB_TOKEN", "session-config-canary")

    cfg = config.Config.load()
    cfg.set("token", "replacement-config-canary")
    assert cfg.effective_token == "session-config-canary"
    assert json.loads(path.read_text())["token"] == "replacement-config-canary"


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("descriptor_chmod", [False, True])
def test_config_is_private_before_secret_serialization(tmp_path, monkeypatch, existing, descriptor_chmod):
    if not descriptor_chmod:
        monkeypatch.delattr(config.os, "fchmod", raising=False)
    directory = tmp_path / "settings"
    directory.mkdir()
    path = directory / "config.json"
    if existing:
        path.write_text("{}")
        path.chmod(0o644)
    monkeypatch.setattr(config, "_CONFIG_DIR", directory)
    monkeypatch.setattr(config, "_CONFIG_FILE", path)
    dumps = json.dumps

    def check_permissions(data, **kwargs):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        return dumps(data, **kwargs)

    monkeypatch.setattr(config.json, "dumps", check_permissions)
    config.Config(token="synthetic-token").save()
    assert json.loads(path.read_text())["token"] == "synthetic-token"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires O_NOFOLLOW")
def test_config_rejects_symlink_without_overwriting_target(tmp_path, monkeypatch):
    target = tmp_path / "unrelated.txt"
    target.write_text("preserved")
    link = tmp_path / "config.json"
    link.symlink_to(target)
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_CONFIG_FILE", link)
    with pytest.raises(OSError):
        config.Config(token="synthetic-token").save()
    assert target.read_text() == "preserved"
