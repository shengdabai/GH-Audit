import json
import subprocess
from unittest.mock import MagicMock, patch
import pytest
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError


def _cfg(is_public=True, network="auto"):
    return ScanConfig(repo="org/repo", branch="main", commit_sha="abc",
                      is_public=is_public, sca_network=network)


def test_sca_available_by_default():
    # ScaScanner has no is_available override — defaults to True (fallback to API mode)
    with patch("shutil.which", return_value=None):
        assert ScaScanner().is_available() is True


def test_osv_scanner_returns_findings(tmp_path):
    osv_output = {
        "results": [{
            "source": {"path": "requirements.txt"},
            "packages": [{
                "package": {"name": "requests", "version": "2.20.0"},
                "vulnerabilities": [{"id": "GHSA-1234-5678-abcd"}]
            }]
        }]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(osv_output)
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", return_value=mock_result):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234-5678-abcd"
    assert "requests" in findings[0].evidence_redacted


def test_osv_scanner_timeout_raises_incomplete(tmp_path):
    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("osv-scanner", 120)):
            with pytest.raises(ScanIncompleteError):
                ScaScanner().scan(str(tmp_path), _cfg())


def test_osv_api_fallback_parses_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\nflask==1.0.0\n")

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "results": [
            {"vulns": [{"id": "GHSA-1234"}]},  # requests has vuln
            {"vulns": []},                       # flask is clean
        ]
    }

    with patch("shutil.which", return_value=None):
        with patch("requests.post", return_value=mock_resp):
            findings = ScaScanner().scan(str(tmp_path), _cfg())

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-1234"


def test_osv_api_fallback_handles_network_error(tmp_path):
    import requests as req_lib
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")

    with patch("shutil.which", return_value=None):
        with patch("requests.post", side_effect=req_lib.RequestException("timeout")):
            with pytest.raises(ScanIncompleteError):
                ScaScanner().scan(str(tmp_path), _cfg())


@pytest.mark.parametrize("version", [1, 2, 3])
def test_npm_lockfiles_use_npm_ecosystem(tmp_path, version):
    packages = {"old-package": {"version": "1.0.0", "dependencies": {
        "@scope/nested": {"version": "2.0.0"}}}}
    lock = {"lockfileVersion": version, "dependencies": packages}
    if version >= 2:
        lock["packages"] = {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/old-package": {"version": "1.0.0"},
            "node_modules/old-package/node_modules/@scope/nested": {"version": "2.0.0"},
            "node_modules/local": {"version": "file:../local"},
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    response = MagicMock(status_code=200)
    response.json.return_value = {"results": [{"vulns": [{"id": "GHSA-test"}]}, {}]}
    with patch("shutil.which", return_value=None), patch("requests.post", return_value=response) as post:
        findings = ScaScanner().scan(str(tmp_path), _cfg())
    assert post.call_args.kwargs["json"]["queries"] == [
        {"version": "1.0.0", "package": {"name": "old-package", "ecosystem": "npm"}},
        {"version": "2.0.0", "package": {"name": "@scope/nested", "ecosystem": "npm"}},
    ]
    assert len(findings) == 1
    assert findings[0].file_path == "package-lock.json"
    assert findings[0].rule_id == "GHSA-test"


def test_fallback_checks_beyond_old_file_and_package_limits(tmp_path):
    for number in range(6):
        (tmp_path / f"requirements-{number}.txt").write_text(
            "\n".join(f"package-{index}==1.0.0" for index in range(105)))
    with patch.object(ScaScanner, "_query_osv_api_batch", return_value={}) as query:
        ScaScanner()._osv_api_fallback(str(tmp_path), _cfg())
    assert query.call_count == 12
    assert sum(len(call.args[0]) for call in query.call_args_list) == 630
    assert all(len(call.args[0]) <= 100 for call in query.call_args_list)


def test_osv_http_error_raises_incomplete():
    import requests
    response = MagicMock(status_code=500)
    response.raise_for_status.side_effect = requests.HTTPError("server error")
    with patch("requests.post", return_value=response):
        with pytest.raises(ScanIncompleteError):
            ScaScanner()._query_osv_api_batch([("package", "1.0.0")])
    response.json.assert_not_called()


@pytest.mark.parametrize("lock", [[], {"packages": []}, {"dependencies": []}])
def test_malformed_lockfile_raises_incomplete(tmp_path, lock):
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    with pytest.raises(ScanIncompleteError):
        ScaScanner()._osv_api_fallback(str(tmp_path), _cfg())


@pytest.fixture
def offline_paths(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    executable = tmp_path / "osv-scanner"
    executable.touch()
    return checkout.resolve(), str(executable.resolve())


@pytest.mark.parametrize("config", [_cfg(False), _cfg(None), _cfg("true"), _cfg(True, "offline")])
def test_offline_uses_only_v2_command_and_cached_database(offline_paths, config):
    checkout, binary = offline_paths
    version = subprocess.CompletedProcess([], 0, "osv-scanner version: 2.7.1\n", "")
    scan = subprocess.CompletedProcess([], 0, '{"results": []}', "")
    with patch("shutil.which", return_value=binary), \
         patch("subprocess.run", side_effect=[version, scan]) as run, \
         patch("requests.post") as post:
        assert ScaScanner().scan(str(checkout), config) == []
    assert [call.args[0] for call in run.call_args_list] == [
        [binary, "--version"],
        [binary, "scan", "source", "--offline", "--format", "json", "--verbosity", "error", "--recursive",
         "--no-call-analysis=go", "--no-call-analysis=rust",
         str(checkout)],
    ]
    post.assert_not_called()


@pytest.mark.parametrize("version", ["osv-scanner version: 1.9.3", "osv-scanner version: 3.0.0", "unknown"])
def test_private_unsupported_osv_version_does_not_pass_repository_to_tool(offline_paths, version):
    checkout, binary = offline_paths
    probe = subprocess.CompletedProcess([], 0, version, "")
    with patch("shutil.which", return_value=binary), \
         patch("subprocess.run", return_value=probe) as run, \
         patch("requests.post") as post:
        with pytest.raises(ScanIncompleteError, match="requires OSV-Scanner v2"):
            ScaScanner().scan(str(checkout), _cfg(False))
    run.assert_called_once_with([binary, "--version"], capture_output=True, text=True, timeout=10)
    post.assert_not_called()


def test_private_missing_osv_is_incomplete_without_network(tmp_path):
    with patch("shutil.which", return_value=None), patch("requests.post") as post:
        with pytest.raises(ScanIncompleteError, match="offline SCA requires"):
            ScaScanner().scan(str(tmp_path), _cfg(False))
    post.assert_not_called()


@pytest.mark.parametrize("code", [0, 1, 127])
def test_private_missing_database_does_not_fall_back(offline_paths, code):
    checkout, binary = offline_paths
    version = subprocess.CompletedProcess([], 0, "osv-scanner version: 2.7.1\n", "")
    failure = subprocess.CompletedProcess([], code, '{"results": []}', "synthetic private package path")
    with patch("shutil.which", return_value=binary), \
         patch("subprocess.run", side_effect=[version, failure]), \
         patch("requests.post") as post:
        with pytest.raises(ScanIncompleteError, match="local database") as error:
            ScaScanner().scan(str(checkout), _cfg(False))
    assert "synthetic private package path" not in str(error.value)
    post.assert_not_called()


@pytest.mark.parametrize("route", ["relative", "inside", "symlink_into", "symlink_out"])
def test_private_rejects_untrusted_tool_before_invocation(offline_paths, route):
    checkout, trusted = offline_paths
    untrusted = checkout / "osv-scanner"
    if route == "symlink_out":
        untrusted.symlink_to(trusted)
    else:
        untrusted.touch()
    if route == "relative":
        selected = "bin/osv-scanner"
    elif route == "symlink_into":
        link = checkout.parent / "scanner-link"
        link.symlink_to(untrusted)
        selected = str(link)
    else:
        selected = str(untrusted)
    with patch("shutil.which", return_value=selected), \
         patch("subprocess.run") as run, patch("requests.post") as post:
        with pytest.raises(ScanIncompleteError, match="absolute|outside"):
            ScaScanner().scan(str(checkout), _cfg(False))
    run.assert_not_called()
    post.assert_not_called()


def test_private_can_explicitly_opt_into_online_fallback(tmp_path):
    (tmp_path / "requirements.txt").write_text("sample-pkg==1.0.0\n")
    response = MagicMock(status_code=200)
    response.json.return_value = {"results": [{}]}
    with patch("shutil.which", return_value=None), patch("requests.post", return_value=response) as post:
        assert ScaScanner().scan(str(tmp_path), _cfg(False, "online")) == []
    post.assert_called_once()


def test_pypi_public_fallback_sends_only_valid_exact_coordinates(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "pkg-foo[extra1, extra2] == 1!2.0rc1.post2.dev3+build.1 ; python_version >= '3.11'\n"
        "pkg-bar==1.2.3 --hash=sha256:synthetic\n"
        "not-registry @ https://example.invalid/package.zip\n"
        "bad==https://example.invalid/private.zip\n"
        "bad==git+ssh://example.invalid/repo\n"
        "bad==file:./test\n"
        "bad==1.2.*\n"
        "bad==1.2.3 unexpected\n"
        "../private==1.0.0\n"
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"results": [{}, {}]}
    with patch("shutil.which", return_value=None), patch("requests.post", return_value=response) as post:
        assert ScaScanner().scan(str(tmp_path), _cfg()) == []
    assert post.call_args.kwargs["json"]["queries"] == [
        {"version": "1!2.0rc1.post2.dev3+build.1", "package": {"name": "pkg-foo", "ecosystem": "PyPI"}},
        {"version": "1.2.3", "package": {"name": "pkg-bar", "ecosystem": "PyPI"}},
    ]


def test_npm_lock_validates_scopes_aliases_and_registry_origin():
    scanner = ScaScanner()
    v1 = {"dependencies": {"alias": {"version": "npm:@scope/real@2.3.4-beta.2+build"}}}
    assert scanner._parse_package_lock(json.dumps(v1)) == [("@scope/real", "2.3.4-beta.2+build")]
    v3 = {"packages": {
        "node_modules/alias": {"name": "@scope/real", "version": "2.3.4-beta.2+build",
                               "resolved": "https://registry.npmjs.org/@scope/real/-/real-2.3.4.tgz"},
        "node_modules/bad-name": {"name": "token=value", "version": "1.2.3"},
        "node_modules/workspace": {"version": "1.2.3", "link": True},
        "node_modules/git-source": {"version": "1.2.3", "resolved": "git+ssh://example.invalid/repo"},
        "node_modules/local-source": {"version": "1.2.3", "resolved": "file:../private"},
        "node_modules/tarball": {"version": "1.2.3", "resolved": "https://example.invalid/package.tgz"},
        "node_modules/url-parameters": {"version": "1.2.3",
                                        "resolved": "https://registry.npmjs.org/pkg.tgz?key=value"},
        "node_modules/malformed": {"version": "1.2.3", "resolved": "https://["},
    }}
    assert scanner._parse_package_lock(json.dumps(v3)) == [("@scope/real", "2.3.4-beta.2+build")]


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_osv_http_redirect_is_incomplete_without_following(status):
    response = MagicMock(status_code=status)
    with patch("requests.post", return_value=response) as post:
        with pytest.raises(ScanIncompleteError, match="OSV API request or response failed"):
            ScaScanner()._query_osv_api_batch([("package", "1.0.0")])
    post.assert_called_once()
    assert post.call_args.kwargs["allow_redirects"] is False
    response.json.assert_not_called()
