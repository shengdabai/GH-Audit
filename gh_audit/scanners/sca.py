import json
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests
from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import (
    BaseScanner, ScanConfig, ScanIncompleteError, iter_repo_files, result_records,
    run_json_tool,
)

_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", re.IGNORECASE | re.ASCII)
_NPM_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_PYPI_PIN = re.compile(
    r"([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)"
    r"(?:\[[a-z0-9._, -]+\])?\s*==\s*([^\s;#]+)(?=$|\s*[;#]|\s+--hash=)",
    re.IGNORECASE | re.ASCII,
)
_PYPI_VERSION = re.compile(
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?",
    re.IGNORECASE | re.ASCII,
)
_OSV_V2 = re.compile(r"osv-scanner version: v?2\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?")


class ScaScanner(BaseScanner):
    name = "sca"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            if config.sca_network not in ("auto", "offline", "online"):
                raise ValueError("invalid SCA network policy")
            if config.sca_is_offline:
                return self._run_osv_scanner(repo_path, config, offline=True)
            if self._external_tool_available("osv-scanner"):
                return self._run_osv_scanner(repo_path, config)
            return self._osv_api_fallback(repo_path, config)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError) as exc:
            raise ScanIncompleteError("scan incomplete: sca returned invalid or unreadable data") from exc

    def _run_osv_scanner(self, repo_path: str, config: ScanConfig, *, offline: bool = False) -> list[Finding]:
        if offline:
            tool = shutil.which("osv-scanner")
            if not tool:
                raise ScanIncompleteError("scan incomplete: offline SCA requires OSV-Scanner v2 and a local database")
            executable = Path(tool)
            if not executable.is_absolute():
                raise ScanIncompleteError("scan incomplete: offline SCA requires an absolute OSV-Scanner executable path")
            try:
                checkout = Path(repo_path).resolve(strict=True)
                resolved_executable = executable.resolve(strict=True)
            except (OSError, RuntimeError):
                raise ScanIncompleteError("scan incomplete: could not resolve offline OSV-Scanner paths") from None
            if executable.is_relative_to(checkout) or resolved_executable.is_relative_to(checkout):
                raise ScanIncompleteError("scan incomplete: offline OSV-Scanner must be installed outside the checkout")
            binary = str(resolved_executable)
            try:
                version = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                raise ScanIncompleteError("scan incomplete: could not check OSV-Scanner version") from None
            if version.returncode != 0 or not any(
                    _OSV_V2.fullmatch(line.strip()) for line in version.stdout.splitlines()):
                raise ScanIncompleteError("scan incomplete: offline SCA requires OSV-Scanner v2")
            # Older versions can otherwise invoke external language tooling in offline mode.
            command = [binary, "scan", "source", "--offline", "--format", "json", "--verbosity", "error", "--recursive",
                       "--no-call-analysis=go", "--no-call-analysis=rust",
                       str(checkout)]
            try:
                # OSV-Scanner can return 1 for findings even if it also logged an error.
                data = run_json_tool(command, require_empty_stderr=True)
            except ScanIncompleteError:
                raise ScanIncompleteError(
                    "scan incomplete: offline OSV-Scanner failed; check the scanner and local database"
                ) from None
        else:
            data = run_json_tool(["osv-scanner", "--format=json", repo_path])
        findings = []
        for r in result_records(data, "results", nullable=True):
            for pkg in result_records(r, "packages"):
                pkg_info = pkg.get("package", {})
                for vuln in result_records(pkg, "vulnerabilities", optional=True):
                    f = Finding(
                        finding_id=str(uuid.uuid4()), fingerprint="",
                        repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                        file_path=r.get("source", {}).get("path", ""),
                        line_start=0, line_end=0,
                        category=Category.SCA,
                        rule_id=vuln.get("id", "unknown-vuln"),
                        title=f"Vulnerable dependency: {pkg_info.get('name', '?')} - {vuln.get('id', '?')}",
                        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        evidence_redacted=f"{pkg_info.get('name')}@{pkg_info.get('version')}",
                        recommendation="Upgrade to a patched version",
                        standard_mapping=[vuln.get("id", "")],
                        scanner="osv-scanner",
                        discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
                    )
                    f.fingerprint = f.compute_fingerprint()
                    findings.append(f)
        return findings

    def _osv_api_fallback(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        lock_files = (path for path in iter_repo_files(repo_path)
                      if path.match("requirements*.txt") or path.name == "package-lock.json")
        findings = []
        for lock in lock_files:
            try:
                text = lock.read_text(encoding="utf-8")
                ecosystem = "npm" if lock.name == "package-lock.json" else "PyPI"
                packages = (self._parse_package_lock(text) if ecosystem == "npm"
                            else self._parse_requirements(text))
                # Batch OSV API calls
                vulns_by_pkg = {}
                for start in range(0, len(packages), 100):
                    vulns_by_pkg.update(self._query_osv_api_batch(packages[start:start + 100], ecosystem))
                for (pkg, version), vulns in vulns_by_pkg.items():
                    for v in vulns:
                        f = Finding(
                            finding_id=str(uuid.uuid4()), fingerprint="",
                            repo=config.repo, branch=config.branch, commit_sha=config.commit_sha,
                            file_path=str(lock.relative_to(repo_path)),
                            line_start=0, line_end=0,
                            category=Category.SCA,
                            rule_id=v.get("id", "osv-vuln"),
                            title=f"Vulnerable dependency: {pkg}=={version} ({v.get('id', '?')})",
                            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            evidence_redacted=f"{pkg}=={version}",
                            recommendation="Upgrade to a patched version (check osv.dev)",
                            standard_mapping=[v.get("id", "")],
                            scanner="osv-api",
                            discovered_at=datetime.now(timezone.utc), status=Status.OPEN,
                        )
                        f.fingerprint = f.compute_fingerprint()
                        findings.append(f)
            except (OSError, ValueError, KeyError) as exc:
                raise ScanIncompleteError("scan incomplete: could not read dependency file") from exc
        return findings

    def _parse_requirements(self, text: str) -> list[tuple[str, str]]:
        results = []
        for line in text.splitlines():
            m = _PYPI_PIN.match(line.strip())
            if m and all(len(part) <= 255 for part in m.groups()) and _PYPI_VERSION.fullmatch(m.group(2)):
                results.append((m.group(1), m.group(2)))
        return list(dict.fromkeys(results))

    def _parse_package_lock(self, text: str) -> list[tuple[str, str]]:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("package-lock.json must contain an object")
        packages = []

        def add(name, info):
            name = info.get("name") or name
            version = info.get("version", "")
            if info.get("link") or not isinstance(version, str):
                return
            if version.startswith("npm:"):  # npm aliases in lockfile v1
                name, _, version = version[4:].rpartition("@")
            resolved = info.get("resolved")
            if resolved:
                if not isinstance(resolved, str):
                    return
                try:
                    url = urlsplit(resolved)
                except ValueError:
                    return
                if (url.scheme != "https" or url.netloc != "registry.npmjs.org" or not url.path
                        or url.query or url.fragment):
                    return
            if (isinstance(name, str) and len(name) <= 214 and _NPM_NAME.fullmatch(name)
                    and len(version) <= 256 and _NPM_VERSION.fullmatch(version)):
                packages.append((name, version))

        if "packages" in data:  # lockfile v2/v3
            if not isinstance(data["packages"], dict):
                raise ValueError("package-lock packages must contain an object")
            for path, info in data["packages"].items():
                if "node_modules/" in path and isinstance(info, dict):
                    add(path.rsplit("node_modules/", 1)[-1], info)
        else:  # lockfile v1
            def visit(dependencies):
                if not isinstance(dependencies, dict):
                    raise ValueError("package-lock dependencies must contain an object")
                for name, info in dependencies.items():
                    if isinstance(info, dict):
                        add(name, info)
                        visit(info.get("dependencies", {}))
            visit(data.get("dependencies", {}))
        return list(dict.fromkeys(packages))

    def _query_osv_api_batch(self, packages: list[tuple[str, str]], ecosystem: str = "PyPI") -> dict[tuple[str, str], list[dict]]:
        """Use OSV batch endpoint to query all packages in one request."""
        if not packages:
            return {}
        queries = [
            {"version": version, "package": {"name": pkg, "ecosystem": ecosystem}}
            for pkg, version in packages
        ]
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
                timeout=15,
                allow_redirects=False,
            )
            if 300 <= resp.status_code < 400:
                raise ValueError("OSV API redirect rejected")
            resp.raise_for_status()
            results = result_records(resp.json(), "results")
            if len(results) != len(packages):
                raise ValueError("OSV batch result count does not match query count")
            for result in results:
                if result.get("error"):
                    raise ValueError("OSV batch returned an error")
                result_records(result, "vulns", optional=True)
        except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ScanIncompleteError("scan incomplete: OSV API request or response failed") from exc
        return {
            packages[i]: result.get("vulns", [])
            for i, result in enumerate(results)
        }
