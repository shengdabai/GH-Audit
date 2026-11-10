import json
import re
import subprocess
import uuid
from datetime import datetime, timezone

import requests
from rich.console import Console

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.scanners.base import BaseScanner, ScanConfig, iter_repo_files

console = Console()


class ScaScanner(BaseScanner):
    name = "sca"

    def scan(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        if self._external_tool_available("osv-scanner"):
            return self._run_osv_scanner(repo_path, config)
        return self._osv_api_fallback(repo_path, config)

    def _run_osv_scanner(self, repo_path: str, config: ScanConfig) -> list[Finding]:
        try:
            result = subprocess.run(
                ["osv-scanner", "--format=json", repo_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode not in (0, 1):
                console.print(f"[yellow][sca] osv-scanner exited {result.returncode}: {result.stderr[:200]}[/yellow]")
                return []
            data = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            console.print("[yellow][sca] osv-scanner timed out after 120s[/yellow]")
            return []
        except json.JSONDecodeError as e:
            console.print(f"[yellow][sca] osv-scanner returned invalid JSON: {e}[/yellow]")
            return []
        findings = []
        for r in data.get("results", []):
            for pkg in r.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
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
                text = lock.read_text(encoding="utf-8", errors="ignore")
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
            except (OSError, ValueError, KeyError) as e:
                console.print(f"[yellow][sca] error scanning {lock}: {e}[/yellow]")
                continue
        return findings

    def _parse_requirements(self, text: str) -> list[tuple[str, str]]:
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
            if m:
                results.append((m.group(1), m.group(2)))
        return results

    def _parse_package_lock(self, text: str) -> list[tuple[str, str]]:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("package-lock.json must contain an object")
        packages = []

        def add(name, info):
            name = info.get("name") or name
            version = info.get("version", "")
            # Local paths and Git URLs are not registry versions.
            if isinstance(name, str) and isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?", version):
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
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except (requests.RequestException, ValueError, KeyError) as e:
            console.print(f"[yellow][sca] OSV API error: {e}[/yellow]")
            return {}
        return {
            packages[i]: result.get("vulns", [])
            for i, result in enumerate(results)
            if i < len(packages)
        }
