import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from gh_audit.config import Config
from gh_audit.discovery import cleanup_repo, clone_repo, checkout_sha, get_repo_info, list_org_repos
from gh_audit.models import Severity
from gh_audit.normalizer import deduplicate, diff_findings, load_previous_content_fingerprints, load_suppressions
from gh_audit.reporters.html_report import HtmlReporter
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.terminal import TerminalReporter
from gh_audit.scanners.base import ScanConfig, ScanIncompleteError
from gh_audit.scanners.governance import GovernanceScanner
from gh_audit.scanners.iac import IacScanner
from gh_audit.scanners.pii import PiiScanner
from gh_audit.scanners.sast import SastScanner
from gh_audit.scanners.sca import ScaScanner
from gh_audit.scanners.secrets import SecretsScanner

console = Console()

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_KNOWN_MODULES = {"secrets", "pii", "sast", "sca", "iac", "governance"}

_ALL_SCANNERS = {
    "secrets": SecretsScanner,
    "pii": PiiScanner,
    "sast": SastScanner,
    "sca": ScaScanner,
    "iac": IacScanner,
}


@click.group()
def cli():
    """GitHub repository security audit tool."""


@cli.command()
@click.argument("repo", required=False)
@click.option("--org", help="Scan all repos in this GitHub org")
@click.option("--branch", default=None)
@click.option("--modules", default=None, help="Comma-separated: secrets,pii,sast,sca,iac,governance")
@click.option("--output", default="terminal", help="Comma-separated: terminal,json,html")
@click.option("--min-severity", default="low",
              type=click.Choice(["info", "low", "medium", "high", "critical"]))
@click.option("--diff", is_flag=True, help="Only report new findings vs last scan")
def scan(repo, org, branch, modules, output, min_severity, diff):
    """Scan a repo or org for security issues."""
    cfg = Config.load()
    output_formats = [o.strip() for o in output.split(",")]
    enabled_modules = [m.strip() for m in modules.split(",")] if modules else cfg.modules

    unknown = [m for m in enabled_modules if m not in _KNOWN_MODULES]
    if unknown:
        raise click.BadParameter(
            f"Unknown modules: {', '.join(unknown)}. Valid: {', '.join(sorted(_KNOWN_MODULES))}",
            param_hint="--modules",
        )

    try:
        if org:
            console.print(f"[bold]Discovering repos in org:[/bold] {org}")
            repos = list_org_repos(org, cfg.token)
        elif repo:
            repos = [get_repo_info(repo, cfg.token)]
        else:
            raise click.UsageError("Provide REPO or --org")
    except click.UsageError:
        raise
    except Exception as e:
        console.print(f"[red]✗ Failed to discover repos: {e}[/red]")
        raise SystemExit(1)

    min_sev_idx = _SEVERITY_ORDER.index(min_severity)
    failed = False

    for repo_info in repos:
        console.print(f"\n[bold cyan]Scanning:[/bold cyan] {repo_info.full_name}")
        scan_cfg = ScanConfig(
            repo=repo_info.full_name,
            branch=branch or repo_info.default_branch,
            commit_sha=repo_info.head_sha,
            is_public=repo_info.is_public,
            history_depth=cfg.history_depth,
        )

        all_findings = []
        repo_path = None
        try:
            repo_path = clone_repo(repo_info, cfg.token, branch=scan_cfg.branch)
            scan_cfg.commit_sha = checkout_sha(repo_path)
            for mod_name in enabled_modules:
                if mod_name == "governance":
                    scanner = GovernanceScanner(token=cfg.token)
                elif mod_name in _ALL_SCANNERS:
                    scanner = _ALL_SCANNERS[mod_name]()
                else:
                    console.print(f"[yellow]Unknown module: {mod_name}[/yellow]")
                    continue
                # A module that cannot finish is reported per module; the other
                # modules' findings are kept and the command still exits 1.
                try:
                    if not scanner.is_available():
                        raise ScanIncompleteError(f"{mod_name} tool not found")
                    findings = scanner.scan(repo_path, scan_cfg)
                except ScanIncompleteError as e:
                    failed = True
                    console.print(f"  [red][INCOMPLETE][/red] {mod_name}: {e}")
                    continue
                all_findings.extend(findings)
                console.print(f"  [green]✓[/green] {mod_name}: {len(findings)} findings")
        except RuntimeError as e:
            failed = True
            console.print(f"[red][INCOMPLETE] {repo_info.full_name}: {e}[/red]")
            continue
        finally:
            if repo_path:
                cleanup_repo(repo_path)

        all_findings = deduplicate(all_findings)

        if diff:
            prev_fps = load_previous_content_fingerprints(cfg.results_dir, repo_info.full_name)
            all_findings = diff_findings(all_findings, prev_fps)
            console.print(f"  [dim]--diff: {len(all_findings)} new findings vs last scan[/dim]")

        filtered = [f for f in all_findings
                    if _SEVERITY_ORDER.index(f.severity.value) >= min_sev_idx]

        # Apply suppressions
        suppressed = load_suppressions()
        filtered = [f for f in filtered
                    if f.compute_content_fingerprint() not in suppressed]

        _write_reports(filtered, repo_info.full_name, output_formats, cfg)

    if failed:
        raise SystemExit(1)


def _write_reports(findings, repo_name, output_formats, cfg):
    safe_name = repo_name.replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_dir = cfg.results_dir / safe_name
    results_dir.mkdir(parents=True, exist_ok=True)

    if "terminal" in output_formats:
        TerminalReporter().print(findings, repo_name)
    if "json" in output_formats:
        out = results_dir / f"{ts}.json"
        JsonReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]JSON → {out}[/dim]")
    if "html" in output_formats:
        out = results_dir / f"{ts}.html"
        HtmlReporter().write(findings, str(out), repo=repo_name)
        console.print(f"[dim]HTML → {out}[/dim]")


@cli.command()
def doctor():
    """Check tool availability and token status."""
    from github import Github  # noqa: PLC0415 — lazy import to avoid slow startup
    cfg = Config.load()
    console.print("\n[bold]gh-audit doctor[/bold]\n")
    if cfg.token:
        try:
            gh = Github(cfg.token)
            rate = gh.get_rate_limit().core
            console.print(f"[green]✓[/green] GitHub token   valid (rate limit: {rate.remaining}/{rate.limit})")
        except Exception as e:
            console.print(f"[red]✗[/red] GitHub token   invalid: {e}")
    else:
        console.print("[yellow]![/yellow] GitHub token   not set (export GITHUB_TOKEN=...)")

    checks = [
        ("secrets",    ["gitleaks", "trufflehog"]),
        ("pii",        []),
        ("sast",       ["semgrep", "bandit"]),
        ("sca",        ["osv-scanner"]),
        ("iac",        ["trivy", "checkov"]),
        ("governance", []),
    ]
    for mod, tools in checks:
        found = [t for t in tools if shutil.which(t)]
        if mod in ("governance", "pii"):
            console.print(f"[green]✓[/green] {mod:<14} builtin (always available)")
        elif found:
            console.print(f"[green]✓[/green] {mod:<14} {', '.join(found)}")
        else:
            hint = f"pip install {tools[0]}" if tools else ""
            console.print(f"[dim]○[/dim] {mod:<14} builtin only  ({hint})")


@cli.command()
@click.argument("repo")
def history(repo):
    """Show past scan results for a repo."""
    cfg = Config.load()
    results_dir = cfg.results_dir / repo.replace("/", "_")
    if not results_dir.exists():
        console.print(f"[yellow]No scan history found for {repo}[/yellow]")
        return
    for f in sorted(results_dir.glob("*.json"), reverse=True)[:10]:
        data = json.loads(f.read_text())
        s = data.get("summary", {})
        console.print(
            f"[dim]{f.stem}[/dim]  "
            f"[red]{s.get('critical',0)}c[/red] "
            f"[orange1]{s.get('high',0)}h[/orange1] "
            f"[yellow]{s.get('medium',0)}m[/yellow] "
            f"[green]{s.get('low',0)}l[/green]"
        )


@cli.command()
@click.argument("fingerprint")
@click.option("--reason", required=True)
@click.option("--expires", default="30d", help="e.g. 30d, 90d")
def suppress(fingerprint, reason, expires):
    """Suppress a finding by its content fingerprint (shown in JSON report)."""
    suppress_file = Path.home() / ".gh-audit" / "suppressions.json"
    data = json.loads(suppress_file.read_text()) if suppress_file.exists() else {}
    data[fingerprint] = {"reason": reason, "expires": expires, "created_at": datetime.now(timezone.utc).isoformat()}
    suppress_file.parent.mkdir(parents=True, exist_ok=True)
    suppress_file.write_text(json.dumps(data, indent=2))
    console.print(f"[green]✓[/green] Fingerprint {fingerprint[:16]}... suppressed ({expires}): {reason}")


@cli.group()
def config():
    """Manage gh-audit configuration."""


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value."""
    cfg = Config.load()
    if key == "token":
        console.print("[yellow]⚠ Storing token in config file. Prefer: export GITHUB_TOKEN=...[/yellow]")
    cfg.set(key, value)
    console.print(f"[green]✓[/green] Set {key}={'***' if key == 'token' else value}")
