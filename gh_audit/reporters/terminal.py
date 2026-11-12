import re

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from gh_audit.models import Finding, Severity

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "green",
    "info": "dim",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_DISPLAY_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]")

console = Console()


def _literal(value: str, *, style: str = "") -> Text:
    """Keep report data literal and make terminal controls visible."""
    safe = _DISPLAY_CONTROLS.sub(lambda match: match[0].encode("unicode_escape").decode("ascii"), value)
    return Text(safe, style=style)


class TerminalReporter:
    def print(self, findings: list[Finding], repo: str) -> None:
        console.rule(_literal(f"gh-audit: {repo}", style="bold"))

        if not findings:
            console.print("[green]No findings.[/green]")
            console.rule()
            return

        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Category", width=12)
        table.add_column("Title", width=30)
        table.add_column("Location", width=30)
        table.add_column("Evidence", width=25)
        table.add_column("Recommendation", width=35)

        for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.index(x.severity.value)):
            style = _SEVERITY_STYLE.get(f.severity.value, "")
            table.add_row(
                _literal(f.severity.value.upper(), style=style),
                _literal(f.category.value),
                _literal(f.title),
                _literal(f"{f.file_path}:{f.line_start}"),
                _literal(f.evidence_redacted),
                _literal(f.recommendation),
            )

        console.print(table)
        counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
        console.rule()
        console.print(
            f"[bold red]{counts['critical']} critical[/] · "
            f"[bold orange1]{counts['high']} high[/] · "
            f"[bold yellow]{counts['medium']} medium[/] · "
            f"[green]{counts['low']} low[/] · "
            f"[dim]{counts['info']} info[/]"
        )
