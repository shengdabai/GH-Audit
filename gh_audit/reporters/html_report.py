from html import escape
from datetime import datetime, timezone
from gh_audit.models import Finding

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#6b7280",
}


class HtmlReporter:
    def write(self, findings: list[Finding], output_path: str, repo: str) -> None:
        rows = ""
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity.value, "#6b7280")
            location = escape(f"{f.file_path}:{f.line_start}")
            rows += (
                f"<tr>"
                f"<td><span style='color:{color};font-weight:bold'>{escape(f.severity.value.upper())}</span></td>"
                f"<td>{escape(f.category.value)}</td>"
                f"<td>{escape(f.title)}</td>"
                f"<td><code>{location}</code></td>"
                f"<td><code>{escape(f.evidence_redacted)}</code></td>"
                f"<td>{escape(f.recommendation)}</td>"
                f"</tr>"
            )

        summary_counts = {s: sum(1 for f in findings if f.severity.value == s)
                          for s in ("critical", "high", "medium", "low", "info")}
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>gh-audit: {escape(repo)}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #1f2937; }}
    h1 {{ color: #111827; }}
    .summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
    .badge {{ padding: .4rem .8rem; border-radius: .4rem; color: white; font-weight: bold; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #e5e7eb; padding: .5rem .75rem; text-align: left; font-size:.875rem; }}
    th {{ background: #f9fafb; }}
    code {{ background: #f3f4f6; padding: .1rem .3rem; border-radius: .2rem; }}
  </style>
</head>
<body>
  <h1>gh-audit Report: {escape(repo)}</h1>
  <p>Scanned at {ts}</p>
  <div class="summary">
    <span class="badge" style="background:#dc2626">{summary_counts['critical']} Critical</span>
    <span class="badge" style="background:#ea580c">{summary_counts['high']} High</span>
    <span class="badge" style="background:#d97706">{summary_counts['medium']} Medium</span>
    <span class="badge" style="background:#65a30d">{summary_counts['low']} Low</span>
    <span class="badge" style="background:#6b7280">{summary_counts['info']} Info</span>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Evidence</th><th>Recommendation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
