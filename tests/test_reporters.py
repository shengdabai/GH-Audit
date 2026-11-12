import json
from datetime import datetime
from io import StringIO

from rich.console import Console

from gh_audit.models import Category, Confidence, Finding, Severity, Status
from gh_audit.reporters import terminal
from gh_audit.reporters.json_report import JsonReporter
from gh_audit.reporters.html_report import HtmlReporter

def _finding():
    f = Finding(
        finding_id="abc", fingerprint="fp1",
        repo="org/repo", branch="main", commit_sha="abc123",
        file_path="app/config.py", line_start=10, line_end=10,
        category=Category.SECRETS, rule_id="aws-key",
        title="AWS Key", severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_redacted="AKIA****EXAMPLE",
        recommendation="Rotate key",
        standard_mapping=["CWE-798"],
        scanner="builtin",
        discovered_at=datetime(2026, 4, 21),
        status=Status.OPEN,
    )
    return f

def test_json_reporter_produces_valid_json(tmp_path):
    out = tmp_path / "report.json"
    JsonReporter().write([_finding()], str(out), repo="org/repo")
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["severity"] == "critical"

def test_html_reporter_produces_html_file(tmp_path):
    out = tmp_path / "report.html"
    HtmlReporter().write([_finding()], str(out), repo="org/repo")
    content = out.read_text()
    assert "<!DOCTYPE html>" in content
    assert "AWS Key" in content
    assert "AKIAIOSFODNN7EXAMPLE" not in content


def test_html_reporter_escapes_xss(tmp_path):
    from datetime import datetime
    from gh_audit.models import Category, Confidence, Finding, Severity, Status
    f = Finding(
        finding_id="xss", fingerprint="xss",
        repo="org/repo", branch="main", commit_sha="abc",
        file_path='<script>alert(1)</script>.py',
        line_start='</code><svg onload=alert(2)>', line_end=1,
        category=Category.SECRETS, rule_id="xss-test",
        title='<img src=x onerror=alert(1)>',
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        evidence_redacted='<b>not bold</b>',
        recommendation='<script>evil()</script>',
        standard_mapping=[], scanner="builtin",
        discovered_at=datetime(2026, 4, 21), status=Status.OPEN,
    )
    out = tmp_path / "report.html"
    from gh_audit.reporters.html_report import HtmlReporter
    HtmlReporter().write([f], str(out), repo='org/</title><iframe src=fixture>')
    content = out.read_text()
    assert "<script>" not in content
    assert "<img src=x" not in content
    assert "<svg onload" not in content
    assert "<iframe src" not in content
    assert "&lt;/code&gt;&lt;svg onload=alert(2)&gt;" in content
    assert "&lt;script&gt;" in content or "&lt;img" in content


def test_terminal_reports_fields_as_literal_text_without_active_controls(monkeypatch):
    finding = _finding()
    finding.title = "[/unopened] [green]"
    finding.file_path = "[bold]app.py"
    finding.line_start = "\rnext"
    finding.evidence_redacted = "\x1b[2J\x07"
    finding.recommendation = "Review 中文 \x9b2J\tend"
    output = StringIO()
    monkeypatch.setattr(terminal, "console", Console(file=output, width=190, color_system=None))

    terminal.TerminalReporter().print([finding], "org/[red]repo[/red]")

    report = output.getvalue()
    for literal in ("org/[red]repo[/red]", "[/unopened] [green]", "[bold]app.py",
                    r"\rnext", r"\x1b[2J\x07", r"Review 中文 \x9b2J\tend"):
        assert literal in report
    for control in ("\r", "\x1b", "\x07", "\x9b", "\t"):
        assert control not in report
