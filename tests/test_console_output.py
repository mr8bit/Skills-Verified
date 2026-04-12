from io import StringIO

from rich.console import Console

from skills_verified.core.models import (
    Category, CategoryScore, Finding, Grade, Report, Severity,
)
from skills_verified.output.console import render_report


def _make_report(grade: Grade = Grade.B, score: int = 82) -> Report:
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=score,
        overall_grade=grade,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 95, Grade.A, 2, 0, 1),
            CategoryScore(Category.CVE, 100, Grade.A, 0, 0, 0),
            CategoryScore(Category.GUARDRAILS, 85, Grade.B, 3, 0, 0),
            CategoryScore(Category.PERMISSIONS, 68, Grade.C, 7, 0, 2),
            CategoryScore(Category.SUPPLY_CHAIN, 92, Grade.A, 1, 0, 0),
        ],
        findings=[
            Finding(
                title="Unsafe eval() call",
                description="eval() usage detected",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="danger.py",
                line_number=5,
                analyzer="pattern",
            ),
        ],
        analyzers_used=["pattern", "guardrails", "permissions"],
        llm_used=False,
        scan_duration_seconds=3.5,
    )


def test_render_report_contains_grade():
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    report = _make_report()
    render_report(report, console=console)
    output = buf.getvalue()
    assert "B" in output


def test_render_report_contains_score():
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    report = _make_report()
    render_report(report, console=console)
    output = buf.getvalue()
    assert "82" in output


def test_render_report_contains_finding():
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    report = _make_report()
    render_report(report, console=console)
    output = buf.getvalue()
    assert "eval" in output.lower()


def test_render_report_contains_repo_url():
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    report = _make_report()
    render_report(report, console=console)
    output = buf.getvalue()
    assert "test/repo" in output
