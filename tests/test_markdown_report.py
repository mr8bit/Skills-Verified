from pathlib import Path

from skills_verified.core.models import (
    Category,
    CategoryScore,
    Finding,
    Grade,
    Report,
    Severity,
)
from skills_verified.output.markdown_report import generate_markdown, save_markdown


def _make_report() -> Report:
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=82,
        overall_grade=Grade.B,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 75, Grade.B, 3, 0, 1),
            CategoryScore(Category.CVE, 90, Grade.A, 1, 0, 0),
        ],
        findings=[
            Finding(
                title="Dangerous eval usage",
                description="eval() with untrusted input",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="src/main.py",
                line_number=42,
                analyzer="pattern_analyzer",
                confidence=0.95,
            ),
        ],
        analyzers_used=["pattern_analyzer", "cve_analyzer"],
        llm_used=False,
        scan_duration_seconds=1.5,
    )


def _make_empty_report() -> Report:
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=100,
        overall_grade=Grade.A,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 100, Grade.A, 0, 0, 0),
        ],
        findings=[],
        analyzers_used=["pattern_analyzer"],
        llm_used=False,
        scan_duration_seconds=0.5,
    )


def _make_report_no_file() -> Report:
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=70,
        overall_grade=Grade.C,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 70, Grade.C, 1, 0, 1),
        ],
        findings=[
            Finding(
                title="Suspicious pattern",
                description="Suspicious behavior detected",
                severity=Severity.MEDIUM,
                category=Category.CODE_SAFETY,
                file_path=None,
                line_number=None,
                analyzer="behavioral_analyzer",
                confidence=0.8,
            ),
        ],
        analyzers_used=["behavioral_analyzer"],
        llm_used=False,
        scan_duration_seconds=2.0,
    )


# --- Full style tests ---

def test_full_contains_header():
    md = generate_markdown(_make_report(), style="full")
    assert "## Skills Verified" in md
    assert "B (82/100)" in md


def test_full_contains_summary_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Severity | Count |" in md
    assert "| HIGH" in md


def test_full_contains_categories_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Category | Grade | Score |" in md
    assert "Code Safety" in md


def test_full_contains_findings_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Severity | Title | File | Confidence |" in md
    assert "Dangerous eval usage" in md
    assert "`src/main.py:42`" in md
    assert "0.95" in md


# --- Summary style tests ---

def test_summary_has_no_findings_table():
    md = generate_markdown(_make_report(), style="summary")
    assert "| Severity | Title | File | Confidence |" not in md
    assert "1 findings found" in md


def test_summary_has_header_and_categories():
    md = generate_markdown(_make_report(), style="summary")
    assert "## Skills Verified" in md
    assert "| Category | Grade | Score |" in md


# --- Edge case tests ---

def test_no_findings():
    md = generate_markdown(_make_empty_report(), style="full")
    assert "| Severity | Title | File | Confidence |" not in md
    assert "A (100/100)" in md


def test_finding_without_file():
    md = generate_markdown(_make_report_no_file(), style="full")
    assert "N/A" in md


def test_repo_url_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "test/repo" in md


def test_scan_duration_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "1.5s" in md


def test_analyzers_count_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "2" in md


def test_save_markdown(tmp_path: Path):
    report = _make_report()
    out_path = tmp_path / "report.md"
    save_markdown(report, "full", out_path)
    assert out_path.exists()
    content = out_path.read_text()
    assert "## Skills Verified" in content
