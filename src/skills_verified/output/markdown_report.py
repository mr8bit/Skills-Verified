from pathlib import Path

from skills_verified.core.models import Report, Severity


_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]


def _category_display_name(category_value: str) -> str:
    return category_value.replace("_", " ").title()


def _severity_index(severity: Severity) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


def _build_header(report: Report) -> str:
    grade = report.overall_grade.value
    score = report.overall_score
    return f"## Skills Verified -- Trust Score: {grade} ({score}/100)\n"


def _build_meta(report: Report) -> str:
    duration = report.scan_duration_seconds
    analyzers_count = len(report.analyzers_used)
    lines = [
        f"**Repository:** `{report.repo_url}`",
        f"**Scan duration:** {duration}s | **Analyzers:** {analyzers_count}",
        "",
    ]
    return "\n".join(lines)


def _build_summary_table(report: Report) -> str:
    severity_counts: dict[Severity, int] = {s: 0 for s in _SEVERITY_DISPLAY_ORDER}
    for finding in report.findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1

    lines = [
        "### Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in _SEVERITY_DISPLAY_ORDER:
        count = severity_counts[severity]
        lines.append(f"| {severity.value.upper()} | {count} |")
    lines.append("")
    return "\n".join(lines)


def _build_categories_table(report: Report) -> str:
    lines = [
        "### Categories",
        "",
        "| Category | Grade | Score |",
        "| --- | --- | --- |",
    ]
    for cat_score in report.categories:
        name = _category_display_name(cat_score.category.value)
        grade = cat_score.grade.value
        score = cat_score.score
        lines.append(f"| {name} | {grade} | {score} |")
    lines.append("")
    return "\n".join(lines)


def _build_findings_table(report: Report) -> str:
    sorted_findings = sorted(report.findings, key=lambda f: _severity_index(f.severity))

    lines = [
        "### Findings",
        "",
        "| Severity | Title | File | Confidence |",
        "| --- | --- | --- | --- |",
    ]
    for finding in sorted_findings:
        severity = finding.severity.value.upper()
        title = finding.title
        if finding.file_path is not None:
            if finding.line_number is not None:
                file_col = f"`{finding.file_path}:{finding.line_number}`"
            else:
                file_col = f"`{finding.file_path}`"
        else:
            file_col = "N/A"
        confidence = f"{finding.confidence:.2f}".rstrip("0").rstrip(".")
        # Ensure at least two decimal places representation if needed
        if "." not in confidence:
            confidence = f"{finding.confidence:.2f}"
        else:
            # Use fixed 2 decimal places for consistency
            confidence = f"{finding.confidence:.2f}"
        lines.append(f"| {severity} | {title} | {file_col} | {confidence} |")
    lines.append("")
    return "\n".join(lines)


def generate_markdown(report: Report, style: str = "full") -> str:
    parts: list[str] = []

    parts.append(_build_header(report))
    parts.append(_build_meta(report))
    parts.append(_build_summary_table(report))
    parts.append(_build_categories_table(report))

    if style == "full":
        if report.findings:
            parts.append(_build_findings_table(report))
    else:
        findings_count = len(report.findings)
        parts.append(f"> {findings_count} findings found. Run full scan for details.\n")

    return "\n".join(parts)


def save_markdown(report: Report, style: str, path: Path) -> None:
    content = generate_markdown(report, style=style)
    path.write_text(content, encoding="utf-8")
