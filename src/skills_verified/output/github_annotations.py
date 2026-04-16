from skills_verified.core.models import Finding, Severity

_SEVERITY_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "notice",
}


def format_annotations(findings: list[Finding]) -> list[str]:
    """Return a list of GitHub Actions workflow command strings for the given findings."""
    lines: list[str] = []
    for finding in findings:
        level = _SEVERITY_LEVEL[finding.severity]

        params: list[str] = []
        if finding.file_path is not None:
            params.append(f"file={finding.file_path}")
            if finding.line_number is not None:
                params.append(f"line={finding.line_number}")
        params.append(f"title={finding.title}")

        params_str = ",".join(params)
        line = f"::{level} {params_str}::{finding.description}"
        lines.append(line)
    return lines


def print_annotations(findings: list[Finding]) -> None:
    """Print GitHub Actions annotation commands for the given findings to stdout."""
    for line in format_annotations(findings):
        print(line)
