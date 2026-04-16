import sys
from pathlib import Path

import click
from rich.console import Console

from skills_verified.core.models import Grade
from skills_verified.output.badge import save_badge
from skills_verified.output.codeclimate import save_codeclimate
from skills_verified.output.github_annotations import print_annotations
from skills_verified.output.markdown_report import save_markdown
from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.config_injection_analyzer import ConfigInjectionAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.analyzers.mcp_analyzer import MCPAnalyzer
from skills_verified.analyzers.metadata_analyzer import MetadataAnalyzer
from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.pipeline import Pipeline
from skills_verified.output.console import render_report
from skills_verified.output.json_report import save_json_report
from skills_verified.repo.fetcher import fetch_repo, is_git_url

console = Console()

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def check_threshold(
    score: int,
    grade: Grade,
    threshold: int | None,
    threshold_grade: str | None,
) -> bool:
    if threshold is None and threshold_grade is None:
        return True
    if threshold is not None and score < threshold:
        return False
    if threshold_grade is not None and GRADE_ORDER[grade.value] > GRADE_ORDER[threshold_grade]:
        return False
    return True


@click.command("skills-verified")
@click.argument("source")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file")
@click.option("--skip", type=str, default=None, help="Comma-separated analyzer names to skip")
@click.option("--only", type=str, default=None, help="Comma-separated analyzer names to run exclusively")
@click.option("--llm-url", type=str, default=None, envvar="SV_LLM_URL", help="OpenAI-compatible API base URL")
@click.option("--llm-model", type=str, default=None, envvar="SV_LLM_MODEL", help="LLM model name")
@click.option("--llm-key", type=str, default=None, envvar="SV_LLM_KEY", help="LLM API key")
@click.option("--threshold", type=click.IntRange(0, 100), default=None, help="Minimum trust score (0-100); exit 1 if below")
@click.option("--threshold-grade", type=click.Choice(["A", "B", "C", "D", "F"], case_sensitive=False), default=None, help="Minimum grade; exit 1 if worse")
@click.option("--format", "formats", type=click.Choice(["json", "codeclimate", "badge", "github", "markdown"], case_sensitive=False), multiple=True, help="Output formats (repeatable)")
@click.option("--output-dir", type=click.Path(file_okay=False), default=".", help="Directory for format artifacts")
@click.option("--markdown-style", type=click.Choice(["full", "summary"], case_sensitive=False), default="full", help="Markdown report detail level")
def main(
    source: str,
    output: str | None,
    skip: str | None,
    only: str | None,
    llm_url: str | None,
    llm_model: str | None,
    llm_key: str | None,
    threshold: int | None,
    threshold_grade: str | None,
    formats: tuple[str, ...],
    output_dir: str,
    markdown_style: str,
) -> None:
    """Skills Verified — AI Agent Trust Scanner.

    Analyze a repository for vulnerabilities and compute a Trust Score.

    SOURCE can be a GitHub URL or a local path.
    """
    llm_config = None
    if llm_url and llm_model and llm_key:
        llm_config = LlmConfig(url=llm_url, model=llm_model, key=llm_key)

    all_analyzers = [
        PatternAnalyzer(),
        CveAnalyzer(),
        BanditAnalyzer(),
        SemgrepAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
        LlmAnalyzer(config=llm_config),
        ObfuscationAnalyzer(),
        ReverseShellAnalyzer(),
        ExfiltrationAnalyzer(),
        BehavioralAnalyzer(),
        MCPAnalyzer(),
        ConfigInjectionAnalyzer(),
        MetadataAnalyzer(),
        KnownThreatsAnalyzer(),
        PrivilegeAnalyzer(),
    ]

    skip_set = set(skip.split(",")) if skip else set()
    only_set = set(only.split(",")) if only else None

    analyzers = []
    for a in all_analyzers:
        if a.name in skip_set:
            continue
        if only_set is not None and a.name not in only_set:
            continue
        analyzers.append(a)

    try:
        repo_path = fetch_repo(source)
    except (ValueError, Exception) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(2)

    pipeline = Pipeline(analyzers=analyzers)
    report = pipeline.run(
        repo_path=repo_path,
        repo_url=source,
        llm_used=llm_config is not None,
    )

    render_report(report, console=console)

    if output:
        save_json_report(report, Path(output))
        console.print(f"  [dim]JSON report saved to {output}[/dim]\n")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if "json" in formats and not output:
        save_json_report(report, out / "report.json")

    if "codeclimate" in formats:
        save_codeclimate(report.findings, out / "gl-code-quality-report.json")

    if "badge" in formats:
        save_badge(score=report.overall_score, grade=report.overall_grade, path=out / "badge.json")

    if "github" in formats:
        print_annotations(report.findings)

    if "markdown" in formats:
        save_markdown(report, style=markdown_style, path=out / "report.md")

    passed = check_threshold(
        score=report.overall_score,
        grade=report.overall_grade,
        threshold=threshold,
        threshold_grade=threshold_grade,
    )
    if not passed:
        console.print(f"  [red bold]THRESHOLD FAILED:[/red bold] score={report.overall_score}, grade={report.overall_grade.value}")
        if threshold is not None:
            console.print(f"    Required score >= {threshold}")
        if threshold_grade is not None:
            console.print(f"    Required grade >= {threshold_grade}")
        console.print()
        sys.exit(1)
