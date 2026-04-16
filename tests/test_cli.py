import json

from click.testing import CliRunner

from skills_verified.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "skills-verified" in result.output.lower() or "usage" in result.output.lower()


def test_cli_with_local_path(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path)])
    assert result.exit_code == 0
    assert "TRUST SCORE" in result.output


def test_cli_with_json_output(fake_repo_path, tmp_path):
    out_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()


def test_cli_with_skip(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--skip", "bandit,semgrep"])
    assert result.exit_code == 0


def test_cli_with_only(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails"])
    assert result.exit_code == 0


def test_cli_nonexistent_path():
    runner = CliRunner()
    result = runner.invoke(main, ["/nonexistent/path/xyz123"])
    assert result.exit_code == 2


def test_cli_threshold_pass(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--threshold", "0"])
    assert result.exit_code == 0


def test_cli_threshold_fail(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--threshold", "100"])
    assert result.exit_code == 1


def test_cli_threshold_grade_pass(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--threshold-grade", "F"])
    assert result.exit_code == 0


def test_cli_format_badge(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--format", "badge", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    badge_path = tmp_path / "badge.json"
    assert badge_path.exists()
    data = json.loads(badge_path.read_text())
    assert data["schemaVersion"] == 1


def test_cli_format_markdown(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--format", "markdown", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    md_path = tmp_path / "report.md"
    assert md_path.exists()
    assert "## Skills Verified" in md_path.read_text()


def test_cli_format_codeclimate(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--format", "codeclimate", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    cc_path = tmp_path / "gl-code-quality-report.json"
    assert cc_path.exists()
    data = json.loads(cc_path.read_text())
    assert isinstance(data, list)


def test_cli_markdown_style_summary(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails", "--format", "markdown", "--output-dir", str(tmp_path), "--markdown-style", "summary"])
    assert result.exit_code == 0
    content = (tmp_path / "report.md").read_text()
    assert "| Severity | Title | File | Confidence |" not in content


def test_cli_error_exit_code():
    runner = CliRunner()
    result = runner.invoke(main, ["/nonexistent/path/xyz123"])
    assert result.exit_code == 2
