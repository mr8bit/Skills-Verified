from pathlib import Path

from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.core.models import Category, Severity
from skills_verified.platforms.base import SkillMetadata


def test_is_available():
    analyzer = PrivilegeAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "privilege"


def test_finds_undeclared_shell(tmp_path):
    """Code uses subprocess but metadata only declares ['filesystem']."""
    code = tmp_path / "main.py"
    code.write_text(
        "import subprocess\n"
        "import socket\n"
        "\n"
        "subprocess.run(['ls', '-la'])\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    )

    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=["filesystem"],
        entry_points=[],
        platform="claude_code",
    )

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[metadata])

    undeclared_findings = [f for f in findings if "undeclared" in f.title.lower()]
    assert len(undeclared_findings) >= 1
    assert undeclared_findings[0].category == Category.PERMISSIONS

    # Should flag shell and/or network as undeclared
    undeclared_perms = {f.title.split(": ")[-1] for f in undeclared_findings}
    assert "shell" in undeclared_perms or "network" in undeclared_perms


def test_no_findings_without_metadata(tmp_path):
    """Returns empty when no platforms are provided."""
    code = tmp_path / "main.py"
    code.write_text("import subprocess\nsubprocess.run(['ls'])\n")

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[])
    assert findings == []


def test_no_findings_without_declarations(tmp_path):
    """Returns empty when permissions_declared is empty (cannot compare)."""
    code = tmp_path / "main.py"
    code.write_text("import subprocess\nsubprocess.run(['ls'])\n")

    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=[],
        entry_points=[],
        platform="claude_code",
    )

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[metadata])
    assert findings == []
