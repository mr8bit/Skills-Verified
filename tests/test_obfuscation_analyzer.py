from pathlib import Path

from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = ObfuscationAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "obfuscation"


def test_finds_hex_escape(fake_repo_path):
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    hex_findings = [f for f in findings if "hex" in f.title.lower()]
    assert len(hex_findings) >= 1
    assert hex_findings[0].category == Category.OBFUSCATION


def test_finds_chr_concat(fake_repo_path):
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    chr_findings = [f for f in findings if "chr()" in f.title.lower()]
    assert len(chr_findings) >= 1
    assert chr_findings[0].category == Category.OBFUSCATION


def test_finds_base64_exec(fake_repo_path):
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    b64_findings = [
        f for f in findings if "base64" in f.title.lower() and "exec" in f.title.lower()
    ]
    assert len(b64_findings) >= 1
    assert b64_findings[0].severity == Severity.CRITICAL
    assert b64_findings[0].category == Category.OBFUSCATION


def test_finds_fromcharcode(fake_repo_path):
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    fcc_findings = [f for f in findings if "fromcharcode" in f.title.lower()]
    assert len(fcc_findings) >= 1
    assert fcc_findings[0].category == Category.OBFUSCATION


def test_finds_nested_eval(fake_repo_path):
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    eval_findings = [
        f for f in findings if "eval" in f.title.lower() and "compile" in f.title.lower()
    ]
    assert len(eval_findings) >= 1
    assert eval_findings[0].severity == Severity.CRITICAL
    assert eval_findings[0].category == Category.OBFUSCATION


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []
