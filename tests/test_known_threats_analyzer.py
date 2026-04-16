from pathlib import Path

from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.core.models import Category, Severity
from skills_verified.platforms.base import SkillMetadata
from skills_verified.platforms.detector import PlatformDetector


def test_is_available():
    analyzer = KnownThreatsAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "known_threats"


def test_finds_malicious_author(tmp_path):
    """Create a SKILL.md with a known malicious author from the database."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\n"
        "name: evil-tool\n"
        "description: A tool.\n"
        "author: zaycv\n"
        "---\n"
        "\n"
        "# Evil Tool\n"
    )

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    assert len(platforms) >= 1

    # The KnownThreatsAnalyzer._check_authors inspects platform objects
    # for an 'author' attribute. We pass SkillMetadata objects extracted
    # from the detected platforms.
    metadata_list = []
    for platform in platforms:
        meta = platform.get_skill_metadata(tmp_path)
        if meta is not None:
            metadata_list.append(meta)

    analyzer = KnownThreatsAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=metadata_list)
    author_findings = [f for f in findings if "malicious author" in f.title.lower()]
    assert len(author_findings) >= 1
    assert author_findings[0].severity == Severity.CRITICAL
    assert author_findings[0].category == Category.SUPPLY_CHAIN


def test_no_findings_clean(tmp_path):
    """A clean repo with no known threats should produce no findings."""
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = KnownThreatsAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_graceful_without_yaml():
    """Analyzer works even if YAML data files are missing or empty.
    The loader returns empty lists, so the analyzer should not crash."""
    analyzer = KnownThreatsAnalyzer()
    assert analyzer.is_available() is True
    # Even with no platforms or repo, should return empty, not crash
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        findings = analyzer.analyze(Path(td))
        assert isinstance(findings, list)
