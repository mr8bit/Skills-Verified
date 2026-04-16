from pathlib import Path

from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = ExfiltrationAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "exfiltration"


def test_finds_dns_exfil(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    dns_findings = [f for f in findings if "dns" in f.title.lower()]
    assert len(dns_findings) >= 1
    assert dns_findings[0].category == Category.EXFILTRATION


def test_finds_env_harvest(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    env_findings = [f for f in findings if "environ" in f.title.lower() or "harvest" in f.title.lower()]
    assert len(env_findings) >= 1
    assert env_findings[0].category == Category.EXFILTRATION


def test_finds_http_exfil(fake_repo_path):
    """The exfiltration.py fixture contains requests.post with env data;
    the analyzer should flag the curl/wget pattern or the credential file read
    that accompanies the HTTP upload."""
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    http_findings = [
        f for f in findings
        if "curl" in f.title.lower()
        or "wget" in f.title.lower()
        or "upload" in f.title.lower()
    ]
    assert len(http_findings) >= 1
    assert http_findings[0].category == Category.EXFILTRATION


def test_finds_credential_read(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    cred_findings = [f for f in findings if "credential" in f.title.lower()]
    assert len(cred_findings) >= 1
    assert cred_findings[0].category == Category.EXFILTRATION


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []
