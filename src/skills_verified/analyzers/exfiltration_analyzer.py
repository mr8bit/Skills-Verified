import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh"}

BUILTIN_PATTERNS = [
    {
        "title": "DNS exfiltration via f-string subdomain",
        "pattern": re.compile(r"""f["'].*\{.*\}.*\.\w{2,6}["']"""),
        "severity": Severity.HIGH,
        "description": "Data embedded into a DNS-style domain string via f-string, suggesting DNS exfiltration.",
    },
    {
        "title": "Environment variable bulk harvesting (Python)",
        "pattern": re.compile(r"os\.environ\.copy\s*\(\)|dict\s*\(\s*os\.environ\s*\)"),
        "severity": Severity.MEDIUM,
        "description": "Bulk copy of environment variables, often the first step in credential exfiltration.",
    },
    {
        "title": "Environment variable bulk harvesting (Node.js)",
        "pattern": re.compile(r"Object\.keys\s*\(\s*process\.env\s*\)"),
        "severity": Severity.MEDIUM,
        "description": "Bulk access to process.env in Node.js, collecting all environment variables.",
    },
    {
        "title": "Credential file read",
        "pattern": re.compile(
            r"open\s*\(.*\.(ssh|aws|npmrc|gitconfig|env)"
        ),
        "severity": Severity.HIGH,
        "description": "Reading well-known credential files such as SSH keys, AWS credentials, or git configuration.",
    },
    {
        "title": "curl/wget with data upload",
        "pattern": re.compile(r"curl\s+.*-d\s+@|wget\s+.*--post-file"),
        "severity": Severity.HIGH,
        "description": "curl or wget used to upload file content to a remote server.",
    },
]


class ExfiltrationAnalyzer(Analyzer):
    name = "exfiltration"

    def __init__(self) -> None:
        self._yaml_patterns: list[dict] = []
        loader = SignatureLoader()
        sigs = loader.load_signatures("exfiltration_patterns.yaml")
        for sig in sigs:
            try:
                compiled = re.compile(sig["pattern"])
                self._yaml_patterns.append(
                    {
                        "id": sig["id"],
                        "title": sig.get("title", sig["id"]),
                        "pattern": compiled,
                        "severity": getattr(Severity, sig["severity"]),
                        "description": sig.get("description", ""),
                    }
                )
            except re.error:
                logger.warning(
                    "Failed to compile exfiltration signature %s: %s",
                    sig.get("id", "?"),
                    sig["pattern"],
                )

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SCAN_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(file_path.relative_to(repo_path))
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in BUILTIN_PATTERNS:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.EXFILTRATION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
                for pat in self._yaml_patterns:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.EXFILTRATION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
        return findings
