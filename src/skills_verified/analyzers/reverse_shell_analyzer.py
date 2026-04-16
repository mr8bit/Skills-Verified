import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh", ".ps1", ".pl", ".php"}

# Line-level patterns matched per line
BUILTIN_LINE_PATTERNS = [
    {
        "title": "Bash TCP reverse shell",
        "pattern": re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"),
        "severity": Severity.CRITICAL,
        "description": "Bash reverse shell using /dev/tcp to connect back to an attacker-controlled host.",
    },
    {
        "title": "Netcat reverse shell with -e flag",
        "pattern": re.compile(r"\bnc\b.*\s-e\s+/bin/(sh|bash)"),
        "severity": Severity.CRITICAL,
        "description": "Netcat used with -e to pipe a shell to a remote host.",
    },
    {
        "title": "Python pty.spawn shell",
        "pattern": re.compile(r"pty\.spawn\s*\("),
        "severity": Severity.CRITICAL,
        "description": "Python pty.spawn used to spawn an interactive shell, often part of a reverse shell chain.",
    },
    {
        "title": "PowerShell TCPClient reverse shell",
        "pattern": re.compile(r"New-Object\s+System\.Net\.Sockets\.TCPClient"),
        "severity": Severity.CRITICAL,
        "description": "PowerShell TCPClient used to connect to a remote host for shell access.",
    },
    {
        "title": "PowerShell Invoke-Expression with DownloadString",
        "pattern": re.compile(
            r"(IEX|Invoke-Expression).*\.(DownloadString|DownloadData)\s*\(",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": "PowerShell downloading and immediately executing remote code.",
    },
    {
        "title": "Socat reverse shell",
        "pattern": re.compile(r"socat\s+.*exec:", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Socat used to forward a shell to a remote host via TCP.",
    },
]

# File-level patterns matched against the entire file content (multiline awareness)
BUILTIN_FILE_PATTERNS = [
    {
        "title": "Python socket + subprocess reverse shell",
        "pattern": re.compile(
            r"socket\.socket.*subprocess|subprocess.*socket\.socket",
            re.DOTALL,
        ),
        "severity": Severity.CRITICAL,
        "description": "Python socket.socket combined with subprocess to establish a reverse shell.",
    },
]


class ReverseShellAnalyzer(Analyzer):
    name = "reverse_shell"

    def __init__(self) -> None:
        self._yaml_patterns: list[dict] = []
        loader = SignatureLoader()
        sigs = loader.load_signatures("reverse_shell_signatures.yaml")
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
                    "Failed to compile reverse_shell signature %s: %s",
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

            # Line-level scanning (built-in + YAML)
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in BUILTIN_LINE_PATTERNS:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.CODE_SAFETY,
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
                                category=Category.CODE_SAFETY,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )

            # File-level scanning for multiline patterns
            for pat in BUILTIN_FILE_PATTERNS:
                if pat["pattern"].search(content):
                    findings.append(
                        Finding(
                            title=pat["title"],
                            description=pat["description"],
                            severity=pat["severity"],
                            category=Category.CODE_SAFETY,
                            file_path=rel_path,
                            line_number=None,
                            analyzer=self.name,
                        )
                    )
        return findings
