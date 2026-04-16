import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh", ".ps1"}

BUILTIN_PATTERNS = [
    {
        "title": "Hex escape sequence chain",
        "pattern": re.compile(r"(\\x[0-9a-fA-F]{2}){4,}"),
        "severity": Severity.HIGH,
        "description": "4+ consecutive hex escape sequences used to obfuscate payloads.",
    },
    {
        "title": "String.fromCharCode obfuscation",
        "pattern": re.compile(
            r"String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){3,}\)"
        ),
        "severity": Severity.HIGH,
        "description": "String.fromCharCode called with 4+ arguments to reconstruct obfuscated strings.",
    },
    {
        "title": "Python chr() concatenation chain",
        "pattern": re.compile(
            r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)"
        ),
        "severity": Severity.HIGH,
        "description": "3+ chr() calls concatenated to build obfuscated strings.",
    },
    {
        "title": "Base64 decode with exec/eval",
        "pattern": re.compile(
            r"(exec|eval)\s*\(.*b(ase)?64.*(decode|b64decode)"
        ),
        "severity": Severity.CRITICAL,
        "description": "Base64-decoded content passed to exec() or eval(), a classic obfuscation-to-execution pattern.",
    },
    {
        "title": "eval(atob(...)) pattern",
        "pattern": re.compile(r"eval\s*\(\s*atob\s*\("),
        "severity": Severity.CRITICAL,
        "description": "eval() applied to atob() base64-decoded content, a common JavaScript obfuscation technique.",
    },
    {
        "title": "String concatenation building commands",
        "pattern": re.compile(r"""["'][a-z]{1,4}["']\s*\+\s*["'][a-z]{1,4}["']"""),
        "severity": Severity.MEDIUM,
        "description": "Strings split and concatenated to avoid keyword detection (e.g., 'cu'+'rl').",
    },
    {
        "title": "Nested eval/exec with compile",
        "pattern": re.compile(r"(eval|exec)\s*\(\s*compile\s*\("),
        "severity": Severity.CRITICAL,
        "description": "eval or exec wrapping compile(), enabling multi-stage code execution.",
    },
]


class ObfuscationAnalyzer(Analyzer):
    name = "obfuscation"

    def __init__(self) -> None:
        self._yaml_patterns: list[dict] = []
        loader = SignatureLoader()
        sigs = loader.load_signatures("obfuscation_signatures.yaml")
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
                    "Failed to compile obfuscation signature %s: %s",
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
                                category=Category.OBFUSCATION,
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
                                category=Category.OBFUSCATION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
        return findings
