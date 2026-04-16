import ast
import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS_REGEX = {".py", ".js", ".ts"}
SCAN_EXTENSIONS_AST = {".py"}

# --- AST analysis configuration ---

# Source functions/attributes that read sensitive data
SENSITIVE_SOURCES = {
    "os.environ",
    "os.getenv",
    "open",
    "sys.stdin.read",
}

# Sink functions that send data externally or execute commands
DANGEROUS_SINKS = {
    "requests.post",
    "requests.get",
    "urllib.request.urlopen",
    "subprocess.run",
    "subprocess.Popen",
    "socket.send",
}

# --- Regex-based behavioral patterns ---

_DANGEROUS_CALLS = r"(exec|eval|subprocess\.(run|call|Popen)|requests\.(get|post)|urllib)"

REGEX_PATTERNS = [
    {
        "title": "Delayed execution with time.sleep",
        "detect": re.compile(r"time\.sleep\s*\(\s*\d+\s*\)"),
        "context": re.compile(_DANGEROUS_CALLS),
        "severity": Severity.MEDIUM,
        "description": (
            "time.sleep() found in a file that also contains exec/eval/subprocess/requests, "
            "suggesting delayed malicious execution."
        ),
    },
    {
        "title": "Conditional CI environment activation",
        "detect": re.compile(
            r"""os\.getenv\s*\(\s*['"]"""
            r"(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS)"
            r"""['"]\s*\)"""
        ),
        "context": re.compile(_DANGEROUS_CALLS),
        "severity": Severity.HIGH,
        "description": (
            "CI environment variable check found near dangerous execution calls, "
            "suggesting behavior that activates only in CI pipelines."
        ),
    },
    {
        "title": "Conditional platform check with dangerous operation",
        "detect": re.compile(r"platform\.system\s*\(\s*\)"),
        "context": re.compile(r"(exec|eval|subprocess\.(run|call|Popen))"),
        "severity": Severity.MEDIUM,
        "description": (
            "platform.system() check found near exec/subprocess calls, "
            "suggesting platform-specific malicious behavior."
        ),
    },
]


# ---------------------------------------------------------------------------
# AST visitor: lightweight source-to-sink taint detection within a function
# or at module level.
# ---------------------------------------------------------------------------


class _TaintVisitor(ast.NodeVisitor):
    """Walk a Python AST and look for variables assigned from a sensitive
    source that later appear as arguments in a dangerous sink call."""

    def __init__(self, rel_path: str, analyzer_name: str) -> None:
        self.rel_path = rel_path
        self.analyzer_name = analyzer_name
        self.findings: list[Finding] = []
        # Stack of taint sets: each entry represents a scope (module or function)
        self._scope_taints: list[dict[str, tuple[str, int]]] = [{}]

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _attr_name(node: ast.AST) -> str | None:
        """Return a dotted name for an Attribute or Name node, or None."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _TaintVisitor._attr_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        return None

    def _call_name(self, node: ast.Call) -> str | None:
        return self._attr_name(node.func)

    def _is_source_call(self, node: ast.Call) -> str | None:
        """Return the source label if the call is a sensitive source, else None."""
        name = self._call_name(node)
        if name and name in SENSITIVE_SOURCES:
            return name
        return None

    def _is_source_attr(self, node: ast.AST) -> str | None:
        """Return the source label if the node is a sensitive attribute access."""
        name = self._attr_name(node)
        if name and name in SENSITIVE_SOURCES:
            return name
        return None

    def _is_sink_call(self, node: ast.Call) -> str | None:
        name = self._call_name(node)
        if name and name in DANGEROUS_SINKS:
            return name
        return None

    @property
    def _current_taints(self) -> dict[str, tuple[str, int]]:
        return self._scope_taints[-1]

    # -- visitors ----------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_taints.append({})
        self.generic_visit(node)
        self._scope_taints.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        source_label = None
        if isinstance(node.value, ast.Call):
            source_label = self._is_source_call(node.value)
        if source_label is None:
            source_label = self._is_source_attr(node.value)
        if source_label:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._current_taints[target.id] = (
                        source_label,
                        node.lineno,
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_label = self._is_sink_call(node)
        if sink_label:
            # Check arguments for tainted variable names
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self._current_taints:
                    source_label, _source_line = self._current_taints[arg.id]
                    self.findings.append(
                        Finding(
                            title=f"Sensitive data flow: {source_label} -> {sink_label}",
                            description=(
                                f"Variable '{arg.id}' assigned from {source_label} "
                                f"is passed to {sink_label}."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CODE_SAFETY,
                            file_path=self.rel_path,
                            line_number=node.lineno,
                            analyzer=self.analyzer_name,
                        )
                    )
            for kw in node.keywords:
                if (
                    isinstance(kw.value, ast.Name)
                    and kw.value.id in self._current_taints
                ):
                    source_label, _source_line = self._current_taints[
                        kw.value.id
                    ]
                    self.findings.append(
                        Finding(
                            title=f"Sensitive data flow: {source_label} -> {sink_label}",
                            description=(
                                f"Variable '{kw.value.id}' assigned from {source_label} "
                                f"is passed to {sink_label}."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CODE_SAFETY,
                            file_path=self.rel_path,
                            line_number=node.lineno,
                            analyzer=self.analyzer_name,
                        )
                    )
        self.generic_visit(node)


class BehavioralAnalyzer(Analyzer):
    name = "behavioral"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix
            if suffix not in SCAN_EXTENSIONS_REGEX and suffix not in SCAN_EXTENSIONS_AST:
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(file_path.relative_to(repo_path))

            # AST-based analysis for Python files
            if suffix in SCAN_EXTENSIONS_AST:
                findings.extend(self._analyze_ast(content, rel_path))

            # Regex-based behavioral patterns for all supported files
            if suffix in SCAN_EXTENSIONS_REGEX:
                findings.extend(self._analyze_regex(content, rel_path))

        return findings

    def _analyze_ast(self, content: str, rel_path: str) -> list[Finding]:
        """Run AST-based taint analysis on Python source."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        visitor = _TaintVisitor(rel_path, self.name)
        visitor.visit(tree)
        return visitor.findings

    def _analyze_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Run regex-based behavioral pattern detection."""
        findings: list[Finding] = []
        for pat in REGEX_PATTERNS:
            detect_match = None
            context_present = False
            # Find the first detect match line number
            for line_number, line in enumerate(content.splitlines(), start=1):
                if pat["detect"].search(line) and detect_match is None:
                    detect_match = line_number
                if pat["context"].search(line):
                    context_present = True
            # Only report if both the trigger and the context pattern are in the file
            if detect_match is not None and context_present:
                findings.append(
                    Finding(
                        title=pat["title"],
                        description=pat["description"],
                        severity=pat["severity"],
                        category=Category.CODE_SAFETY,
                        file_path=rel_path,
                        line_number=detect_match,
                        analyzer=self.name,
                    )
                )
        return findings
