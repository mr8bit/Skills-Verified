"""MCP security analyzer — detects tool poisoning, schema poisoning,
rug-pull indicators and cross-tool chaining in MCP definitions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.platforms.base import MCPToolDefinition, PlatformProfile

# ---------------------------------------------------------------------------
# Injection / poisoning patterns shared across checks
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(your\s+)?(instructions|guidelines)",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
]

# Cross-tool chaining phrases
_CROSS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bthen\s+call\b", re.IGNORECASE),
    re.compile(r"\binvoke\b", re.IGNORECASE),
    re.compile(r"\buse\s+the\s+\S+\s+tool\b", re.IGNORECASE),
    re.compile(r"\brun\s+\S+\s+after\b", re.IGNORECASE),
]

# Rug-pull detection patterns in source code
_RUG_PULL_DYNAMIC_LIST_RE = re.compile(
    r"(tools/list|listTools)", re.IGNORECASE,
)
_RUG_PULL_CONDITIONAL_RE = re.compile(
    r"\b(if|switch|case|ternary)\b", re.IGNORECASE,
)
_RUG_PULL_PY_REDEFINE_RE = re.compile(
    r"server\.tool\s*\(", re.IGNORECASE,
)
_RUG_PULL_JS_REDEFINE_RE = re.compile(
    r"registerTool\s*\(", re.IGNORECASE,
)
_RUG_PULL_TIMER_RE = re.compile(
    r"\b(setTimeout|setInterval)\b",
)

# String fields in JSON schemas that may carry injected text
_SCHEMA_STRING_FIELDS = {"title", "default", "examples", "enum", "description"}

# File extensions to scan for rug-pull indicators
_CODE_EXTENSIONS = {".py", ".js", ".mjs", ".ts", ".mts"}


class MCPAnalyzer(Analyzer):
    name = "mcp"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        if not platforms:
            return []

        # Collect all MCP definitions from every detected platform
        all_defs: list[MCPToolDefinition] = []
        for platform in platforms:
            all_defs.extend(platform.get_mcp_definitions(repo_path))

        if not all_defs:
            return []

        findings: list[Finding] = []
        for tool_def in all_defs:
            findings.extend(self._check_tool_poisoning(tool_def))
            findings.extend(self._check_schema_poisoning(tool_def))
            findings.extend(self._check_cross_tool_chaining(tool_def))

        findings.extend(self._check_rug_pull(repo_path))

        return findings

    # ------------------------------------------------------------------
    # Tool poisoning — description field of each tool
    # ------------------------------------------------------------------

    def _check_tool_poisoning(self, tool_def: MCPToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        desc = tool_def.description or ""

        # Check for prompt injection patterns
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(desc):
                findings.append(Finding(
                    title=f"MCP tool poisoning in '{tool_def.name}'",
                    description=(
                        f"Tool description contains prompt injection pattern: "
                        f"'{pattern.pattern}'. Description: {desc[:200]}"
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.MCP_SECURITY,
                    file_path=str(tool_def.source_file),
                    line_number=None,
                    analyzer=self.name,
                ))

        # Suspiciously long description — may hide instructions after
        # legitimate-looking text
        if len(desc) > 500:
            findings.append(Finding(
                title=f"Unusually long tool description for '{tool_def.name}'",
                description=(
                    f"Tool description is {len(desc)} chars long. "
                    f"Long descriptions may conceal hidden instructions."
                ),
                severity=Severity.CRITICAL,
                category=Category.MCP_SECURITY,
                file_path=str(tool_def.source_file),
                line_number=None,
                analyzer=self.name,
                confidence=0.7,
            ))

        return findings

    # ------------------------------------------------------------------
    # Schema poisoning — string values inside input_schema / raw_definition
    # ------------------------------------------------------------------

    def _check_schema_poisoning(self, tool_def: MCPToolDefinition) -> list[Finding]:
        findings: list[Finding] = []

        suspicious_strings: list[str] = []
        self._collect_suspicious_strings(tool_def.input_schema, suspicious_strings)
        self._collect_suspicious_strings(tool_def.raw_definition, suspicious_strings)

        for text in suspicious_strings:
            findings.append(Finding(
                title=f"MCP schema poisoning in '{tool_def.name}'",
                description=(
                    f"Prompt injection pattern found in schema value: "
                    f"{text[:200]}"
                ),
                severity=Severity.HIGH,
                category=Category.MCP_SECURITY,
                file_path=str(tool_def.source_file),
                line_number=None,
                analyzer=self.name,
            ))

        return findings

    def _collect_suspicious_strings(
        self, obj: Any, out: list[str], *, parent_key: str = ""
    ) -> None:
        """Recursively walk a dict/list and collect string values that match
        injection patterns.  Prioritises the well-known schema string fields
        but also inspects every string value encountered."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                self._collect_suspicious_strings(value, out, parent_key=str(key))
        elif isinstance(obj, list):
            for item in obj:
                self._collect_suspicious_strings(item, out, parent_key=parent_key)
        elif isinstance(obj, str):
            # Only flag strings in schema-relevant fields or when the
            # parent key is a well-known string field
            is_schema_field = parent_key.lower() in _SCHEMA_STRING_FIELDS
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(obj):
                    # Always flag schema string fields; for other keys,
                    # still flag to be safe (schema can nest arbitrarily)
                    if is_schema_field or True:  # scan all strings
                        out.append(obj)
                    break

    # ------------------------------------------------------------------
    # Rug-pull indicators — dynamic tool list / runtime redefinition
    # ------------------------------------------------------------------

    def _check_rug_pull(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in _CODE_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue

            rel_path = str(file_path.relative_to(repo_path))
            lines = content.splitlines()

            findings.extend(
                self._check_dynamic_list(lines, content, rel_path)
            )
            findings.extend(
                self._check_runtime_redefine(lines, content, rel_path, file_path.suffix)
            )

        return findings

    def _check_dynamic_list(
        self, lines: list[str], content: str, rel_path: str
    ) -> list[Finding]:
        """Flag tools/list or listTools near conditional logic."""
        findings: list[Finding] = []

        if not _RUG_PULL_DYNAMIC_LIST_RE.search(content):
            return findings
        if not _RUG_PULL_CONDITIONAL_RE.search(content):
            return findings

        for line_number, line in enumerate(lines, start=1):
            if _RUG_PULL_DYNAMIC_LIST_RE.search(line):
                findings.append(Finding(
                    title="MCP rug-pull indicator — dynamic tool list",
                    description=(
                        "tools/list or listTools is used alongside conditional "
                        "logic, suggesting the tool list may change at runtime."
                    ),
                    severity=Severity.HIGH,
                    category=Category.MCP_SECURITY,
                    file_path=rel_path,
                    line_number=line_number,
                    analyzer=self.name,
                    confidence=0.8,
                ))

        return findings

    def _check_runtime_redefine(
        self,
        lines: list[str],
        content: str,
        rel_path: str,
        suffix: str,
    ) -> list[Finding]:
        """Flag server.tool / registerTool inside conditionals or timers."""
        findings: list[Finding] = []

        redefine_re = (
            _RUG_PULL_PY_REDEFINE_RE if suffix == ".py"
            else _RUG_PULL_JS_REDEFINE_RE
        )

        if not redefine_re.search(content):
            return findings

        has_timer = _RUG_PULL_TIMER_RE.search(content) is not None
        has_conditional = _RUG_PULL_CONDITIONAL_RE.search(content) is not None

        if not (has_timer or has_conditional):
            return findings

        for line_number, line in enumerate(lines, start=1):
            if redefine_re.search(line):
                trigger = "timer callback" if has_timer else "conditional block"
                findings.append(Finding(
                    title="MCP rug-pull indicator — runtime tool redefinition",
                    description=(
                        f"Tool registration (server.tool/registerTool) "
                        f"appears in a file with {trigger} logic, "
                        f"suggesting tools may be redefined after initial "
                        f"handshake."
                    ),
                    severity=Severity.HIGH,
                    category=Category.MCP_SECURITY,
                    file_path=rel_path,
                    line_number=line_number,
                    analyzer=self.name,
                    confidence=0.7,
                ))

        return findings

    # ------------------------------------------------------------------
    # Cross-tool chaining — description references calling another tool
    # ------------------------------------------------------------------

    def _check_cross_tool_chaining(
        self, tool_def: MCPToolDefinition
    ) -> list[Finding]:
        findings: list[Finding] = []
        desc = tool_def.description or ""

        for pattern in _CROSS_TOOL_PATTERNS:
            if pattern.search(desc):
                findings.append(Finding(
                    title=f"Cross-tool chaining in '{tool_def.name}'",
                    description=(
                        f"Tool description instructs calling another tool: "
                        f"matched '{pattern.pattern}'. "
                        f"Description: {desc[:200]}"
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.MCP_SECURITY,
                    file_path=str(tool_def.source_file),
                    line_number=None,
                    analyzer=self.name,
                ))

        return findings
