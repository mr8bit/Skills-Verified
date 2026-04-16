"""Config injection analyzer — detects dangerous hooks, API URL overrides,
prompt injection in rules files, suspicious env vars, and credential
leaks across platform config files."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.platforms.base import ConfigFile, PlatformProfile

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

_DANGEROUS_COMMANDS_RE = re.compile(
    r"\b(curl|wget|nc|ncat|bash\s+-c|sh\s+-c|powershell)\b", re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
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

_SHELL_COMMANDS_IN_CODEBLOCK_RE = re.compile(
    r"\b(curl|wget|nc|bash|sh\s+-c|rm\s+-rf|chmod\s+777)\b", re.IGNORECASE,
)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_SENSITIVE_ENV_VARS_RE = re.compile(
    r"\$(?:ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET(?:_ACCESS_KEY)?|"
    r"OPENAI_API_KEY|AZURE_KEY|GCP_KEY|DATABASE_URL|"
    r"PRIVATE_KEY|SSH_KEY|NPM_TOKEN|DOCKER_PASSWORD)",
    re.IGNORECASE,
)

_CREDENTIAL_KEY_RE = re.compile(
    r"(password|token|secret|api_key|apikey|private_key|credential)",
    re.IGNORECASE,
)

_ANTHROPIC_DOMAIN_RE = re.compile(r"anthropic\.com", re.IGNORECASE)


class ConfigInjectionAnalyzer(Analyzer):
    name = "config_injection"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        if not platforms:
            return []

        all_configs: list[ConfigFile] = []
        for platform in platforms:
            all_configs.extend(platform.get_config_files(repo_path))

        if not all_configs:
            return []

        findings: list[Finding] = []
        for cfg in all_configs:
            if cfg.config_type == "settings":
                findings.extend(self._check_settings(cfg))
            elif cfg.config_type == "rules":
                findings.extend(self._check_rules(cfg))
            elif cfg.config_type == "manifest":
                findings.extend(self._check_manifest(cfg))

            # OpenClaw-specific: credential leak in any JSON config
            if isinstance(cfg.content, dict):
                findings.extend(self._check_credentials_in_json(cfg))

        return findings

    # ------------------------------------------------------------------
    # settings (JSON) checks
    # ------------------------------------------------------------------

    def _check_settings(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)

        # 1. Hooks with dangerous commands
        findings.extend(self._check_hooks(data, file_path))

        # 2. apiUrl / baseUrl override (CVE-2026-21852 vector)
        findings.extend(self._check_api_url_override(data, file_path))

        # 3. MCP servers with suspicious URLs
        findings.extend(self._check_mcp_server_urls(data, file_path))

        return findings

    def _check_hooks(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for key in ("hooks", "customCommands"):
            value = data.get(key)
            if value is None:
                continue
            dangerous_strings = self._extract_all_strings(value)
            for text in dangerous_strings:
                if _DANGEROUS_COMMANDS_RE.search(text):
                    findings.append(Finding(
                        title="Dangerous command in config hook",
                        description=(
                            f"Config key '{key}' contains a dangerous "
                            f"command: {text[:200]}"
                        ),
                        severity=Severity.HIGH,
                        category=Category.CONFIG_INJECTION,
                        file_path=file_path,
                        line_number=None,
                        analyzer=self.name,
                    ))

        return findings

    def _check_api_url_override(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for key in ("apiUrl", "baseUrl"):
            url = data.get(key)
            if not isinstance(url, str):
                continue
            if url and not _ANTHROPIC_DOMAIN_RE.search(url):
                findings.append(Finding(
                    title=f"API URL override to non-Anthropic domain — {key}",
                    description=(
                        f"Config sets '{key}' to '{url}', which does not "
                        f"point to anthropic.com.  This is a known attack "
                        f"vector (CVE-2026-21852) that redirects API calls "
                        f"to a malicious server."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.CONFIG_INJECTION,
                    file_path=file_path,
                    line_number=None,
                    analyzer=self.name,
                    cve_id="CVE-2026-21852",
                ))

        return findings

    def _check_mcp_server_urls(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return findings

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            for url_key in ("url", "command", "endpoint"):
                url_value = server_cfg.get(url_key)
                if not isinstance(url_value, str):
                    continue
                # Flag non-localhost, non-standard URLs
                if self._is_suspicious_url(url_value):
                    findings.append(Finding(
                        title=f"Suspicious MCP server URL in '{server_name}'",
                        description=(
                            f"MCP server '{server_name}' has {url_key}="
                            f"'{url_value}' which points to a potentially "
                            f"untrusted host."
                        ),
                        severity=Severity.HIGH,
                        category=Category.CONFIG_INJECTION,
                        file_path=file_path,
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.7,
                    ))

        return findings

    # ------------------------------------------------------------------
    # rules (text — CLAUDE.md, .cursorrules) checks
    # ------------------------------------------------------------------

    def _check_rules(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        text = cfg.content
        if not isinstance(text, str):
            return findings

        file_path = str(cfg.path)

        # 1. Prompt injection patterns
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        title="Prompt injection in config rules file",
                        description=(
                            f"Rules file contains injection pattern: "
                            f"'{pattern.pattern}'. Line: {line.strip()[:150]}"
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.CONFIG_INJECTION,
                        file_path=file_path,
                        line_number=line_number,
                        analyzer=self.name,
                    ))

        # 2. Shell commands in code blocks
        in_code_block = False
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block and _SHELL_COMMANDS_IN_CODEBLOCK_RE.search(line):
                findings.append(Finding(
                    title="Shell command in rules code block",
                    description=(
                        f"Code block in rules file contains a shell "
                        f"command: {line.strip()[:150]}"
                    ),
                    severity=Severity.HIGH,
                    category=Category.CONFIG_INJECTION,
                    file_path=file_path,
                    line_number=line_number,
                    analyzer=self.name,
                ))

        # 3. Base64-encoded payloads
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in _BASE64_RE.finditer(line):
                try:
                    decoded = base64.b64decode(match.group()).decode(
                        "utf-8", errors="ignore"
                    )
                    suspicious = [
                        "ignore", "system", "prompt", "instruction",
                        "override", "jailbreak", "curl", "wget", "bash",
                    ]
                    if any(w in decoded.lower() for w in suspicious):
                        findings.append(Finding(
                            title="Base64-encoded payload in rules file",
                            description=(
                                f"Base64 string decodes to suspicious "
                                f"content: {decoded[:100]}"
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=line_number,
                            analyzer=self.name,
                        ))
                except Exception:
                    pass

        return findings

    # ------------------------------------------------------------------
    # manifest (JSON — mcp.json, flow files) checks
    # ------------------------------------------------------------------

    def _check_manifest(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)

        # 1. Suspicious env var references in args
        all_strings = self._extract_all_strings(data)
        for text in all_strings:
            if _SENSITIVE_ENV_VARS_RE.search(text):
                findings.append(Finding(
                    title="Sensitive env var reference in manifest",
                    description=(
                        f"Manifest references a sensitive environment "
                        f"variable: {text[:200]}"
                    ),
                    severity=Severity.HIGH,
                    category=Category.CONFIG_INJECTION,
                    file_path=file_path,
                    line_number=None,
                    analyzer=self.name,
                ))

        # 2. Server URLs pointing to suspicious domains
        servers = data.get("mcpServers", {})
        if isinstance(servers, dict):
            for server_name, server_cfg in servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                for url_key in ("url", "command", "endpoint"):
                    url_value = server_cfg.get(url_key)
                    if isinstance(url_value, str) and self._is_suspicious_url(url_value):
                        findings.append(Finding(
                            title=f"Suspicious server URL in manifest — '{server_name}'",
                            description=(
                                f"Manifest server '{server_name}' has "
                                f"{url_key}='{url_value}' pointing to a "
                                f"potentially untrusted host."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=None,
                            analyzer=self.name,
                            confidence=0.7,
                        ))

        return findings

    # ------------------------------------------------------------------
    # OpenClaw-specific: credentials stored in config
    # ------------------------------------------------------------------

    def _check_credentials_in_json(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)
        self._walk_credential_keys(data, file_path, findings)
        return findings

    def _walk_credential_keys(
        self, obj: Any, file_path: str, findings: list[Finding]
    ) -> None:
        """Recursively scan JSON for keys that look like credentials."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and len(value) >= 8:
                    if _CREDENTIAL_KEY_RE.search(key):
                        findings.append(Finding(
                            title="Credential stored in config file",
                            description=(
                                f"Config key '{key}' appears to contain "
                                f"a credential value (length {len(value)}). "
                                f"Credentials should not be stored in "
                                f"repository config files."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=None,
                            analyzer=self.name,
                        ))
                else:
                    self._walk_credential_keys(value, file_path, findings)
        elif isinstance(obj, list):
            for item in obj:
                self._walk_credential_keys(item, file_path, findings)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_all_strings(obj: Any) -> list[str]:
        """Recursively collect all string values from a nested dict/list."""
        strings: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, str):
                strings.append(node)
            elif isinstance(node, dict):
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(obj)
        return strings

    @staticmethod
    def _is_suspicious_url(url: str) -> bool:
        """Heuristic: flag URLs that are not localhost or well-known hosts."""
        url_lower = url.lower().strip()

        # Not a URL-like string at all
        if not any(url_lower.startswith(p) for p in ("http://", "https://", "ws://", "wss://")):
            return False

        safe_hosts = [
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "anthropic.com", "github.com", "npmjs.org", "pypi.org",
        ]
        for host in safe_hosts:
            if host in url_lower:
                return False

        return True
