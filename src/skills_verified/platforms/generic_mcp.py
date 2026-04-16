import json
import re
from pathlib import Path

from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)

_PY_MCP_IMPORT_RE = re.compile(
    r"""^\s*(?:import\s+mcp|from\s+mcp\b)""",
    re.MULTILINE,
)
_JS_MCP_IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*['"]@modelcontextprotocol/sdk['"]|"""
    r"""from\s+['"]@modelcontextprotocol/sdk['"\/])""",
)

_PY_TOOL_DECORATOR_RE = re.compile(
    r"""@server\.tool\s*\("""
    r"""|server\.add_tool\s*\("""
    r"""|@server\.call_tool\s*\("""
)
_JS_TOOL_RE = re.compile(
    r"""server\.setRequestHandler\s*\(\s*(?:ListToolsRequestSchema|CallToolRequestSchema)"""
    r"""|\.tool\s*\(\s*['"]([^'"]+)['"]"""
)


class GenericMCPProfile(PlatformProfile):
    name = "generic_mcp"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        # Check manifest files
        for name in ("mcp.json", "mcp-config.json"):
            if (repo_path / name).is_file():
                return True

        # Check Python files for MCP imports
        for py_file in repo_path.rglob("*.py"):
            if not py_file.is_file():
                continue
            try:
                content = py_file.read_text(errors="ignore")
            except OSError:
                continue
            if _PY_MCP_IMPORT_RE.search(content):
                return True

        # Check JS/TS files for MCP SDK imports
        for pattern in ("*.js", "*.ts", "*.mjs", "*.mts"):
            for js_file in repo_path.rglob(pattern):
                if not js_file.is_file():
                    continue
                try:
                    content = js_file.read_text(errors="ignore")
                except OSError:
                    continue
                if _JS_MCP_IMPORT_RE.search(content):
                    return True

        return False

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        configs: list[ConfigFile] = []

        for name in ("mcp.json", "mcp-config.json"):
            path = repo_path / name
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(errors="ignore"))
                configs.append(ConfigFile(
                    path=path.relative_to(repo_path),
                    platform=self.name,
                    config_type="manifest",
                    content=data,
                ))
            except (OSError, json.JSONDecodeError):
                pass

        return configs

    # ------------------------------------------------------------------
    # skill metadata
    # ------------------------------------------------------------------

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        return None

    # ------------------------------------------------------------------
    # MCP definitions
    # ------------------------------------------------------------------

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        # From manifest files
        definitions.extend(self._defs_from_manifests(repo_path))

        # From Python source
        definitions.extend(self._scan_python_tools(repo_path))

        # From JS/TS source
        definitions.extend(self._scan_js_tools(repo_path))

        return definitions

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _defs_from_manifests(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        for name in ("mcp.json", "mcp-config.json"):
            path = repo_path / name
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue

            if not isinstance(data, dict):
                continue

            # Tool definitions directly in manifest
            tools = data.get("tools", [])
            if isinstance(tools, list):
                for tool in tools:
                    if not isinstance(tool, dict):
                        continue
                    definitions.append(MCPToolDefinition(
                        name=tool.get("name", "unknown"),
                        description=tool.get("description", ""),
                        input_schema=tool.get("inputSchema", {}),
                        source_file=path.relative_to(repo_path),
                        raw_definition=tool,
                    ))

            # Server configs in manifest
            servers = data.get("mcpServers", {})
            if isinstance(servers, dict):
                for server_name, server_cfg in servers.items():
                    if not isinstance(server_cfg, dict):
                        continue
                    definitions.append(MCPToolDefinition(
                        name=server_name,
                        description=server_cfg.get("description", ""),
                        input_schema=server_cfg.get("inputSchema", {}),
                        source_file=path.relative_to(repo_path),
                        raw_definition=server_cfg,
                    ))

        return definitions

    def _scan_python_tools(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        for py_file in repo_path.rglob("*.py"):
            if not py_file.is_file():
                continue
            try:
                content = py_file.read_text(errors="ignore")
            except OSError:
                continue

            for match in _PY_TOOL_DECORATOR_RE.finditer(content):
                rest = content[match.end():]
                func_name = self._extract_py_func_name(rest)
                definitions.append(MCPToolDefinition(
                    name=func_name or "unknown",
                    description="",
                    input_schema={},
                    source_file=py_file.relative_to(repo_path),
                ))

        return definitions

    def _scan_js_tools(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        for ext in ("*.js", "*.ts", "*.mjs", "*.mts"):
            for js_file in repo_path.rglob(ext):
                if not js_file.is_file():
                    continue
                try:
                    content = js_file.read_text(errors="ignore")
                except OSError:
                    continue

                for match in _JS_TOOL_RE.finditer(content):
                    tool_name = match.group(1) if match.group(1) else "unknown"
                    definitions.append(MCPToolDefinition(
                        name=tool_name,
                        description="",
                        input_schema={},
                        source_file=js_file.relative_to(repo_path),
                    ))

        return definitions

    @staticmethod
    def _extract_py_func_name(text_after_decorator: str) -> str | None:
        """Find the first ``def <name>`` after a decorator match."""
        for line in text_after_decorator.splitlines():
            stripped = line.strip()
            m = re.match(r"def\s+(\w+)\s*\(", stripped)
            if m:
                return m.group(1)
            if stripped.startswith("@") or stripped.startswith("class "):
                break
        return None
