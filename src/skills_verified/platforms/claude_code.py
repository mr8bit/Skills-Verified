import json
import re
from pathlib import Path

import yaml

from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)

_DETECTION_MARKERS = [
    "SKILL.md",
    ".skills",
    ".claude/settings.json",
    ".claude/config.json",
    "CLAUDE.md",
]

_TOOL_DECORATOR_RE = re.compile(
    r"""@server\.(call_tool|tool)\s*\("""
    r"""|server\.tool\s*\("""
)


class ClaudeCodeProfile(PlatformProfile):
    name = "claude_code"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        for marker in _DETECTION_MARKERS:
            if (repo_path / marker).exists():
                return True
        return False

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        configs: list[ConfigFile] = []

        # .claude/settings.json
        settings = repo_path / ".claude" / "settings.json"
        self._try_load_json(settings, repo_path, "settings", configs)

        # .claude/config.json
        config = repo_path / ".claude" / "config.json"
        self._try_load_json(config, repo_path, "settings", configs)

        # CLAUDE.md
        claude_md = repo_path / "CLAUDE.md"
        if claude_md.is_file():
            try:
                text = claude_md.read_text(errors="ignore")
                configs.append(ConfigFile(
                    path=claude_md.relative_to(repo_path),
                    platform=self.name,
                    config_type="rules",
                    content=text,
                ))
            except OSError:
                pass

        return configs

    # ------------------------------------------------------------------
    # skill metadata
    # ------------------------------------------------------------------

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        skill_md = repo_path / "SKILL.md"
        if not skill_md.is_file():
            return None

        try:
            text = skill_md.read_text(errors="ignore")
        except OSError:
            return None

        frontmatter = self._parse_frontmatter(text)
        if frontmatter is None:
            return None

        permissions = frontmatter.get("permissions", [])
        if isinstance(permissions, str):
            permissions = [permissions]

        entry_points_raw = frontmatter.get("entry_points", [])
        if isinstance(entry_points_raw, str):
            entry_points_raw = [entry_points_raw]

        return SkillMetadata(
            name=frontmatter.get("name"),
            description=frontmatter.get("description"),
            author=frontmatter.get("author"),
            permissions_declared=list(permissions),
            entry_points=[Path(e) for e in entry_points_raw],
            platform=self.name,
        )

    # ------------------------------------------------------------------
    # MCP definitions
    # ------------------------------------------------------------------

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        # From .claude/settings.json → mcpServers
        settings_path = repo_path / ".claude" / "settings.json"
        if settings_path.is_file():
            try:
                data = json.loads(settings_path.read_text(errors="ignore"))
                servers = data.get("mcpServers", {})
                for server_name, server_cfg in servers.items():
                    if not isinstance(server_cfg, dict):
                        continue
                    definitions.append(MCPToolDefinition(
                        name=server_name,
                        description=server_cfg.get("description", ""),
                        input_schema=server_cfg.get("inputSchema", {}),
                        source_file=settings_path.relative_to(repo_path),
                        raw_definition=server_cfg,
                    ))
            except (OSError, json.JSONDecodeError):
                pass

        # Scan Python files for tool decorators
        definitions.extend(self._scan_python_tools(repo_path))

        return definitions

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _try_load_json(
        self,
        path: Path,
        repo_path: Path,
        config_type: str,
        out: list[ConfigFile],
    ) -> None:
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(errors="ignore"))
            out.append(ConfigFile(
                path=path.relative_to(repo_path),
                platform=self.name,
                config_type=config_type,
                content=data,
            ))
        except (OSError, json.JSONDecodeError):
            pass

    @staticmethod
    def _parse_frontmatter(text: str) -> dict | None:
        """Parse YAML frontmatter between the first two ``---`` lines."""
        lines = text.splitlines(keepends=True)
        if not lines or lines[0].strip() != "---":
            return None

        end_idx = None
        for idx, line in enumerate(lines[1:], start=1):
            if line.strip() == "---":
                end_idx = idx
                break

        if end_idx is None:
            return None

        yaml_block = "".join(lines[1:end_idx])
        try:
            parsed = yaml.safe_load(yaml_block)
            return parsed if isinstance(parsed, dict) else None
        except yaml.YAMLError:
            return None

    def _scan_python_tools(self, repo_path: Path) -> list[MCPToolDefinition]:
        """Scan .py files for ``@server.call_tool`` / ``server.tool()`` patterns."""
        definitions: list[MCPToolDefinition] = []
        for py_file in repo_path.rglob("*.py"):
            if not py_file.is_file():
                continue
            try:
                content = py_file.read_text(errors="ignore")
            except OSError:
                continue

            for match in _TOOL_DECORATOR_RE.finditer(content):
                # Try to extract the function name on the next def line
                rest = content[match.end():]
                func_name = self._extract_func_name(rest)
                definitions.append(MCPToolDefinition(
                    name=func_name or "unknown",
                    description="",
                    input_schema={},
                    source_file=py_file.relative_to(repo_path),
                ))
        return definitions

    @staticmethod
    def _extract_func_name(text_after_decorator: str) -> str | None:
        """Find the first ``def <name>`` after a decorator match."""
        for line in text_after_decorator.splitlines():
            stripped = line.strip()
            m = re.match(r"def\s+(\w+)\s*\(", stripped)
            if m:
                return m.group(1)
            # Stop searching if we hit another decorator or class
            if stripped.startswith("@") or stripped.startswith("class "):
                break
        return None
