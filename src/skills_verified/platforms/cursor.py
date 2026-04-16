import json
from pathlib import Path

from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)


class CursorProfile(PlatformProfile):
    name = "cursor"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        markers = [".cursor", ".cursorrules", ".cursor/rules"]
        for marker in markers:
            if (repo_path / marker).exists():
                return True
        return False

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        configs: list[ConfigFile] = []

        # .cursorrules (text)
        cursorrules = repo_path / ".cursorrules"
        if cursorrules.is_file():
            try:
                text = cursorrules.read_text(errors="ignore")
                configs.append(ConfigFile(
                    path=cursorrules.relative_to(repo_path),
                    platform=self.name,
                    config_type="rules",
                    content=text,
                ))
            except OSError:
                pass

        # .cursor/rules/*.md (text)
        rules_dir = repo_path / ".cursor" / "rules"
        if rules_dir.is_dir():
            for md_file in sorted(rules_dir.glob("*.md")):
                if not md_file.is_file():
                    continue
                try:
                    text = md_file.read_text(errors="ignore")
                    configs.append(ConfigFile(
                        path=md_file.relative_to(repo_path),
                        platform=self.name,
                        config_type="rules",
                        content=text,
                    ))
                except OSError:
                    pass

        # .cursor/mcp.json (JSON)
        mcp_json = repo_path / ".cursor" / "mcp.json"
        if mcp_json.is_file():
            try:
                data = json.loads(mcp_json.read_text(errors="ignore"))
                configs.append(ConfigFile(
                    path=mcp_json.relative_to(repo_path),
                    platform=self.name,
                    config_type="settings",
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

        mcp_json = repo_path / ".cursor" / "mcp.json"
        if not mcp_json.is_file():
            return definitions

        try:
            data = json.loads(mcp_json.read_text(errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return definitions

        if not isinstance(data, dict):
            return definitions

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return definitions

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            definitions.append(MCPToolDefinition(
                name=server_name,
                description=server_cfg.get("description", ""),
                input_schema=server_cfg.get("inputSchema", {}),
                source_file=mcp_json.relative_to(repo_path),
                raw_definition=server_cfg,
            ))

        return definitions
