import json
import re
from pathlib import Path

from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)

_REGISTER_TYPE_RE = re.compile(r"""RED\.nodes\.registerType\s*\(\s*['"]([^'"]+)['"]""")


class OpenClawProfile(PlatformProfile):
    name = "openclaw"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        dir_markers = ["flows", "nodes", ".openclaw"]
        for marker in dir_markers:
            if (repo_path / marker).exists():
                return True

        pkg_json = repo_path / "package.json"
        if pkg_json.is_file():
            try:
                text = pkg_json.read_text(errors="ignore")
                if "node-red" in text:
                    return True
            except OSError:
                pass

        return False

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        configs: list[ConfigFile] = []

        # .openclaw/*.json
        openclaw_dir = repo_path / ".openclaw"
        if openclaw_dir.is_dir():
            for json_file in sorted(openclaw_dir.glob("*.json")):
                self._try_load_json(json_file, repo_path, "settings", configs)

        # flows/*.json
        flows_dir = repo_path / "flows"
        if flows_dir.is_dir():
            for json_file in sorted(flows_dir.glob("*.json")):
                self._try_load_json(json_file, repo_path, "manifest", configs)

        return configs

    # ------------------------------------------------------------------
    # skill metadata
    # ------------------------------------------------------------------

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        pkg_json = repo_path / "package.json"
        if not pkg_json.is_file():
            return None

        try:
            data = json.loads(pkg_json.read_text(errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return None

        if not isinstance(data, dict):
            return None

        return SkillMetadata(
            name=data.get("name"),
            description=data.get("description"),
            author=data.get("author"),
            permissions_declared=[],
            entry_points=[],
            platform=self.name,
        )

    # ------------------------------------------------------------------
    # MCP definitions
    # ------------------------------------------------------------------

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        definitions: list[MCPToolDefinition] = []

        nodes_dir = repo_path / "nodes"
        if not nodes_dir.is_dir():
            return definitions

        for js_file in sorted(nodes_dir.rglob("*.js")):
            if not js_file.is_file():
                continue
            try:
                content = js_file.read_text(errors="ignore")
            except OSError:
                continue

            for match in _REGISTER_TYPE_RE.finditer(content):
                definitions.append(MCPToolDefinition(
                    name=match.group(1),
                    description="",
                    input_schema={},
                    source_file=js_file.relative_to(repo_path),
                ))

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
