from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfigFile:
    path: Path           # relative to repo root
    platform: str        # "claude_code", "openclaw", "cursor", "generic_mcp"
    config_type: str     # "settings", "hooks", "rules", "manifest"
    content: dict | str  # parsed content


@dataclass
class SkillMetadata:
    name: str | None
    description: str | None
    author: str | None
    permissions_declared: list[str] = field(default_factory=list)
    entry_points: list[Path] = field(default_factory=list)
    platform: str = ""


@dataclass
class MCPToolDefinition:
    name: str
    description: str
    input_schema: dict
    source_file: Path
    raw_definition: dict = field(default_factory=dict)


class PlatformProfile(ABC):
    name: str = "base"

    @abstractmethod
    def detect(self, repo_path: Path) -> bool:
        """Check if repository belongs to this platform."""

    @abstractmethod
    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        """Return all platform config files."""

    @abstractmethod
    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        """Extract skill/plugin metadata if present."""

    @abstractmethod
    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        """Extract MCP tool definitions if present."""
