import json
from pathlib import Path

from skills_verified.platforms.detector import PlatformDetector


def test_detects_claude_code(tmp_path):
    """SKILL.md triggers claude_code platform detection."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\n"
        "name: my-skill\n"
        "description: A skill.\n"
        "---\n"
    )

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "claude_code" in platform_names


def test_detects_cursor(tmp_path):
    """.cursorrules triggers cursor platform detection."""
    cursorrules = tmp_path / ".cursorrules"
    cursorrules.write_text("You are a helpful assistant.\n")

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "cursor" in platform_names


def test_detects_generic_mcp(tmp_path):
    """mcp.json triggers generic_mcp platform detection."""
    mcp_json = tmp_path / "mcp.json"
    mcp_json.write_text(json.dumps({
        "tools": [
            {
                "name": "read_file",
                "description": "Reads a file.",
                "inputSchema": {}
            }
        ]
    }))

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "generic_mcp" in platform_names


def test_detects_multiple(tmp_path):
    """Repo with both SKILL.md and mcp.json detects both platforms."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\n"
        "name: multi-platform\n"
        "description: Multi.\n"
        "---\n"
    )
    mcp_json = tmp_path / "mcp.json"
    mcp_json.write_text(json.dumps({"tools": []}))

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "claude_code" in platform_names
    assert "generic_mcp" in platform_names


def test_empty_repo(tmp_path):
    """An empty repo detects no platforms."""
    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    assert platforms == []
