import hashlib
import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

CAMPAIGN_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".ps1", ".rb",
    ".md", ".txt", ".json", ".yaml", ".yml",
}

MAX_HASH_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


class KnownThreatsAnalyzer(Analyzer):
    name = "known_threats"

    def __init__(self) -> None:
        loader = SignatureLoader()
        self._malicious_authors: list[dict] = loader.load_authors(
            "malicious_authors.yaml",
        )
        self._malicious_hashes: list[dict] = loader.load_hashes(
            "malicious_hashes.yaml",
        )
        self._campaigns: list[dict] = loader.load_campaigns(
            "campaign_signatures.yaml",
        )

        # Pre-build a lowercase set for fast author lookups.
        self._author_names_lower: dict[str, dict] = {
            entry["name"].lower(): entry
            for entry in self._malicious_authors
            if "name" in entry
        }

        # Pre-build a hash lookup dict.
        self._hash_lookup: dict[str, dict] = {
            entry["sha256"]: entry
            for entry in self._malicious_hashes
            if "sha256" in entry
        }

        # Pre-compile campaign patterns.
        self._compiled_campaigns: list[dict] = []
        for campaign in self._campaigns:
            compiled_patterns: list[dict] = []
            for pat_entry in campaign.get("patterns", []):
                try:
                    compiled = re.compile(pat_entry["pattern"])
                    compiled_patterns.append({
                        "regex": compiled,
                        "severity": getattr(
                            Severity, pat_entry.get("severity", "HIGH"),
                        ),
                        "description": pat_entry.get("description", ""),
                    })
                except re.error:
                    logger.warning(
                        "Failed to compile campaign pattern in %s: %s",
                        campaign.get("id", "?"),
                        pat_entry.get("pattern", "?"),
                    )
            self._compiled_campaigns.append({
                "id": campaign.get("id", ""),
                "name": campaign.get("name", ""),
                "patterns": compiled_patterns,
                "indicators": campaign.get("indicators", {}),
            })

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        findings: list[Finding] = []

        platforms = kwargs.get("platforms") or []

        findings.extend(self._check_authors(platforms))
        findings.extend(self._check_git_remotes(repo_path))
        findings.extend(self._check_file_hashes(repo_path))
        findings.extend(self._check_campaigns(repo_path))

        return findings

    # ------------------------------------------------------------------
    # Author check
    # ------------------------------------------------------------------

    def _check_authors(self, platforms: list) -> list[Finding]:
        findings: list[Finding] = []
        for platform in platforms:
            metadata = None
            if hasattr(platform, "get_skill_metadata"):
                # platform is a PlatformProfile; we'd need repo_path, but
                # when passed through kwargs the caller already resolved
                # SkillMetadata for us.  Handle both forms.
                metadata = platform
            # If the caller passes SkillMetadata objects directly:
            if hasattr(platform, "author"):
                metadata = platform

            if metadata is None:
                continue

            author = getattr(metadata, "author", None)
            if not author:
                continue

            author_lower = author.lower()
            if author_lower in self._author_names_lower:
                entry = self._author_names_lower[author_lower]
                findings.append(Finding(
                    title=f"Known malicious author: {author}",
                    description=(
                        f"Author '{author}' is listed in the malicious authors database. "
                        f"Source: {entry.get('source', 'N/A')}. "
                        f"{entry.get('description', '')}"
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.SUPPLY_CHAIN,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=1.0,
                ))
        return findings

    # ------------------------------------------------------------------
    # Git remote check
    # ------------------------------------------------------------------

    def _check_git_remotes(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        git_config = repo_path / ".git" / "config"
        if not git_config.exists():
            return findings

        try:
            content = git_config.read_text(errors="ignore")
        except OSError:
            return findings

        url_pattern = re.compile(r"url\s*=\s*(.+)")
        urls: list[str] = []
        for match in url_pattern.finditer(content):
            urls.append(match.group(1).strip())

        for url in urls:
            url_lower = url.lower()
            for author_name, entry in self._author_names_lower.items():
                if author_name in url_lower:
                    findings.append(Finding(
                        title=f"Git remote linked to known malicious author: {entry.get('name', author_name)}",
                        description=(
                            f"Git remote URL '{url}' contains the name of known malicious "
                            f"author '{entry.get('name', author_name)}'. "
                            f"Source: {entry.get('source', 'N/A')}."
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        file_path=".git/config",
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.9,
                    ))
        return findings

    # ------------------------------------------------------------------
    # File hash check
    # ------------------------------------------------------------------

    def _check_file_hashes(self, repo_path: Path) -> list[Finding]:
        if not self._hash_lookup:
            return []

        findings: list[Finding] = []
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip .git directory internals.
            try:
                rel = file_path.relative_to(repo_path)
            except ValueError:
                continue
            if rel.parts and rel.parts[0] == ".git":
                continue

            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size > MAX_HASH_FILE_SIZE:
                continue

            file_hash = self._compute_sha256(file_path)
            if file_hash is None:
                continue

            if file_hash in self._hash_lookup:
                entry = self._hash_lookup[file_hash]
                findings.append(Finding(
                    title=f"Known malicious file hash: {entry.get('name', file_hash[:16])}",
                    description=(
                        f"File '{rel}' matches SHA256 hash of known malicious file. "
                        f"Hash: {file_hash}. "
                        f"Severity: {entry.get('severity', 'CRITICAL')}."
                    ),
                    severity=getattr(
                        Severity,
                        entry.get("severity", "CRITICAL"),
                        Severity.CRITICAL,
                    ),
                    category=Category.SUPPLY_CHAIN,
                    file_path=str(rel),
                    line_number=None,
                    analyzer=self.name,
                    confidence=1.0,
                ))
        return findings

    @staticmethod
    def _compute_sha256(file_path: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    # ------------------------------------------------------------------
    # Campaign pattern check
    # ------------------------------------------------------------------

    def _check_campaigns(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for campaign in self._compiled_campaigns:
            campaign_id = campaign["id"]
            campaign_name = campaign["name"]

            # Pattern scanning across code/text files.
            for file_path in repo_path.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix not in CAMPAIGN_SCAN_EXTENSIONS:
                    continue
                try:
                    rel = file_path.relative_to(repo_path)
                except ValueError:
                    continue
                if rel.parts and rel.parts[0] == ".git":
                    continue

                try:
                    content = file_path.read_text(errors="ignore")
                except OSError:
                    continue

                rel_str = str(rel)
                for line_number, line in enumerate(content.splitlines(), start=1):
                    for pat in campaign["patterns"]:
                        if pat["regex"].search(line):
                            findings.append(Finding(
                                title=f"Campaign match [{campaign_id}] {campaign_name}",
                                description=(
                                    f"{pat['description']} "
                                    f"(Campaign: {campaign_name})"
                                ),
                                severity=pat["severity"],
                                category=Category.SUPPLY_CHAIN,
                                file_path=rel_str,
                                line_number=line_number,
                                analyzer=self.name,
                                confidence=0.85,
                            ))

            # Indicator file checks.
            indicator_files = (
                campaign.get("indicators", {}).get("files") or []
            )
            for indicator_filename in indicator_files:
                for found in repo_path.rglob(indicator_filename):
                    try:
                        rel = found.relative_to(repo_path)
                    except ValueError:
                        continue
                    if rel.parts and rel.parts[0] == ".git":
                        continue
                    findings.append(Finding(
                        title=f"Campaign indicator file [{campaign_id}] {campaign_name}",
                        description=(
                            f"File '{rel}' matches an indicator filename for "
                            f"campaign '{campaign_name}' ({campaign_id})."
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        file_path=str(rel),
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.7,
                    ))

        return findings
