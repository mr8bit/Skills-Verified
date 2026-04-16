import logging
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts"}

# Maps permission category -> list of compiled regex patterns that indicate usage.
PERMISSION_PATTERNS: dict[str, list[re.Pattern]] = {
    "network": [
        re.compile(r"\brequests\."),
        re.compile(r"\burllib\."),
        re.compile(r"\bhttpx\."),
        re.compile(r"\bfetch\s*\("),
        re.compile(r"\bsocket\.socket\b"),
        re.compile(r"\bhttp\.client\b"),
    ],
    "filesystem": [
        re.compile(r"\bopen\s*\("),
        re.compile(r"\bPath\s*\("),
        re.compile(r"\bos\.path\b"),
        re.compile(r"\bshutil\."),
        re.compile(r"\bos\.remove\b"),
        re.compile(r"\bos\.unlink\b"),
        re.compile(r"\bos\.mkdir\b"),
        re.compile(r"\bos\.makedirs\b"),
        re.compile(r"\bos\.rename\b"),
    ],
    "shell": [
        re.compile(r"\bsubprocess\."),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bos\.popen\s*\("),
        re.compile(r"\bos\.exec"),
    ],
    "process": [
        re.compile(r"\bos\.kill\s*\("),
        re.compile(r"\bos\.fork\s*\("),
        re.compile(r"\bsignal\."),
        re.compile(r"\bmultiprocessing\."),
    ],
    "env": [
        re.compile(r"\bos\.environ\b"),
        re.compile(r"\bos\.getenv\b"),
        re.compile(r"\bdotenv\b"),
    ],
}

DANGEROUS_COMBINATION = {"network", "shell", "filesystem"}


class PrivilegeAnalyzer(Analyzer):
    name = "privilege"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        platforms = kwargs.get("platforms") or []

        # Collect SkillMetadata objects from platforms.
        all_metadata = []
        for platform in platforms:
            if hasattr(platform, "permissions_declared"):
                all_metadata.append(platform)

        if not all_metadata:
            return []

        # Check each skill's declared permissions against actual code usage.
        findings: list[Finding] = []
        for metadata in all_metadata:
            declared = set(metadata.permissions_declared or [])
            if not declared:
                # Cannot compare without declarations.
                continue

            # Determine entry points to scan.  If the metadata provides
            # specific entry points, scan those; otherwise scan the entire
            # repo for the supported extensions.
            entry_points = getattr(metadata, "entry_points", None) or []
            files_to_scan = self._collect_files(repo_path, entry_points)

            # Detect actual permission usage across scanned files.
            detected = self._detect_permissions(files_to_scan, repo_path)

            detected_categories = set(detected.keys())
            skill_name = getattr(metadata, "name", None) or "unknown"

            # Undeclared access: code uses permission not listed in declared.
            for perm in sorted(detected_categories - declared):
                sample_files = detected[perm][:3]
                sample_desc = ", ".join(sample_files)
                findings.append(Finding(
                    title=f"Undeclared permission usage: {perm}",
                    description=(
                        f"Skill '{skill_name}' uses '{perm}' capabilities but does not "
                        f"declare this permission. Detected in: {sample_desc}."
                    ),
                    severity=Severity.HIGH,
                    category=Category.PERMISSIONS,
                    file_path=sample_files[0] if sample_files else None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.9,
                ))

            # Over-privilege: declared but not actually used.
            for perm in sorted(declared - detected_categories):
                findings.append(Finding(
                    title=f"Over-privileged declaration: {perm}",
                    description=(
                        f"Skill '{skill_name}' declares '{perm}' permission but "
                        f"no matching code patterns were detected. Consider removing "
                        f"the unnecessary permission declaration."
                    ),
                    severity=Severity.LOW,
                    category=Category.PERMISSIONS,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.7,
                ))

            # Dangerous combination: network + shell + filesystem all used.
            if DANGEROUS_COMBINATION.issubset(detected_categories):
                findings.append(Finding(
                    title="Dangerous permission combination detected",
                    description=(
                        f"Skill '{skill_name}' uses network, shell, and filesystem "
                        f"permissions together. This combination enables download-and-execute "
                        f"attack patterns and warrants careful review."
                    ),
                    severity=Severity.HIGH,
                    category=Category.PERMISSIONS,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.85,
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_files(
        self,
        repo_path: Path,
        entry_points: list[Path],
    ) -> list[Path]:
        """Collect files to scan for permission patterns."""
        files: list[Path] = []

        if entry_points:
            for ep in entry_points:
                full = repo_path / ep
                if full.is_file() and full.suffix in SCAN_EXTENSIONS:
                    files.append(full)
                elif full.is_dir():
                    for f in full.rglob("*"):
                        if f.is_file() and f.suffix in SCAN_EXTENSIONS:
                            files.append(f)

        # Always also scan the whole repo to catch transitive usage.
        if not files:
            for f in repo_path.rglob("*"):
                if f.is_file() and f.suffix in SCAN_EXTENSIONS:
                    # Skip .git internals.
                    try:
                        rel = f.relative_to(repo_path)
                    except ValueError:
                        continue
                    if rel.parts and rel.parts[0] == ".git":
                        continue
                    files.append(f)

        return files

    def _detect_permissions(
        self,
        files: list[Path],
        repo_path: Path,
    ) -> dict[str, list[str]]:
        """Scan files and return a mapping of detected permission -> list of relative file paths."""
        detected: dict[str, list[str]] = {}

        for file_path in files:
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue

            try:
                rel_str = str(file_path.relative_to(repo_path))
            except ValueError:
                rel_str = str(file_path)

            for perm_name, patterns in PERMISSION_PATTERNS.items():
                for pat in patterns:
                    if pat.search(content):
                        detected.setdefault(perm_name, [])
                        if rel_str not in detected[perm_name]:
                            detected[perm_name].append(rel_str)
                        break  # One match per permission category per file suffices.

        return detected
