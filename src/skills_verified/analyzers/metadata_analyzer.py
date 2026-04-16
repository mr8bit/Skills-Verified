"""Metadata analyzer — detects prompt injection in skill metadata fields,
suspicious author patterns, and deceptive naming conventions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.platforms.base import PlatformProfile, SkillMetadata

# ---------------------------------------------------------------------------
# Prompt injection patterns (same set used across the platform-dependent
# analyzers for consistency)
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

# Suspicious author patterns: random chars, sequential numbers, throwaway
_SUSPICIOUS_AUTHOR_PATTERNS: list[re.Pattern[str]] = [
    # random hex-looking strings (8+ hex chars)
    re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE),
    # sequential digits (12345, 0000, etc.)
    re.compile(r"^\d{4,}$"),
    # user+random digits (user12345, test999)
    re.compile(r"^(user|test|admin|temp|tmp|anon)\d+$", re.IGNORECASE),
    # throwaway-style names
    re.compile(
        r"^(anonymous|unknown|noname|nobody|null|undefined|none|n/a|na|x+)$",
        re.IGNORECASE,
    ),
    # single character repeated
    re.compile(r"^(.)\1{3,}$"),
    # keyboard smash: no vowels in a 5+ char string
    re.compile(r"^[^aeiouAEIOU\d\s]{5,}$"),
]

# Deceptive naming: words that imply trust, combined with skill/plugin
_TRUST_WORDS_RE = re.compile(
    r"\b(safe|security|secure|verify|verified|audit|audited|official|trusted)\b",
    re.IGNORECASE,
)
_SKILL_WORDS_RE = re.compile(
    r"\b(skill|plugin|extension|addon|add-on|module|tool)\b",
    re.IGNORECASE,
)

# Files to scan for injection in repo-level documentation
_DOC_FILENAMES = {"SKILL.md", "README.md"}

_DOC_SCAN_EXTENSIONS = {".md"}


class MetadataAnalyzer(Analyzer):
    name = "metadata"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        if not platforms:
            return []

        all_metadata: list[SkillMetadata] = []
        for platform in platforms:
            meta = platform.get_skill_metadata(repo_path)
            if meta is not None:
                all_metadata.append(meta)

        findings: list[Finding] = []

        if not all_metadata:
            # Even without metadata, still scan doc files for injection
            findings.extend(self._check_doc_files(repo_path))
            return findings if findings else []

        for meta in all_metadata:
            findings.extend(self._check_name_injection(meta))
            findings.extend(self._check_description_injection(meta))
            findings.extend(self._check_suspicious_author(meta))
            findings.extend(self._check_deceptive_naming(meta))

        findings.extend(self._check_doc_files(repo_path))

        return findings

    # ------------------------------------------------------------------
    # Injection in name field
    # ------------------------------------------------------------------

    def _check_name_injection(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        name = meta.name or ""
        if not name:
            return findings

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(name):
                findings.append(Finding(
                    title="Prompt injection in skill name",
                    description=(
                        f"Skill name '{name}' contains a prompt injection "
                        f"pattern: '{pattern.pattern}'. This is a critical "
                        f"attack vector as the name is often included in "
                        f"LLM context."
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.CONFIG_INJECTION,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                ))

        return findings

    # ------------------------------------------------------------------
    # Injection in description field
    # ------------------------------------------------------------------

    def _check_description_injection(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        desc = meta.description or ""
        if not desc:
            return findings

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(desc):
                findings.append(Finding(
                    title="Prompt injection in skill description",
                    description=(
                        f"Skill description contains a prompt injection "
                        f"pattern: '{pattern.pattern}'. "
                        f"Description: {desc[:200]}"
                    ),
                    severity=Severity.CRITICAL,
                    category=Category.CONFIG_INJECTION,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                ))

        return findings

    # ------------------------------------------------------------------
    # Suspicious author patterns
    # ------------------------------------------------------------------

    def _check_suspicious_author(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        author = meta.author or ""
        if not author:
            return findings

        author_stripped = author.strip()
        for pattern in _SUSPICIOUS_AUTHOR_PATTERNS:
            if pattern.search(author_stripped):
                findings.append(Finding(
                    title=f"Suspicious author name: '{author_stripped}'",
                    description=(
                        f"Author name '{author_stripped}' matches a "
                        f"suspicious pattern (random characters, sequential "
                        f"numbers, or throwaway name). This may indicate a "
                        f"throwaway account or automated package."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.CONFIG_INJECTION,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.6,
                ))
                break  # one match per author is enough

        return findings

    # ------------------------------------------------------------------
    # Deceptive naming — trust words + skill/plugin words
    # ------------------------------------------------------------------

    def _check_deceptive_naming(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        name = meta.name or ""
        if not name:
            return findings

        has_trust = _TRUST_WORDS_RE.search(name)
        has_skill = _SKILL_WORDS_RE.search(name)

        if has_trust and has_skill:
            findings.append(Finding(
                title=f"Deceptive skill name: '{name}'",
                description=(
                    f"Skill name '{name}' combines trust-implying words "
                    f"('{has_trust.group()}') with skill/plugin terminology "
                    f"('{has_skill.group()}'). This is a social engineering "
                    f"signal — legitimate tools rarely need to advertise "
                    f"their safety in the name."
                ),
                severity=Severity.MEDIUM,
                category=Category.CONFIG_INJECTION,
                file_path=None,
                line_number=None,
                analyzer=self.name,
                confidence=0.7,
            ))

        return findings

    # ------------------------------------------------------------------
    # Doc file scanning — SKILL.md, README.md
    # ------------------------------------------------------------------

    def _check_doc_files(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for doc_name in _DOC_FILENAMES:
            doc_path = repo_path / doc_name
            if not doc_path.is_file():
                continue
            try:
                content = doc_path.read_text(errors="ignore")
            except OSError:
                continue

            rel_path = str(doc_path.relative_to(repo_path))
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pattern in _INJECTION_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            title=f"Prompt injection in {doc_name}",
                            description=(
                                f"Documentation file {doc_name} contains "
                                f"a prompt injection pattern: "
                                f"'{pattern.pattern}'. "
                                f"Line: {line.strip()[:150]}"
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=rel_path,
                            line_number=line_number,
                            analyzer=self.name,
                        ))

        return findings
