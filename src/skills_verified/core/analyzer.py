from abc import ABC, abstractmethod
from pathlib import Path

from skills_verified.core.models import Finding


class Analyzer(ABC):
    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this analyzer can run (tools installed, etc.)."""

    @abstractmethod
    def analyze(self, repo_path: Path) -> list[Finding]:
        """Run analysis on the repo and return findings."""
