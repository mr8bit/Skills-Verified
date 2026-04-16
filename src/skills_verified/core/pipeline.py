import logging
import time
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Finding, Report
from skills_verified.core.scorer import Scorer
from skills_verified.platforms.detector import PlatformDetector

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, analyzers: list[Analyzer]):
        self.analyzers = analyzers
        self.scorer = Scorer()

    def run(self, repo_path: Path, repo_url: str, llm_used: bool = False) -> Report:
        start = time.monotonic()
        all_findings: list[Finding] = []
        used: list[str] = []

        detector = PlatformDetector()
        platforms = detector.detect(repo_path)
        if platforms:
            logger.info("Detected platforms: %s", [p.name for p in platforms])

        for analyzer in self.analyzers:
            if not analyzer.is_available():
                logger.warning("Analyzer %s is not available, skipping", analyzer.name)
                continue
            used.append(analyzer.name)
            try:
                findings = analyzer.analyze(repo_path, platforms=platforms)
                all_findings.extend(findings)
            except Exception:
                logger.exception("Analyzer %s crashed", analyzer.name)

        categories = self.scorer.score_categories(all_findings)
        overall = self.scorer.compute_overall(categories)
        grade = self.scorer.score_to_grade(overall)
        duration = time.monotonic() - start

        return Report(
            repo_url=repo_url,
            overall_score=overall,
            overall_grade=grade,
            categories=categories,
            findings=all_findings,
            analyzers_used=used,
            llm_used=llm_used,
            scan_duration_seconds=round(duration, 2),
        )
