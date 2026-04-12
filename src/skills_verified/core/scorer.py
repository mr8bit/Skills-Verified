from skills_verified.core.models import (
    Category, CategoryScore, Finding, Grade, Severity,
)

SEVERITY_PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


class Scorer:
    def score_to_grade(self, score: int) -> Grade:
        if score >= 90:
            return Grade.A
        if score >= 80:
            return Grade.B
        if score >= 65:
            return Grade.C
        if score >= 50:
            return Grade.D
        return Grade.F

    def score_categories(self, findings: list[Finding]) -> list[CategoryScore]:
        result = []
        for category in Category:
            cat_findings = [f for f in findings if f.category == category]
            penalty = sum(SEVERITY_PENALTIES[f.severity] for f in cat_findings)
            score = max(0, 100 - penalty)
            result.append(CategoryScore(
                category=category,
                score=score,
                grade=self.score_to_grade(score),
                findings_count=len(cat_findings),
                critical_count=sum(
                    1 for f in cat_findings if f.severity == Severity.CRITICAL
                ),
                high_count=sum(
                    1 for f in cat_findings if f.severity == Severity.HIGH
                ),
            ))
        return result

    def compute_overall(self, categories: list[CategoryScore]) -> int:
        if not categories:
            return 100
        return round(sum(c.score for c in categories) / len(categories))
