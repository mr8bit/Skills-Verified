import json
from pathlib import Path

from skills_verified.core.models import Grade

_GRADE_COLORS: dict[Grade, str] = {
    Grade.A: "brightgreen",
    Grade.B: "green",
    Grade.C: "yellow",
    Grade.D: "orange",
    Grade.F: "red",
}


def generate_badge(score: int, grade: Grade) -> dict:
    return {
        "schemaVersion": 1,
        "label": "Trust Score",
        "message": f"{grade.value} ({score})",
        "color": _GRADE_COLORS[grade],
    }


def save_badge(score: int, grade: Grade, path: Path) -> None:
    data = generate_badge(score, grade)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
