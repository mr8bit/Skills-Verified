import json
from pathlib import Path

from skills_verified.core.models import Grade
from skills_verified.output.badge import generate_badge, save_badge


def test_badge_grade_a():
    result = generate_badge(95, Grade.A)
    assert result["schemaVersion"] == 1
    assert result["label"] == "Trust Score"
    assert result["message"] == "A (95)"
    assert result["color"] == "brightgreen"


def test_badge_grade_b():
    result = generate_badge(85, Grade.B)
    assert result["schemaVersion"] == 1
    assert result["label"] == "Trust Score"
    assert result["message"] == "B (85)"
    assert result["color"] == "green"


def test_badge_grade_c():
    result = generate_badge(70, Grade.C)
    assert result["schemaVersion"] == 1
    assert result["label"] == "Trust Score"
    assert result["message"] == "C (70)"
    assert result["color"] == "yellow"


def test_badge_grade_d():
    result = generate_badge(55, Grade.D)
    assert result["schemaVersion"] == 1
    assert result["label"] == "Trust Score"
    assert result["message"] == "D (55)"
    assert result["color"] == "orange"


def test_badge_grade_f():
    result = generate_badge(30, Grade.F)
    assert result["schemaVersion"] == 1
    assert result["label"] == "Trust Score"
    assert result["message"] == "F (30)"
    assert result["color"] == "red"


def test_save_badge(tmp_path: Path):
    out_path = tmp_path / "badge.json"
    save_badge(95, Grade.A, out_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["schemaVersion"] == 1
    assert data["label"] == "Trust Score"
    assert data["message"] == "A (95)"
    assert data["color"] == "brightgreen"
