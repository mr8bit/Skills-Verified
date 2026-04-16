from skills_verified.cli import GRADE_ORDER, check_threshold
from skills_verified.core.models import Grade


def test_no_threshold_passes():
    assert check_threshold(score=30, grade=Grade.F, threshold=None, threshold_grade=None) is True


def test_score_threshold_passes():
    assert check_threshold(score=80, grade=Grade.A, threshold=70, threshold_grade=None) is True


def test_score_threshold_fails():
    assert check_threshold(score=60, grade=Grade.A, threshold=70, threshold_grade=None) is False


def test_score_threshold_exact_boundary_passes():
    assert check_threshold(score=70, grade=Grade.A, threshold=70, threshold_grade=None) is True


def test_grade_threshold_passes():
    assert check_threshold(score=100, grade=Grade.B, threshold=None, threshold_grade="C") is True


def test_grade_threshold_exact_match_passes():
    assert check_threshold(score=100, grade=Grade.C, threshold=None, threshold_grade="C") is True


def test_grade_threshold_fails():
    assert check_threshold(score=100, grade=Grade.F, threshold=None, threshold_grade="C") is False


def test_both_thresholds_both_pass():
    assert check_threshold(score=90, grade=Grade.A, threshold=70, threshold_grade="B") is True


def test_both_thresholds_score_fails():
    assert check_threshold(score=60, grade=Grade.C, threshold=70, threshold_grade="D") is False


def test_both_thresholds_grade_fails():
    assert check_threshold(score=80, grade=Grade.D, threshold=50, threshold_grade="C") is False
