from __future__ import annotations

import pytest

from secscope.analysis.kb import default_kb
from secscope.core.config import ScoreWeights
from secscope.core.models import CodeLocation, Evidence, Finding
from secscope.core.scoring import compute_scores, grade, penalty_score


def f(rule: str, sev: str = "high", conf: str = "high", snippet: str = "x") -> Finding:
    return default_kb().finding(
        rule, module="sast", location=CodeLocation(path="a.py", line=1), evidence=Evidence(snippet=snippet),
        severity=sev, confidence=conf,  # type: ignore[arg-type]
    )  # fmt: skip


def test_empty_is_perfect() -> None:
    assert penalty_score([]) == 100.0


def test_single_penalties() -> None:
    assert penalty_score([f("SAST-SQLI-001", "critical", "confirmed")]) == 75.0
    assert penalty_score([f("SAST-SQLI-001", "high", "high")]) == 92.0
    assert penalty_score([f("SAST-SQLI-001", "medium", "medium")]) == 98.0
    assert penalty_score([f("SAST-SQLI-001", "low", "low")]) == 99.8
    assert penalty_score([f("SAST-SQLI-001", "info", "high")]) == 100.0


def test_repeats_count_a_quarter() -> None:
    items = [f("SAST-SQLI-001", snippet=str(i)) for i in range(5)]
    # 8 + 4 * (8 * 0.25) = 16
    assert penalty_score(items) == 84.0


def test_floor_at_zero() -> None:
    assert (
        penalty_score([f("SAST-SQLI-001", "critical", "confirmed", str(i)) for i in range(200)])
        == 0.0
    )


@pytest.mark.parametrize(
    ("score", "letter"),
    [(100, "A"), (90, "A"), (89.9, "B"), (70, "C"), (60, "D"), (59.9, "F"), (0, "F")],
)
def test_grades(score: float, letter: str) -> None:
    assert grade(score) == letter


def test_sub_scores_and_weight_redistribution() -> None:
    findings = [
        f("SAST-SQLI-001"),
        f("SCA-VULN-001", "critical", "high"),
        f("QUAL-EXCEPT-001", "low", "high"),
    ]
    s = compute_scores(findings, ran=["sast", "sca"])
    assert s.security == 92.0
    assert s.dependencies == 80.0
    assert s.quality == 99.2
    assert s.seo is None
    # security .45, quality .10, dependencies .05 renormalised over 0.60
    assert s.effective_weights == {"security": 0.75, "quality": 0.1667, "dependencies": 0.0833}
    assert s.overall == round(92 * 0.45 / 0.6 + 99.2 * 0.10 / 0.6 + 80 * 0.05 / 0.6, 1)


def test_missing_modules_mean_no_sub_score() -> None:
    s = compute_scores([], ran=["sast"])
    assert s.dependencies is None
    assert s.security == 100.0


def test_confirmed_critical_caps_grade() -> None:
    s = compute_scores(
        [f("SAST-SQLI-001", "critical", "confirmed")], ran=["sast"], seo=100, resilience=100
    )
    assert s.overall is not None
    assert s.overall >= 80
    assert (s.grade, s.grade_capped) == ("D", True)


def test_custom_weights() -> None:
    w = ScoreWeights(security=1.0, seo=0, resilience=0, quality=0, dependencies=0)
    s = compute_scores([f("SAST-SQLI-001")], ran=["sast", "sca"], weights=w)
    assert s.overall == 92.0


def test_dependencies_unmeasured_without_advisory_database() -> None:
    # No advisory DB: "no vulnerable packages found" is not evidence of safety.
    s = compute_scores([], ran=["sast", "sca"], dependencies_measured=False)
    assert s.dependencies is None
    assert "dependencies" not in s.effective_weights
