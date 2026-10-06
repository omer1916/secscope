"""Transparent, reproducible scores (SPEC §9). The formulas are documented in docs/scoring.md.

Penalty score (security, dependencies, quality): start at 100 and subtract, per finding,
``severity_weight × confidence_multiplier``; repeated findings of the same rule_id count
25 % after the first; floor 0. A confirmed critical finding caps the letter grade at D.

SEO and resilience scores are produced by their modules (M6/M7) and passed in.
The overall score is the weighted mean of the available sub-scores; weights of
missing sub-scores are redistributed proportionally (reported as such). With no
sub-score at all there is no overall score (grade "–").
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from secscope.core.config import ScoreWeights
from secscope.core.models import Category, Confidence, Finding, Severity

SEVERITY_PENALTY: dict[Severity, float] = {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}
CONFIDENCE_FACTOR: dict[Confidence, float] = {
    "confirmed": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
}
REPEAT_FACTOR = 0.25
# Sub-scores a module of this build can produce, in display order. Resilience needs load
# testing, which this build does not include (ADR-009); its weight is redistributed.
DISPLAYED_SUBSCORES = ("security", "seo", "quality", "dependencies")
GRADES: tuple[tuple[float, str], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


def grade(score: float) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


def penalty_score(findings: Iterable[Finding]) -> float:
    seen: set[str] = set()
    total = 0.0
    # Count the most severe instance of each rule at full weight.
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_PENALTY[f.severity] * CONFIDENCE_FACTOR[f.confidence], f.id),
    )
    for f in ordered:
        p = SEVERITY_PENALTY[f.severity] * CONFIDENCE_FACTOR[f.confidence]
        total += p if f.rule_id not in seen else p * REPEAT_FACTOR
        seen.add(f.rule_id)
    return max(0.0, round(100.0 - total, 1))


def _is_dependency(f: Finding) -> bool:
    return f.rule_id.startswith("SCA-")


@dataclass
class Scores:
    security: float | None = None
    dependencies: float | None = None
    quality: float | None = None
    seo: float | None = None
    resilience: float | None = None
    # None (grade "–") when no sub-score was measured: nothing measured is not an "A".
    overall: float | None = None
    grade: str = "–"
    grade_capped: bool = False
    effective_weights: dict[str, float] = field(default_factory=dict[str, float])

    def as_dict(self) -> dict[str, object]:
        return {
            "overall": self.overall,
            "grade": self.grade,
            "grade_capped": self.grade_capped,
            "security": self.security,
            "dependencies": self.dependencies,
            "quality": self.quality,
            "seo": self.seo,
            "resilience": self.resilience,
            "effective_weights": self.effective_weights,
        }


def compute_scores(
    findings: list[Finding],
    *,
    weights: ScoreWeights | None = None,
    ran: Iterable[str] = (),
    seo: float | None = None,
    resilience: float | None = None,
    dependencies_measured: bool = True,
) -> Scores:
    """``ran``: module ids that actually ran — a sub-score exists only if a contributing module ran.

    ``dependencies_measured=False`` (no advisory database) leaves the dependency score empty:
    an absent measurement is not a clean result.
    """
    weights = weights or ScoreWeights()
    ran_set = set(ran)
    security_modules = {
        "sast",
        "secrets",
        "config_audit",
        "dast_native",
        "dast_zap",
        "dast_nuclei",
        "browser",
    }
    s = Scores(seo=seo, resilience=resilience)
    if ran_set & security_modules:
        s.security = penalty_score(
            f for f in findings if f.category == Category.SECURITY and not _is_dependency(f)
        )
    if "sca" in ran_set and dependencies_measured:
        s.dependencies = penalty_score(
            f for f in findings if _is_dependency(f) and f.category == Category.SECURITY
        )
    if ran_set & {"sast", "browser"}:
        s.quality = penalty_score(f for f in findings if f.category == Category.QUALITY)

    parts = {
        "security": (s.security, weights.security),
        "seo": (s.seo, weights.seo),
        "resilience": (s.resilience, weights.resilience),
        "quality": (s.quality, weights.quality),
        "dependencies": (s.dependencies, weights.dependencies),
    }
    available = {k: (v, w) for k, (v, w) in parts.items() if v is not None and w > 0}
    total_w = sum(w for _, w in available.values())
    if total_w > 0:
        s.effective_weights = {k: round(w / total_w, 4) for k, (_, w) in available.items()}
        s.overall = round(sum(v * w for v, w in available.values()) / total_w, 1)  # type: ignore[operator]
    if s.overall is None:
        return s
    s.grade = grade(s.overall)
    confirmed_critical = any(
        f.severity == "critical" and f.confidence == "confirmed" for f in findings
    )
    if confirmed_critical and s.grade in {"A", "B", "C"}:
        s.grade, s.grade_capped = "D", True
    return s
