"""Fix plan (SPEC §11.1): group findings by rule and order them by impact ÷ effort.

Impact uses the same weights as the score (severity × confidence), summed over a rule's
findings with the repeat discount, so fixing one rule everywhere ("all security headers in
one patch") is a single action. Quick wins (high impact, small effort) come first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secscope.core.models import SEVERITY_ORDER, Finding, max_severity
from secscope.core.scoring import CONFIDENCE_FACTOR, REPEAT_FACTOR, SEVERITY_PENALTY

EFFORT_COST = {"S": 1.0, "M": 2.0, "L": 4.0}


@dataclass
class PlanItem:
    rule_id: str
    title_tr: str
    title_en: str
    severity: str
    effort: str
    count: int
    impact: float
    priority: float
    finding_ids: list[str] = field(default_factory=list[str])

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": {"tr": self.title_tr, "en": self.title_en},
            "severity": self.severity,
            "effort": self.effort,
            "count": self.count,
            "impact": round(self.impact, 2),
            "priority": round(self.priority, 2),
            "finding_ids": self.finding_ids,
        }


def fix_plan(findings: list[Finding]) -> list[PlanItem]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.severity != "info":
            groups.setdefault(f.rule_id, []).append(f)
    items: list[PlanItem] = []
    for rule_id, group in groups.items():
        weights = sorted(
            (SEVERITY_PENALTY[f.severity] * CONFIDENCE_FACTOR[f.confidence] for f in group),
            reverse=True,
        )
        impact = weights[0] + REPEAT_FACTOR * sum(weights[1:])
        effort = group[0].effort
        rep = max(group, key=lambda f: SEVERITY_ORDER[f.severity])
        items.append(
            PlanItem(
                rule_id=rule_id,
                title_tr=rep.title.tr,
                title_en=rep.title.en,
                severity=max_severity([f.severity for f in group]),
                effort=effort,
                count=len(group),
                impact=impact,
                priority=impact / EFFORT_COST[effort],
                finding_ids=[f.id for f in group],
            )
        )
    return sorted(items, key=lambda i: (-i.priority, -SEVERITY_ORDER[i.severity], i.rule_id))  # type: ignore[index]
