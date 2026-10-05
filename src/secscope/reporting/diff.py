"""Compare two scans (SPEC §11.1): new / fixed / persistent / regressed findings by stable id."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secscope.core.jsonutil import jdict
from secscope.core.models import SEVERITY_ORDER, Finding
from secscope.reporting.json_export import report_findings


@dataclass
class ScanDiff:
    new: list[Finding] = field(default_factory=list[Finding])
    fixed: list[Finding] = field(default_factory=list[Finding])
    persistent: list[Finding] = field(default_factory=list[Finding])
    # Same finding, now more severe (or a confidence upgrade to confirmed).
    regressed: list[tuple[Finding, Finding]] = field(default_factory=list[tuple[Finding, Finding]])
    score_delta: dict[str, float | None] = field(default_factory=dict[str, float | None])

    def summary(self) -> dict[str, Any]:
        new_high = sum(1 for f in self.new if f.severity in {"critical", "high"})
        return {
            "new": len(self.new),
            "new_critical_or_high": new_high,
            "fixed": len(self.fixed),
            "persistent": len(self.persistent),
            "regressed": len(self.regressed),
            "score_delta": self.score_delta,
        }


def diff_reports(before: dict[str, Any], after: dict[str, Any]) -> ScanDiff:
    old = {f.id: f for f in report_findings(before)}
    new = {f.id: f for f in report_findings(after)}
    d = ScanDiff()
    for fid, f in new.items():
        if fid not in old:
            d.new.append(f)
            continue
        prev = old[fid]
        worse = SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[prev.severity] or (
            f.confidence == "confirmed" and prev.confidence != "confirmed"
        )
        if worse:
            d.regressed.append((prev, f))
        else:
            d.persistent.append(f)
    d.fixed = [f for fid, f in old.items() if fid not in new]
    for key in ("overall", "security", "seo", "resilience", "quality", "dependencies"):
        a = jdict(before.get("scores")).get(key)
        b = jdict(after.get("scores")).get(key)
        d.score_delta[key] = (
            round(b - a, 1) if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None
        )

    def order(f: Finding) -> tuple[int, str]:
        return (-SEVERITY_ORDER[f.severity], f.rule_id)

    d.new.sort(key=order)
    d.fixed.sort(key=order)
    d.persistent.sort(key=order)
    return d
