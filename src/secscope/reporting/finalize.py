"""End of a scan: apply suppressions, score, save report.json, update the database."""

from __future__ import annotations

from typing import Any

from secscope.core.orchestrator import ScanOutcome
from secscope.core.scan import score_outcome
from secscope.core.session import ScanSession
from secscope.reporting.json_export import REPORT_FILE, build_report, save_report


def finalize_scan(session: ScanSession, outcome: ScanOutcome) -> dict[str, Any]:
    rules = {r["rule_id"] for r in session.repo.suppressions() if r["rule_id"]}
    ids = {r["finding_id"] for r in session.repo.suppressions() if r["finding_id"]}
    kept = [f for f in outcome.findings if f.rule_id not in rules and f.id not in ids]
    suppressed = len(outcome.findings) - len(kept)
    outcome.findings = kept
    score_outcome(session.ctx, outcome)
    report = build_report(session.ctx, outcome, suppressed=suppressed)
    save_report(report, session.ctx.work_dir / REPORT_FILE)
    session.repo.replace_findings(session.ctx.scan_id, outcome.findings)
    session.repo.finish_scan(session.ctx.scan_id, outcome.status, outcome.scores)
    return report
