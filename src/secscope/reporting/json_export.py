"""The canonical report document (``report.json``, schema-versioned, SPEC §11.1).

Every other format (HTML, SARIF, CSV, PDF, diff) is rendered from this dict, so a report
can be re-rendered later with ``secscope report <scan_id>`` without re-scanning.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscope.__about__ import __app_name__, __version__
from secscope.core.jsonutil import jdict
from secscope.core.models import SCHEMA_VERSION, Finding
from secscope.core.orchestrator import ScanOutcome
from secscope.core.redact import redact
from secscope.modules.base import ScanContext
from secscope.reporting.plan import fix_plan

REPORT_SCHEMA_VERSION = 2
REPORT_FILE = "report.json"
MAX_GENERATED_BYTES = 200_000


def build_report(ctx: ScanContext, outcome: ScanOutcome, *, suppressed: int = 0) -> dict[str, Any]:
    config = ctx.config
    seo_result = ctx.results.get("seo")
    seo: dict[str, Any] | None = None
    if seo_result is not None and "seo_score" in seo_result.data:
        generated: dict[str, str] = {}
        for name, path in jdict(seo_result.data.get("generated")).items():
            p = Path(str(path))
            if p.is_file() and p.stat().st_size <= MAX_GENERATED_BYTES:
                generated[name] = p.read_text(encoding="utf-8")
        seo = {
            "score": seo_result.data["seo_score"],
            "production_origin": seo_result.data.get("production_origin"),
            "pages": seo_result.data.get("pages", []),
            "generated": generated,
        }
    sca = ctx.results.get("sca")
    sast = ctx.results.get("sast")
    fp = ctx.fingerprint
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "finding_schema_version": SCHEMA_VERSION,
        "tool": {"name": __app_name__, "version": __version__},
        "scan_id": ctx.scan_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "language": ctx.settings.language,
        "target": {
            "kind": config.target.kind.value,
            "value": redact(config.target.value),
            "url": ctx.target_url,
        },
        "stack": {
            "name": fp.stack,
            "family": fp.stack_family,
            "languages": fp.languages,
            "dev_server": fp.dev_server,
        }
        if fp
        else None,
        "profile": config.profile.value,
        "revision": ctx.revision,
        "coverage": ctx.coverage or None,
        "changed_since": config.changed_since,
        "scope_statement_accepted": config.scope_statement_accepted,
        "status": outcome.status,
        "duration_s": round(outcome.duration_s, 3),
        "modules": outcome.module_info,
        "notes": outcome.notes,
        "tool_versions": outcome.tool_versions,
        "scores": outcome.scores,
        "suppressed": suppressed,
        "fix_plan": [item.as_dict() for item in fix_plan(outcome.findings)],
        "seo": seo,
        "sbom_path": sca.data.get("sbom_path") if sca is not None else None,
        "attack_surface": {
            "summary": sast.data.get("routes_summary"),
            "routes": sast.data.get("routes", []),
        }
        if sast is not None and "routes" in sast.data
        else None,
        "advisory_db": {
            k: v for k, v in (sca.data if sca else {}).items() if k.endswith("_db_updated")
        },
        "findings": [f.model_dump(mode="json") for f in outcome.findings],
    }


def save_report(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_report(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("report_schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError(f"unsupported report schema in {path}")
    return data


def report_findings(report: dict[str, Any]) -> list[Finding]:
    return [Finding.model_validate(f) for f in report.get("findings", [])]
