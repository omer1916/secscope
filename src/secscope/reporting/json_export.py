"""Full JSON export of a scan (schema-versioned, SPEC §11.1)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscope.__about__ import __app_name__, __version__
from secscope.core.config import ScanConfig
from secscope.core.models import SCHEMA_VERSION
from secscope.core.orchestrator import ScanOutcome
from secscope.core.redact import redact

REPORT_SCHEMA_VERSION = 1


def build_json_report(scan_id: str, config: ScanConfig, outcome: ScanOutcome) -> dict[str, Any]:
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "finding_schema_version": SCHEMA_VERSION,
        "tool": {"name": __app_name__, "version": __version__},
        "scan_id": scan_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {"kind": config.target.kind.value, "value": redact(config.target.value)},
        "profile": config.profile.value,
        "scope_statement_accepted": config.scope_statement_accepted,
        "status": outcome.status,
        "duration_s": round(outcome.duration_s, 3),
        "modules": outcome.module_status,
        "findings": [f.model_dump(mode="json") for f in outcome.findings],
    }


def write_json_report(
    out_dir: Path, scan_id: str, config: ScanConfig, outcome: ScanOutcome
) -> Path:
    path = out_dir / f"secscope-{scan_id}.json"
    data = build_json_report(scan_id, config, outcome)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
