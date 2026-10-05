"""Shared helpers for detection-rate tests against fixtures/*/expected.yaml (SPEC §12)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secscope.core.advisories import osv_status, trivy_status
from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.models import Finding
from secscope.core.orchestrator import Orchestrator, ScanOutcome
from secscope.core.scan import run_scan
from secscope.core.session import open_session, tool_manager
from secscope.core.toolmgr import ToolManager
from secscope.modules.registry import load_builtin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
STATIC_MODULES = ["sast", "secrets", "sca", "config_audit"]


def expected(fixture: str) -> dict[str, Any]:
    return yaml.safe_load((FIXTURES / fixture / "expected.yaml").read_text(encoding="utf-8"))


def found_rules(findings: list[Finding]) -> set[str]:
    rules = {f.rule_id for f in findings}
    for f in findings:
        related = f.evidence.extra.get("related_rules", "")
        rules |= {r.strip() for r in related.split(",") if r.strip()}
    return rules


def real_tools() -> ToolManager:
    """Tools from the developer's real data dir (managed binaries + offline DBs)."""
    return tool_manager(Settings())


def vulnerability_db_present() -> bool:
    data_dir = Settings().data_dir
    return trivy_status(data_dir).present or osv_status(data_dir).present


@dataclass
class StaticRun:
    outcome: ScanOutcome
    findings: list[Finding] = field(default_factory=list[Finding])


def run_static(fixture: str, scratch: Path) -> StaticRun:
    real = Settings()
    # The scan's work dir and database live in a scratch dir; tool binaries and the
    # offline advisory databases come from the developer's real data dir.
    settings = real.model_copy(update={"data_dir": scratch})
    config = ScanConfig(target=Target(kind=TargetKind.FOLDER, value=str(FIXTURES / fixture)))
    session = open_session(config, settings, tools=real_tools())
    # SCA reads its databases from settings.data_dir: point it at the real one.
    session.ctx.settings = real
    try:
        outcome = asyncio.run(
            run_scan(Orchestrator(load_builtin(), lambda _e: None), session.ctx, STATIC_MODULES)
        )
    finally:
        session.close()
    return StaticRun(outcome=outcome, findings=outcome.findings)
