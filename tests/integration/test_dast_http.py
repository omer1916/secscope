"""dast_http against a real (loopback) misconfigured server, and the scope-statement gate."""

from __future__ import annotations

import asyncio
from pathlib import Path

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.models import Finding, HttpLocation
from secscope.core.orchestrator import Orchestrator
from secscope.core.scope_guard import ScopeGuard
from secscope.core.toolmgr import Manifest, ToolManager
from secscope.modules.base import LogLevel, ScanContext
from secscope.modules.dast_http import DastHttpModule
from secscope.modules.registry import ModuleRegistry
from tests.helpers.insecure_server import insecure_server


class Collector:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def progress(self, pct: float, message: str = "") -> None: ...
    def log(self, message: str, level: LogLevel = "info") -> None: ...
    def metric(self, series: str, values: dict[str, float]) -> None: ...
    def finding(self, finding: Finding) -> None:
        self.findings.append(finding)


def _ctx(tmp_path: Path, target_url: str) -> ScanContext:
    return ScanContext(
        scan_id="dast-test",
        config=ScanConfig(
            target=Target(kind=TargetKind.URL, value=target_url),
            scope_statement_accepted=True,
        ),
        settings=Settings(data_dir=tmp_path),
        work_dir=tmp_path,
        guard=ScopeGuard(),
        tools=ToolManager(Manifest.load(), tmp_path / "tools"),
        target_url=target_url,
    )


def _scan(tmp_path: Path) -> list[Finding]:
    with insecure_server() as url:
        ctx = _ctx(tmp_path, url)
        emit = Collector()
        asyncio.run(DastHttpModule().run(ctx, emit))
        return emit.findings


def test_misconfigured_server_is_flagged(tmp_path: Path) -> None:
    rules = {f.rule_id for f in _scan(tmp_path)}
    # headers, version, cookie, CORS, TRACE, directory listing is only on /files/ (not crawled),
    # exposed .env, error page, plain HTTP.
    assert {
        "DAST-CSP-001",
        "DAST-HEADERS-001",
        "DAST-SERVER-001",
        "DAST-HTTPS-001",
        "DAST-COOKIE-001",
        "DAST-CORS-001",
        "DAST-METHOD-001",
        "DAST-EXPOSED-001",
        "DAST-ERRLEAK-001",
    } <= rules


def test_findings_are_on_the_target_and_masked(tmp_path: Path) -> None:
    findings = _scan(tmp_path)
    cors = next(f for f in findings if f.rule_id == "DAST-CORS-001")
    assert cors.location.kind == "http"
    assert cors.severity == "high"
    exposed = next(f for f in findings if f.rule_id == "DAST-EXPOSED-001")
    # the exposed-file path is reported; the leaked secret value is never echoed
    assert "/.env" in exposed.location.display()
    assert "hunter2" not in str(exposed.evidence.model_dump())


def test_finding_ids_are_stable_across_ports(tmp_path: Path) -> None:
    first = {f.id for f in _scan(tmp_path / "a")}
    second = {f.id for f in _scan(tmp_path / "b")}  # a different random port
    assert first == second


def test_scope_statement_gates_the_module(tmp_path: Path) -> None:
    with insecure_server() as url:
        ctx = ScanContext(
            scan_id="g",
            config=ScanConfig(
                target=Target(kind=TargetKind.URL, value=url),
                scope_statement_accepted=False,  # not accepted
            ),
            settings=Settings(data_dir=tmp_path),
            work_dir=tmp_path,
            guard=ScopeGuard(),
            tools=ToolManager(Manifest.load(), tmp_path / "tools"),
            target_url=url,
        )
        events: list[object] = []
        orch = Orchestrator(_registry(), events.append)
        asyncio.run(orch.run(ctx, ["dast_http"]))
        assert ctx.results.get("dast_http") is None
        assert any(type(e).__name__ == "ModuleSkipped" for e in events)


def _registry() -> ModuleRegistry:
    return ModuleRegistry([DastHttpModule])


def test_reflection_verification_finds_xss_ssti_and_open_redirect(tmp_path: Path) -> None:
    rules = {f.rule_id for f in _scan(tmp_path)}
    assert {"DAST-XSS-001", "DAST-SSTI-001", "DAST-REDIRECT-001"} <= rules


def test_reflection_findings_name_the_parameter(tmp_path: Path) -> None:
    findings = _scan(tmp_path)

    def params(rule: str) -> set[str | None]:
        return {
            f.location.parameter
            for f in findings
            if f.rule_id == rule and isinstance(f.location, HttpLocation)
        }

    assert "name" in params("DAST-XSS-001")  # /hello reflects it unescaped
    assert params("DAST-SSTI-001") == {"q"}  # /tmpl evaluates {{7*9}}
    assert params("DAST-REDIRECT-001") == {"next"}  # /go follows ?next
    xss = next(f for f in findings if f.rule_id == "DAST-XSS-001")
    assert xss.severity == "high"
    ssti = next(f for f in findings if f.rule_id == "DAST-SSTI-001")
    assert ssti.severity == "critical"
