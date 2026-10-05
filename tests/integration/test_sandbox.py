"""SandboxRunner + run_scan against the real fixtures (SPEC M2 acceptance).

Tests marked ``network`` install dependencies from package registries (pip / npm).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

from secscope.core.config import RunConfig, ScanConfig, Settings, Target, TargetKind
from secscope.core.events import Event, ModuleLog
from secscope.core.orchestrator import Orchestrator, ScanOutcome
from secscope.core.sandbox import SandboxRunner, TargetStartError, build_env
from secscope.core.scan import run_scan
from secscope.core.scope_guard import ScopeGuard, loopback_port_free
from secscope.core.session import open_session
from secscope.modules.base import ScanContext
from tests.fakes import fake_registry

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def scan_fixture(
    tmp_path: Path, fixture: str, *, install: bool = False, accepted: bool = True
) -> tuple[ScanOutcome, ScanContext, list[Event]]:
    config = ScanConfig(
        target=Target(kind=TargetKind.FOLDER, value=str(FIXTURES / fixture)),
        scope_statement_accepted=accepted,
        run=RunConfig(install=install, startup_timeout_s=120),
    )
    session = open_session(config, Settings(data_dir=tmp_path / "data"))
    events: list[Event] = []
    orch = Orchestrator(fake_registry(), events.append)
    try:
        outcome = asyncio.run(run_scan(orch, session.ctx, ["fake_probe"]))
    finally:
        session.close()
    return outcome, session.ctx, events


def logs(events: list[Event]) -> str:
    return "\n".join(e.message for e in events if isinstance(e, ModuleLog))


def assert_stopped(ctx: ScanContext) -> None:
    assert ctx.target is not None
    assert loopback_port_free(ctx.target.port), "port still busy after the scan"


@pytest.mark.parametrize("fixture", ["static-seo-bad", "static-seo-good"])
def test_static_fixture_served_and_stopped(tmp_path: Path, fixture: str) -> None:
    outcome, ctx, events = scan_fixture(tmp_path, fixture)
    assert outcome.module_status == {"prepare": "ok", "fake_probe": "ok", "cleanup": "ok"}, logs(
        events
    )
    assert ctx.results["fake_probe"].data["status"] == 200
    assert ctx.fingerprint is not None
    assert ctx.fingerprint.kind == "static"
    assert_stopped(ctx)


def test_slow_app_started_without_install(tmp_path: Path) -> None:
    outcome, ctx, events = scan_fixture(tmp_path, "slow-app")
    assert outcome.module_status["fake_probe"] == "ok", logs(events)
    assert "slow-app" in ctx.results["fake_probe"].data["body"]
    assert ctx.target is not None
    assert ctx.target.exposed_beyond_loopback == []
    assert_stopped(ctx)


def test_target_not_started_without_scope_statement(tmp_path: Path) -> None:
    outcome, ctx, _ = scan_fixture(tmp_path, "slow-app", accepted=False)
    assert outcome.module_status["fake_probe"] == "skipped"
    assert ctx.target is None
    assert not (ctx.work_dir / "run").exists()  # the user's code was never copied to run


def test_original_project_untouched(tmp_path: Path) -> None:
    before = {p: p.stat().st_mtime_ns for p in (FIXTURES / "slow-app").rglob("*")}
    scan_fixture(tmp_path, "slow-app")
    after = {p: p.stat().st_mtime_ns for p in (FIXTURES / "slow-app").rglob("*")}
    assert before == after


@pytest.mark.network
def test_vuln_flask_with_dependency_install(tmp_path: Path) -> None:
    outcome, ctx, events = scan_fixture(tmp_path, "vuln-flask", install=True)
    assert outcome.module_status["fake_probe"] == "ok", logs(events)
    assert "Vuln Shop" in ctx.results["fake_probe"].data["body"]
    assert_stopped(ctx)
    # The app's SQLite DB was created in the run copy and restored/left there, never in fixtures/.
    assert not (FIXTURES / "vuln-flask" / "shop.db").exists()


@pytest.mark.network
def test_vuln_express_with_npm_ci(tmp_path: Path) -> None:
    outcome, ctx, events = scan_fixture(tmp_path, "vuln-express", install=True)
    assert outcome.module_status["fake_probe"] == "ok", logs(events)
    assert "Vuln Express" in ctx.results["fake_probe"].data["body"]
    assert_stopped(ctx)


def test_start_failure_reports_log_tail(tmp_path: Path) -> None:
    async def scenario() -> TargetStartError:
        runner = SandboxRunner(tmp_path, ScopeGuard())
        try:
            await runner.start(
                [
                    sys.executable,
                    "-c",
                    "print('booting'); print('fatal: missing config'); raise SystemExit(4)",
                ],
                cwd=tmp_path,
                timeout=20,
            )
        except TargetStartError as exc:
            return exc
        finally:
            runner.close()
        raise AssertionError("start should fail")

    exc = asyncio.run(scenario())
    assert "exited with code 4" in str(exc)
    assert "fatal: missing config" in exc.log_tail


def test_ready_timeout(tmp_path: Path) -> None:
    async def scenario() -> None:
        runner = SandboxRunner(tmp_path, ScopeGuard())
        try:
            with pytest.raises(TargetStartError, match="did not become ready"):
                await runner.start(
                    [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout=1.5
                )
        finally:
            runner.close()

    asyncio.run(scenario())


def test_env_whitelist_drops_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_real")
    env = build_env({"APP_MODE": "test", "LISTEN": "{host}:{port}"}, port=4321)
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["PORT"] == "4321"
    assert env["HOST"] == "127.0.0.1"
    assert env["LISTEN"] == "127.0.0.1:4321"
    assert env["APP_MODE"] == "test"
    if os.name == "nt":
        assert "SYSTEMROOT" in {k.upper() for k in env}
