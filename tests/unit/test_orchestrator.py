from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import psutil
import pytest

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.events import (
    ErrorEvent,
    Event,
    FindingEvent,
    ModuleFinished,
    ModuleSkipped,
    ModuleStarted,
    ScanFinished,
    ScanStarted,
    ScopeViolationEvent,
)
from secscope.core.orchestrator import Orchestrator, dependency_layers
from secscope.core.scope_guard import ScopeGuard
from secscope.core.toolmgr import Manifest, ToolManager
from secscope.modules.base import ScanContext
from tests.fakes import ProcessModule, fake_registry

TEST_MANIFEST = Manifest.from_dict(
    {
        "schema": 1,
        "tools": {
            "nonexistent_tool": {
                "kind": "system",
                "commands": ["secscope-definitely-missing-binary"],
                "version_args": ["--version"],
                "version_regex": r"(\d+)",
                "min_version": "1",
                "install_hint": {"tr": "kurun", "en": "install it"},
            }
        },
    }
)


def make_ctx(
    tmp_path: Path, *, accepted: bool = True, target: str | None = "http://localhost:9/"
) -> ScanContext:
    config = ScanConfig(
        target=Target(kind=TargetKind.URL, value="http://localhost:9/"),
        scope_statement_accepted=accepted,
    )
    return ScanContext(
        scan_id="scan-test",
        config=config,
        settings=Settings(data_dir=tmp_path),
        work_dir=tmp_path,
        guard=ScopeGuard(),
        tools=ToolManager(TEST_MANIFEST, tmp_path / "tools"),
        target_url=target,
    )


def run_scan(ctx: ScanContext, modules: list[str]) -> tuple[list[Event], Orchestrator]:
    events: list[Event] = []
    orch = Orchestrator(fake_registry(), events.append)
    asyncio.run(orch.run(ctx, modules))
    return events, orch


def by_type[T](events: list[Event], cls: type[T]) -> list[T]:
    return [e for e in events if isinstance(e, cls)]


def test_happy_path_event_sequence(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_dependent", "fake_fast"])
    assert isinstance(events[0], ScanStarted)
    assert isinstance(events[-1], ScanFinished)
    assert events[-1].status == "completed"
    started = [e.module for e in by_type(events, ModuleStarted)]
    assert started == ["fake_fast", "fake_dependent"]  # dependency order
    assert len(by_type(events, FindingEvent)) == 3
    finished = {e.module: e for e in by_type(events, ModuleFinished)}
    assert finished["fake_fast"].finding_count == 3
    assert all(e.status == "ok" for e in finished.values())


def test_results_flow_downstream(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    run_scan(ctx, ["fake_fast", "fake_dependent"])
    assert ctx.results["fake_dependent"].data["seen"] == ["http://localhost/a"]


def test_missing_tool_is_skipped_with_hint(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_needs_tool", "fake_fast"])
    skipped = by_type(events, ModuleSkipped)
    assert [s.module for s in skipped] == ["fake_needs_tool"]
    assert skipped[0].install_hint is not None
    assert skipped[0].install_hint.en == "install it"
    assert events[-1].status == "completed"  # type: ignore[union-attr]


def test_dynamic_module_requires_scope_statement(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path, accepted=False), ["fake_dynamic"])
    skipped = by_type(events, ModuleSkipped)
    assert skipped
    assert "Scope statement" in skipped[0].reason.en


def test_dynamic_module_requires_target(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path, target=None), ["fake_dynamic"])
    assert by_type(events, ModuleSkipped)[0].reason.en == "No running target."


def test_source_module_requires_source(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_source"])
    assert by_type(events, ModuleSkipped)[0].module == "fake_source"


def test_scope_violation_reported_with_module(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_dynamic"])
    violations = by_type(events, ScopeViolationEvent)
    assert len(violations) == 1
    assert violations[0].module == "fake_dynamic"
    assert violations[0].url == "http://example.com/"


def test_failure_is_isolated_and_secret_masked(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_failing", "fake_fast"])
    finished = {e.module: e.status for e in by_type(events, ModuleFinished)}
    assert finished == {"fake_failing": "failed", "fake_fast": "ok"}
    errors = by_type(events, ErrorEvent)
    assert errors
    assert all("hunter2hunter2" not in (e.message + (e.detail or "")) for e in errors)


def test_timeout(tmp_path: Path) -> None:
    events, _ = run_scan(make_ctx(tmp_path), ["fake_timeout"])
    assert by_type(events, ModuleFinished)[0].status == "timeout"


def test_unknown_module_rejected(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        run_scan(make_ctx(tmp_path), ["nope"])


def test_dependency_cycle_detected() -> None:
    from tests.fakes import DependentModule, FastModule  # noqa: PLC0415

    class Cyclic(FastModule):
        depends_on = ("fake_dependent",)

    with pytest.raises(ValueError, match="cycle"):
        dependency_layers([Cyclic(), DependentModule()])


def test_pause_and_resume(tmp_path: Path) -> None:
    async def scenario() -> list[Event]:
        events: list[Event] = []
        ctx = make_ctx(tmp_path)
        orch = Orchestrator(fake_registry(), events.append)
        task = asyncio.create_task(orch.run(ctx, ["fake_slow"]))
        await asyncio.sleep(0.3)
        orch.pause()
        await asyncio.sleep(0.1)
        count = len(events)
        await asyncio.sleep(0.4)
        assert len(events) == count, "no progress while paused"
        orch.resume()
        await asyncio.sleep(0.3)
        assert len(events) > count
        orch.cancel()
        await task
        return events

    events = asyncio.run(scenario())
    assert events[-1].status == "cancelled"  # type: ignore[union-attr]


def test_cancel_kills_process_tree_and_frees_port(tmp_path: Path) -> None:
    ProcessModule.started.clear()

    async def scenario() -> list[Event]:
        events: list[Event] = []
        orch = Orchestrator(fake_registry(), events.append)
        task = asyncio.create_task(orch.run(make_ctx(tmp_path), ["fake_process", "fake_fast"]))
        for _ in range(100):
            if ProcessModule.started:
                break
            await asyncio.sleep(0.05)
        orch.cancel()
        await asyncio.wait_for(task, 20)
        return events

    events = asyncio.run(scenario())
    assert events[-1].status == "cancelled"  # type: ignore[union-attr]
    pid, gpid, port = ProcessModule.started[0]
    for p in (pid, gpid):
        assert not psutil.pid_exists(p) or psutil.Process(p).status() == psutil.STATUS_ZOMBIE
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))  # port is free again
    status = {e.module: e.status for e in by_type(events, ModuleFinished)}
    assert status["fake_process"] == "cancelled"
    assert status["fake_fast"] == "ok"  # non-exclusive layer ran before the exclusive one


def test_persistence_callbacks(tmp_path: Path) -> None:
    stored: list[tuple[str, int]] = []
    runs: list[tuple[str, str]] = []
    orch = Orchestrator(
        fake_registry(),
        lambda _e: None,
        store_findings=lambda sid, fs: stored.append((sid, len(fs))),
        store_module_run=lambda _sid, m, st, _r, _d: runs.append((m, st)),
    )
    asyncio.run(orch.run(make_ctx(tmp_path), ["fake_fast", "fake_needs_tool"]))
    assert stored == [("scan-test", 3)]
    assert sorted(runs) == [("fake_fast", "ok"), ("fake_needs_tool", "skipped")]


def test_broken_sink_does_not_kill_scan(tmp_path: Path) -> None:
    def sink(_e: Event) -> None:
        raise BrokenPipeError

    orch = Orchestrator(fake_registry(), sink)
    outcome = asyncio.run(orch.run(make_ctx(tmp_path), ["fake_fast"]))
    assert outcome.status == "completed"
    assert len(outcome.findings) == 3
