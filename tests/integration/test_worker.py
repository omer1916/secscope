"""Worker process end to end with fake modules (SPEC M1 acceptance)."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path

import psutil

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.events import (
    CancelCommand,
    Event,
    FindingEvent,
    Metric,
    ModuleSkipped,
    ScanFinished,
    StartCommand,
)
from secscope.storage import db
from secscope.storage.repo import ScanRepository
from secscope.worker.client import WorkerClient
from secscope.worker.main import EXTRA_MODULES_ENV
from tests.fakes import FAKE_REFS

REPO = Path(__file__).resolve().parents[2]


def worker_env() -> dict[str, str]:
    env = dict(os.environ)
    env[EXTRA_MODULES_ENV] = "1"
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def start_command(tmp_path: Path, modules: list[str], scan_id: str) -> StartCommand:
    config = ScanConfig(
        target=Target(kind=TargetKind.URL, value="http://127.0.0.1:9/"),
        scope_statement_accepted=True,
    )
    settings = Settings(data_dir=tmp_path / "data dir")
    return StartCommand(
        config=config.model_dump(mode="json"),
        settings=settings.model_dump(mode="json"),
        scan_id=scan_id,
        modules=modules,
        extra_modules=list(FAKE_REFS),
    )


async def collect(client: WorkerClient, until: type | None = None) -> list[Event]:
    events: list[Event] = []
    async for event in client.events():
        events.append(event)
        if until is not None and isinstance(event, until):
            break
    return events


def test_worker_runs_scan_and_persists(tmp_path: Path) -> None:
    async def scenario() -> tuple[list[Event], int]:
        client = await WorkerClient.start(env=worker_env())
        await client.send(start_command(tmp_path, ["fake_fast", "fake_needs_tool"], "scan-ok"))
        events = await asyncio.wait_for(collect(client), 60)
        return events, await client.wait(30)

    events, code = asyncio.run(scenario())
    assert code == 0
    assert isinstance(events[-1], ScanFinished)
    assert events[-1].status == "completed"
    assert sum(isinstance(e, FindingEvent) for e in events) == 3
    assert any(isinstance(e, ModuleSkipped) and e.module == "fake_needs_tool" for e in events)

    conn = db.connect(tmp_path / "data dir" / "secscope.db")
    repo = ScanRepository(conn)
    assert len(repo.list_findings("scan-ok")) == 3
    assert repo.module_runs("scan-ok") == {"fake_fast": "ok", "fake_needs_tool": "skipped"}
    row = repo.get_scan("scan-ok")
    assert row is not None
    assert row["status"] == "completed"
    conn.close()
    journal = tmp_path / "data dir" / "scans" / "scan-ok" / "events.jsonl"
    assert len(journal.read_text(encoding="utf-8").splitlines()) == len(events)


def _tree_metric(events: list[Event]) -> tuple[int, int, int] | None:
    for e in events:
        if isinstance(e, Metric) and e.series == "tree":
            return int(e.values["pid"]), int(e.values["gpid"]), int(e.values["port"])
    return None


def _assert_dead(*pids: int) -> None:
    for pid in pids:
        assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE


def _assert_port_free(port: int) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))


def test_cancel_command_leaves_no_processes_or_ports(tmp_path: Path) -> None:
    async def scenario() -> tuple[list[Event], tuple[int, int, int], int, int]:
        client = await WorkerClient.start(env=worker_env())
        await client.send(start_command(tmp_path, ["fake_process"], "scan-cancel"))
        events: list[Event] = []
        tree = None
        async for event in client.events():
            events.append(event)
            tree = _tree_metric(events)
            if tree:
                break
        assert tree is not None
        await client.send(CancelCommand())
        events += await asyncio.wait_for(collect(client), 30)
        code = await client.wait(30)
        return events, tree, client.pid, code

    events, (pid, gpid, port), worker_pid, code = asyncio.run(scenario())
    assert code == 0
    assert isinstance(events[-1], ScanFinished)
    assert events[-1].status == "cancelled"
    _assert_dead(pid, gpid, worker_pid)
    _assert_port_free(port)


def test_killing_the_worker_kills_its_children(tmp_path: Path) -> None:
    """If the worker dies hard (crash), its target processes must not survive."""

    async def scenario() -> tuple[int, int, int]:
        client = await WorkerClient.start(env=worker_env())
        await client.send(start_command(tmp_path, ["fake_process"], "scan-crash"))
        events: list[Event] = []
        async for event in client.events():
            events.append(event)
            if tree := _tree_metric(events):
                await client.kill()
                return tree
        raise AssertionError("no tree metric")

    pid, gpid, port = asyncio.run(scenario())
    for _ in range(50):
        if not any(psutil.pid_exists(p) for p in (pid, gpid)):
            break
        import time  # noqa: PLC0415

        time.sleep(0.1)
    _assert_dead(pid, gpid)
    _assert_port_free(port)


def test_ui_disappearing_cancels_scan(tmp_path: Path) -> None:
    async def scenario() -> tuple[list[Event], int]:
        client = await WorkerClient.start(env=worker_env())
        await client.send(start_command(tmp_path, ["fake_slow"], "scan-eof"))
        await asyncio.sleep(1.0)
        await client.close_stdin()
        events = await asyncio.wait_for(collect(client), 30)
        return events, await client.wait(30)

    events, code = asyncio.run(scenario())
    assert code == 0
    assert isinstance(events[-1], ScanFinished)
    assert events[-1].status == "cancelled"


def test_out_of_scope_url_target_rejected(tmp_path: Path) -> None:
    async def scenario() -> list[Event]:
        client = await WorkerClient.start(env=worker_env())
        cmd = start_command(tmp_path, ["fake_fast"], "scan-bad")
        cmd.config["target"]["value"] = "http://example.com/"
        await client.send(cmd)
        events = await asyncio.wait_for(collect(client), 30)
        await client.wait(30)
        return events

    events = asyncio.run(scenario())
    assert isinstance(events[-1], ScanFinished)
    assert events[-1].status == "failed"
