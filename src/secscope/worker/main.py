"""Worker process: runs one scan, speaks JSON-Lines on stdin/stdout (SPEC §3.2).

Protocol: the UI sends one ``start`` command, then any of pause / resume /
cancel / kill_target. The worker streams events and exits after
``scan.finished``. If stdin closes (the UI died) the scan is cancelled, so a
worker never outlives its UI.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import threading
import traceback
from collections.abc import Iterator
from typing import BinaryIO

from pydantic import ValidationError

from secscope.core.config import ScanConfig, Settings, default_log_dir
from secscope.core.events import (
    CancelCommand,
    Command,
    ErrorEvent,
    Event,
    KillTargetCommand,
    PauseCommand,
    ResumeCommand,
    ScanFinished,
    StartCommand,
    decode_command,
    encode,
)
from secscope.core.logging import setup_logging
from secscope.core.orchestrator import Orchestrator
from secscope.core.redact import redact
from secscope.core.scan import run_scan
from secscope.core.session import InvalidTargetError, open_session
from secscope.modules.registry import load_builtin
from secscope.reporting.finalize import finalize_scan

log = logging.getLogger(__name__)

# Importing arbitrary modules by name is a test/development hook only.
EXTRA_MODULES_ENV = "SECSCOPE_ALLOW_EXTRA_MODULES"


class EventWriter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def __call__(self, event: Event) -> None:
        data = encode(event).encode("utf-8")
        with self._lock:
            self._stream.write(data)
            self._stream.flush()


def _stdin_lines() -> Iterator[bytes]:
    # Raw os.read on fd 0, not sys.stdin.buffer: a daemon thread blocked inside
    # BufferedReader holds its lock, and interpreter shutdown then dies with a
    # fatal error (access violation on Windows) while the UI keeps stdin open.
    pending = b""
    while chunk := os.read(0, 65536):
        pending += chunk
        *lines, pending = pending.split(b"\n")
        yield from lines
    if pending:
        yield pending


def _stdin_reader(
    loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[Command | None], writer: EventWriter
) -> None:
    for raw in _stdin_lines():
        if not raw.strip():
            continue
        try:
            command = decode_command(raw)
        except ValidationError as exc:
            writer(ErrorEvent(scan_id="-", message="invalid command", detail=str(exc)))
            continue
        loop.call_soon_threadsafe(queue.put_nowait, command)
    loop.call_soon_threadsafe(queue.put_nowait, None)  # EOF: UI is gone


async def serve(writer: EventWriter) -> int:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Command | None] = asyncio.Queue()
    threading.Thread(target=_stdin_reader, args=(loop, queue, writer), daemon=True).start()

    first = await queue.get()
    if not isinstance(first, StartCommand):
        writer(ErrorEvent(scan_id="-", message="expected a start command"))
        return 2

    try:
        config = ScanConfig.model_validate(first.config)
        settings = (
            Settings.load() if first.settings is None else Settings.model_validate(first.settings)
        )
    except ValidationError as exc:
        writer(
            ErrorEvent(
                scan_id=first.scan_id or "-", message="invalid scan configuration", detail=str(exc)
            )
        )
        return 2

    extra = first.extra_modules if os.environ.get(EXTRA_MODULES_ENV) == "1" else []
    registry = load_builtin(extra)
    try:
        session = open_session(config, settings, scan_id=first.scan_id)
    except (InvalidTargetError, OSError) as exc:
        writer(ErrorEvent(scan_id=first.scan_id or "-", message=str(exc)))
        writer(ScanFinished(scan_id=first.scan_id or "-", status="failed", duration_s=0))
        return 2
    setup_logging(default_log_dir(), settings.log_level)

    ctx = session.ctx
    journal = (ctx.work_dir / "events.jsonl").open("a", encoding="utf-8")

    def sink(event: Event) -> None:
        writer(event)
        journal.write(encode(event))  # partial results survive a crash (SPEC §13)
        journal.flush()

    orchestrator = Orchestrator(
        registry,
        sink,
        store_findings=session.repo.add_findings,
        store_module_run=session.repo.record_module_run,
    )
    modules = list(first.modules) or registry.for_profile(config.profile)
    scan = asyncio.create_task(run_scan(orchestrator, ctx, modules))

    async def pump_commands() -> None:
        while True:
            command = await queue.get()
            match command:
                case None | CancelCommand():
                    orchestrator.cancel()
                    if command is None:
                        return
                case PauseCommand():
                    orchestrator.pause()
                case ResumeCommand():
                    orchestrator.resume()
                case KillTargetCommand():
                    orchestrator.kill_target()
                case StartCommand():
                    writer(ErrorEvent(scan_id=ctx.scan_id, message="scan already running"))

    pump = asyncio.create_task(pump_commands())
    try:
        outcome = await scan
    finally:
        pump.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pump
        journal.close()
    finalize_scan(session, outcome)
    session.close()
    return 0 if outcome.status in ("completed", "cancelled") else 1


def main() -> int:
    # stdout belongs to the protocol: keep a private handle and send stray prints to stderr.
    protocol_out = sys.stdout.buffer
    sys.stdout = sys.stderr
    writer = EventWriter(protocol_out)
    try:
        return asyncio.run(serve(writer))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        writer(
            ErrorEvent(
                scan_id="-", message=f"worker crashed: {exc}", detail=redact(traceback.format_exc())
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
