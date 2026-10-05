"""Async client for the worker process (used by tests and headless tooling).

The desktop UI uses ``QProcess`` with the same protocol (see ``ui/worker_bridge.py``).
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

from pydantic import ValidationError

from secscope.core.events import Command, ErrorEvent, Event, decode_event, encode
from secscope.core.process import ManagedProcess


def worker_command() -> list[str]:
    """How to launch the worker: frozen builds re-enter the same executable."""
    if getattr(sys, "frozen", False):
        # The windowed UI exe has no console streams: use the console sibling for the worker.
        exe = Path(sys.executable)
        console = exe.with_name("secscope.exe" if sys.platform == "win32" else "secscope")
        return [str(console if console.exists() else exe), "worker"]
    return [sys.executable, "-m", "secscope.worker"]


class WorkerClient:
    def __init__(self, proc: ManagedProcess) -> None:
        self._proc = proc

    @classmethod
    async def start(cls, env: Mapping[str, str] | None = None) -> WorkerClient:
        proc = await ManagedProcess.start(
            worker_command(),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return cls(proc)

    @property
    def pid(self) -> int:
        return self._proc.pid

    async def send(self, command: Command) -> None:
        stdin = self._proc.proc.stdin
        assert stdin is not None
        stdin.write(encode(command).encode("utf-8"))
        await stdin.drain()

    async def close_stdin(self) -> None:
        stdin = self._proc.proc.stdin
        if stdin is not None and not stdin.is_closing():
            stdin.close()

    async def events(self) -> AsyncIterator[Event]:
        async for line in self._proc.lines():
            if not line.strip():
                continue
            try:
                yield decode_event(line)
            except ValidationError as exc:
                yield ErrorEvent(
                    scan_id="-",
                    message="undecodable worker output",
                    detail=f"{line[:200]!r}: {exc}",
                )

    async def wait(self, timeout: float | None = None) -> int:
        return await self._proc.wait(timeout)

    async def kill(self) -> None:
        await self._proc.terminate_tree()
