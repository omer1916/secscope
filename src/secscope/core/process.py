"""Child processes that can always be killed as a whole tree (SPEC §3.2, §16).

* POSIX: the child starts a new session (its own process group); killing the
  group with SIGTERM, then SIGKILL, reaches every descendant.
* Windows: the child is created suspended, assigned to a Job Object with
  ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` and only then resumed, so even
  grandchildren started in its first microseconds belong to the job.
  Terminating (or merely closing) the job kills the whole tree — also when the
  worker itself crashes, because the OS closes the job handle then.

A psutil sweep over the recorded descendants is the last line of defence.
"""

from __future__ import annotations

import asyncio
import contextlib
import locale
import logging
import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psutil

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
_LOCALE_ENCODING = locale.getpreferredencoding(False)


def decode_output(raw: bytes) -> str:
    """Decode child output: UTF-8 first, then the OS locale (e.g. cp1254 on Turkish Windows)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode(_LOCALE_ENCODING, errors="replace")


class _WindowsJob:
    """Minimal ctypes wrapper around a kill-on-close Job Object."""

    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_NO_WINDOW = 0x08000000
    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION = 9
    _PROCESS_ACCESS = (
        0x0001 | 0x0100 | 0x0800 | 0x1000
    )  # TERMINATE|SET_QUOTA|SUSPEND_RESUME|QUERY_LIMITED

    def __init__(self) -> None:
        import ctypes  # noqa: PLC0415
        from ctypes import wintypes  # noqa: PLC0415

        self._ctypes = ctypes
        # Typed as Any: WinDLL exports are dynamic, and the stubs omit WinDLL off Windows.
        win_dll = cast(Any, ctypes).WinDLL
        kernel32: Any = win_dll("kernel32", use_last_error=True)
        self._kernel32: Any = kernel32
        self._ntdll: Any = win_dll("ntdll")

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

        class IoCounters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]  # fmt: skip

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        self.handle: int = handle
        info = ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle, self._EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
        ):
            err = ctypes.get_last_error()  # type: ignore[attr-defined]
            kernel32.CloseHandle(handle)
            raise ctypes.WinError(err)  # type: ignore[attr-defined]

    def adopt_and_resume(self, pid: int) -> None:
        k = self._kernel32
        proc = k.OpenProcess(self._PROCESS_ACCESS, False, pid)
        if not proc:
            raise self._ctypes.WinError(self._ctypes.get_last_error())  # type: ignore[attr-defined]
        try:
            if not k.AssignProcessToJobObject(self.handle, proc):
                raise self._ctypes.WinError(self._ctypes.get_last_error())  # type: ignore[attr-defined]
            status = self._ntdll.NtResumeProcess(proc)
            if status != 0:
                raise OSError(f"NtResumeProcess failed: 0x{status & 0xFFFFFFFF:08x}")
        finally:
            k.CloseHandle(proc)

    def terminate(self) -> None:
        self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = 0


@dataclass(frozen=True, slots=True)
class CompletedRun:
    returncode: int
    stdout: str
    stderr: str


async def run_capture(
    argv: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 600,
) -> CompletedRun:
    """Run an external tool to completion, capturing output; the tree dies on timeout/cancel."""
    proc = await ManagedProcess.start(
        argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.proc.communicate(), timeout)
    except BaseException:  # timeout or cancellation
        await proc.terminate_tree()
        raise
    proc.close()
    return CompletedRun(proc.proc.returncode or 0, decode_output(out), decode_output(err))


def python_tool_command(module: str) -> list[str]:
    """Run a Python-based tool we depend on (bandit, pip-audit) from our own environment."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable)
        console = exe.with_name("secscope.exe" if sys.platform == "win32" else "secscope")
        return [str(console if console.exists() else exe), "run-python-tool", module]
    return [sys.executable, "-m", module]


class ManagedProcess:
    """An asyncio subprocess whose entire process tree can be terminated."""

    def __init__(self, proc: asyncio.subprocess.Process, job: _WindowsJob | None) -> None:
        self.proc = proc
        self._job = job
        self._known_descendants: set[int] = set()

    @property
    def pid(self) -> int:
        return self.proc.pid

    @property
    def returncode(self) -> int | None:
        return self.proc.returncode

    @classmethod
    async def start(
        cls,
        argv: Sequence[str],
        *,
        cwd: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: int | None = subprocess.DEVNULL,
        stdout: int | None = subprocess.PIPE,
        stderr: int | None = subprocess.STDOUT,
    ) -> ManagedProcess:
        if not argv:
            raise ValueError("empty command")
        env_dict = dict(env) if env is not None else None
        if IS_WINDOWS:
            job = _WindowsJob()
            flags = (
                _WindowsJob.CREATE_SUSPENDED
                | _WindowsJob.CREATE_NEW_PROCESS_GROUP
                | _WindowsJob.CREATE_NO_WINDOW
            )
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=cwd,
                    env=env_dict,
                    stdin=stdin,
                    stdout=stdout,
                    stderr=stderr,
                    creationflags=flags,
                )
            except BaseException:
                job.close()
                raise
            try:
                job.adopt_and_resume(proc.pid)
            except BaseException:
                job.terminate()
                job.close()
                raise
            return cls(proc, job)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env_dict,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        return cls(proc, None)

    def descendants(self) -> list[psutil.Process]:
        try:
            children = psutil.Process(self.pid).children(recursive=True)
        except psutil.Error:
            return []
        self._known_descendants.update(c.pid for c in children)
        return children

    async def wait(self, timeout: float | None = None) -> int:
        if timeout is None:
            return await self.proc.wait()
        return await asyncio.wait_for(self.proc.wait(), timeout)

    async def lines(self) -> AsyncIterator[str]:
        """Decoded stdout lines (requires stdout=PIPE)."""
        assert self.proc.stdout is not None
        while True:
            raw = await self.proc.stdout.readline()
            if not raw:
                return
            yield decode_output(raw).rstrip("\r\n")

    async def terminate_tree(self, grace: float = 3.0) -> None:
        """Stop the process and every descendant; never leaves orphans behind."""
        self.descendants()  # snapshot before the parent dies and children get re-parented
        if self._job is not None:
            # Windows has no reliable "graceful" signal for arbitrary console-less
            # children; the job object kills the tree atomically.
            self._job.terminate()
        elif sys.platform != "win32" and self.proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.pid, signal.SIGTERM)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.proc.wait(), grace)
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.pid, signal.SIGKILL)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.proc.wait(), grace)
        self._sweep()
        self.close()

    def _sweep(self) -> None:
        survivors: list[psutil.Process] = []
        for pid in self._known_descendants:
            try:
                p = psutil.Process(pid)
                p.kill()
                survivors.append(p)
            except psutil.Error:
                continue
        if survivors:
            log.warning("killed %d leftover descendant(s) of pid %d", len(survivors), self.pid)
            psutil.wait_procs(survivors, timeout=3)

    def close(self) -> None:
        if self._job is not None:
            self._job.close()
            self._job = None

    async def __aenter__(self) -> ManagedProcess:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self.proc.returncode is None or self._known_descendants:
            await self.terminate_tree()
        self.close()
