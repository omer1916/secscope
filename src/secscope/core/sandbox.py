"""SandboxRunner: start the user's app on loopback, wait until ready, watch it, stop it (SPEC §6.1).

Isolation measures (process level; Docker isolation is M10):
* the app runs in a *copy* of the project, never the original;
* only whitelisted environment variables are passed (the user's real secrets such
  as cloud credentials or tokens in the shell environment do not leak into it);
* HOST/PORT point at 127.0.0.1 and a free port; listening on other interfaces is reported;
* the whole process tree is killed on stop/cancel (ManagedProcess).
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import psutil

from secscope.core.process import ManagedProcess
from secscope.core.scope_guard import (
    ScopedHttpClient,
    ScopeGuard,
    allocate_loopback_port,
    loopback_port_free,
)

log = logging.getLogger(__name__)

HOST = "127.0.0.1"
LOG_TAIL_LINES = 50
INSTALL_TIMEOUT_S = 15 * 60

# Passed through from the user's environment; everything else is dropped.
SAFE_ENV_KEYS = frozenset(
    {
        "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
        "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "LANG",
        "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "USER", "USERNAME", "LOGNAME", "SHELL",
        "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "XDG_RUNTIME_DIR",
        "NVM_DIR", "NVM_HOME", "NVM_SYMLINK", "VOLTA_HOME", "PNPM_HOME", "JAVA_HOME",
        "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
    }
)  # fmt: skip

Emit = Callable[[str], None]
MetricEmit = Callable[[dict[str, float]], None]


class TargetStartError(RuntimeError):
    def __init__(self, message: str, log_tail: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.log_tail = list(log_tail)


def build_env(
    extra: Mapping[str, str],
    *,
    port: int,
    python: str | None = None,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if k.upper() in SAFE_ENV_KEYS}
    env.update({"HOST": HOST, "PORT": str(port), "BIND_ADDRESS": HOST})
    for key, value in extra.items():
        env[key] = expand(value, port=port, python=python)
    return env


def expand(value: str, *, port: int, python: str | None) -> str:
    return (
        value.replace("{port}", str(port))
        .replace("{host}", HOST)
        .replace("{python}", python or sys.executable)
    )


def expand_command(
    argv: Sequence[str], *, port: int, python: str | None, env: Mapping[str, str]
) -> list[str]:
    out = [expand(a, port=port, python=python) for a in argv]
    if not out:
        raise TargetStartError("empty run command")
    # Resolve the executable against the *target's* PATH (npm -> npm.cmd on Windows).
    resolved = shutil.which(out[0], path=env.get("PATH") or env.get("Path"))
    if resolved is None and not Path(out[0]).exists():
        raise TargetStartError(f"command not found: {out[0]}")
    if resolved is not None:
        out[0] = resolved
    return out


@dataclass
class TargetInfo:
    url: str
    port: int
    pid: int
    command: list[str]
    log_path: Path
    listen_addresses: list[str] = field(default_factory=list[str])

    @property
    def exposed_beyond_loopback(self) -> list[str]:
        return [a for a in self.listen_addresses if not _is_loopback(a)]


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", maxsplit=1)[0]).is_loopback
    except ValueError:
        return False


class SandboxRunner:
    def __init__(
        self,
        work_dir: Path,
        guard: ScopeGuard,
        *,
        on_log: Emit | None = None,
        on_metric: MetricEmit | None = None,
    ) -> None:
        self.work_dir = work_dir
        self.guard = guard
        self._on_log = on_log
        self._on_metric = on_metric
        self.tail: collections.deque[str] = collections.deque(maxlen=LOG_TAIL_LINES)
        self.proc: ManagedProcess | None = None
        self.info: TargetInfo | None = None
        self.samples: list[dict[str, float]] = []
        self._pump: asyncio.Task[None] | None = None
        self._monitor: asyncio.Task[None] | None = None
        self._log_file = (work_dir / "target.log").open("a", encoding="utf-8")

    # -------------------------------------------------------------- helpers

    def _log(self, line: str) -> None:
        self.tail.append(line)
        self._log_file.write(line + "\n")
        self._log_file.flush()
        if self._on_log is not None:
            self._on_log(line)

    async def _pump_output(self, proc: ManagedProcess) -> None:
        async for line in proc.lines():
            self._log(line)

    async def run_to_completion(
        self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout: float
    ) -> int:
        """Run a one-off command (dependency install) with output captured to the log."""
        self._log(f"$ {' '.join(argv)}")
        async with await ManagedProcess.start(argv, cwd=cwd, env=env) as proc:
            pump = asyncio.create_task(self._pump_output(proc))
            try:
                code = await proc.wait(timeout)
            except TimeoutError:
                await proc.terminate_tree()
                raise TargetStartError(
                    f"command timed out after {timeout:g}s", list(self.tail)
                ) from None
            await pump
        return code

    async def prepare_python_env(self, python: str) -> str:
        """Create a per-scan virtualenv and return its interpreter."""
        venv = self.work_dir / "venv"
        env = build_env({}, port=0)
        uv = shutil.which("uv")
        argv = (
            [uv, "venv", "--python", python, str(venv)] if uv else [python, "-m", "venv", str(venv)]
        )
        code = await self.run_to_completion(argv, cwd=self.work_dir, env=env, timeout=300)
        if code != 0:
            raise TargetStartError("could not create a virtualenv", list(self.tail))
        exe = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if uv:
            # uv-created venvs have no pip; seed it so `{python} -m pip` works everywhere.
            await self.run_to_completion(
                [uv, "pip", "install", "--python", str(exe), "pip"],
                cwd=self.work_dir,
                env=env,
                timeout=300,
            )
        return str(exe)

    async def install(
        self, argv: Sequence[str], *, cwd: Path, python: str | None, extra_env: Mapping[str, str]
    ) -> None:
        env = build_env(extra_env, port=0, python=python)
        if python is not None:
            env["PATH"] = str(Path(python).parent) + os.pathsep + env.get("PATH", "")
            env["VIRTUAL_ENV"] = str(Path(python).parent.parent)
        command = expand_command(argv, port=0, python=python, env=env)
        code = await self.run_to_completion(command, cwd=cwd, env=env, timeout=INSTALL_TIMEOUT_S)
        if code != 0:
            raise TargetStartError(f"dependency install failed (exit {code})", list(self.tail))

    # ---------------------------------------------------------------- start

    async def start(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        port: int | None = None,
        extra_env: Mapping[str, str] | None = None,
        python: str | None = None,
        ready_path: str = "/",
        timeout: float = 60,
    ) -> TargetInfo:
        if self.proc is not None:
            raise RuntimeError("target already started")
        port = port or allocate_loopback_port(HOST)
        if not loopback_port_free(port, HOST):
            raise TargetStartError(f"port {port} is already in use on {HOST}")
        env = build_env(extra_env or {}, port=port, python=python)
        if python is not None:
            env["PATH"] = str(Path(python).parent) + os.pathsep + env.get("PATH", "")
            env["VIRTUAL_ENV"] = str(Path(python).parent.parent)
        command = expand_command(argv, port=port, python=python, env=env)
        self._log(f"$ {' '.join(command)}  (cwd={cwd}, port={port})")
        self.proc = await ManagedProcess.start(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL)
        self._pump = asyncio.create_task(self._pump_output(self.proc))
        url = f"http://{HOST}:{port}"
        try:
            await self._wait_ready(url + _normalise_path(ready_path), timeout)
        except BaseException:
            await self.stop()
            raise
        self.info = TargetInfo(
            url=url + "/",
            port=port,
            pid=self.proc.pid,
            command=command,
            log_path=self.work_dir / "target.log",
            listen_addresses=self._listen_addresses(),
        )
        if self.info.exposed_beyond_loopback:
            self._log(
                "WARNING: the app also listens on "
                + ", ".join(self.info.exposed_beyond_loopback)
                + " (reachable from your network while the scan runs)"
            )
        self._monitor = asyncio.create_task(self._monitor_loop())
        return self.info

    async def start_static(self, root: Path, *, timeout: float = 30) -> TargetInfo:
        if getattr(sys, "frozen", False):
            exe = Path(sys.executable)
            console = exe.with_name("secscope.exe" if sys.platform == "win32" else "secscope")
            argv = [
                str(console if console.exists() else exe),
                "static-server",
                str(root),
                "--port",
                "{port}",
            ]
        else:
            argv = [
                sys.executable,
                "-m",
                "secscope.core.static_server",
                str(root),
                "--port",
                "{port}",
            ]
        return await self.start(argv, cwd=root, timeout=timeout)

    async def _wait_ready(self, url: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last_status: int | None = None
        async with ScopedHttpClient(self.guard, timeout=5) as client:
            while time.monotonic() < deadline:
                assert self.proc is not None
                if self.proc.returncode is not None:
                    await asyncio.sleep(0.2)  # let the output pump drain
                    raise TargetStartError(
                        f"the app exited with code {self.proc.returncode} before becoming ready",
                        list(self.tail),
                    )
                try:
                    response = await client.get(url, follow_redirects=False)
                    last_status = response.status_code
                    if 200 <= response.status_code < 400:
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.3)
        hint = f" (last HTTP status {last_status}; adjust the ready path)" if last_status else ""
        raise TargetStartError(
            f"the app did not become ready within {timeout:g}s{hint}", list(self.tail)
        )

    # -------------------------------------------------------------- monitor

    def _tree(self) -> list[psutil.Process]:
        if self.proc is None:
            return []
        try:
            root = psutil.Process(self.proc.pid)
            return [root, *root.children(recursive=True)]
        except psutil.Error:
            return []

    def _listen_addresses(self) -> list[str]:
        found: set[str] = set()
        for p in self._tree():
            try:
                for c in p.net_connections(kind="inet"):
                    if c.status == psutil.CONN_LISTEN and c.laddr:
                        found.add(str(c.laddr.ip))
            except psutil.Error:
                continue
        return sorted(found)

    def sample(self) -> dict[str, float]:
        cpu = rss = threads = handles = conns = 0.0
        procs = self._tree()
        for p in procs:
            try:
                with p.oneshot():
                    cpu += p.cpu_percent(interval=None)
                    rss += p.memory_info().rss
                    threads += p.num_threads()
                    handles += p.num_handles() if sys.platform == "win32" else p.num_fds()  # pyright: ignore[reportAttributeAccessIssue,reportUnknownMemberType]
                    conns += len(p.net_connections(kind="inet"))
            except psutil.Error:
                continue
        return {
            "t": time.monotonic(),
            "cpu_pct": cpu,
            "rss_mb": rss / 1024 / 1024,
            "threads": threads,
            "handles": handles,
            "connections": conns,
            "processes": float(len(procs)),
        }

    async def _monitor_loop(self, interval: float = 1.0) -> None:
        for p in self._tree():  # prime cpu_percent
            with contextlib.suppress(psutil.Error):
                p.cpu_percent(interval=None)
        while self.proc is not None and self.proc.returncode is None:
            await asyncio.sleep(interval)
            values = await asyncio.to_thread(self.sample)
            self.samples.append(values)
            if self._on_metric is not None:
                self._on_metric({k: v for k, v in values.items() if k != "t"})

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    # ----------------------------------------------------------------- stop

    async def stop(self) -> None:
        if self._monitor is not None:
            self._monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor
            self._monitor = None
        if self.proc is not None:
            await self.proc.terminate_tree()
        if self._pump is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(self._pump, 5)
            self._pump = None
        if self.info is not None:
            for _ in range(50):
                if loopback_port_free(self.info.port, HOST):
                    break
                await asyncio.sleep(0.1)
            else:
                log.warning("port %d still busy after stopping the target", self.info.port)
        self.proc = None

    def close(self) -> None:
        self._log_file.close()


def _normalise_path(path: str) -> str:
    return path if path.startswith("/") else "/" + path
