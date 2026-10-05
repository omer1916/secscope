from __future__ import annotations

import socket
import sys
from pathlib import Path

import psutil
import pytest

from secscope.core.process import ManagedProcess

TREE = Path(__file__).resolve().parents[1] / "helpers" / "tree.py"


def port_is_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


async def test_terminate_tree_kills_grandchildren_and_frees_ports() -> None:
    proc = await ManagedProcess.start([sys.executable, str(TREE)])
    line = await anext(proc.lines())
    grandchild_pid, port = (int(x) for x in line.split())
    assert psutil.pid_exists(grandchild_pid)
    assert not port_is_free(port)

    await proc.terminate_tree(grace=2)

    assert proc.returncode is not None
    gone = not psutil.pid_exists(grandchild_pid) or (
        psutil.Process(grandchild_pid).status() == psutil.STATUS_ZOMBIE
    )
    assert gone
    assert port_is_free(port)


async def test_output_and_exit_code() -> None:
    proc = await ManagedProcess.start([sys.executable, "-c", "print('héllo'); raise SystemExit(3)"])
    lines = [line async for line in proc.lines()]
    assert lines == ["héllo"]
    assert await proc.wait(10) == 3
    proc.close()


async def test_cwd_and_env_with_spaces(tmp_path: Path) -> None:
    work = tmp_path / "dir with space"
    work.mkdir()
    proc = await ManagedProcess.start(
        [sys.executable, "-c", "import os; print(os.getcwd()); print(os.environ['X_TEST'])"],
        cwd=work,
        env={
            "X_TEST": "value with space",
            "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
        },
    )
    lines = [line async for line in proc.lines()]
    await proc.wait(10)
    proc.close()
    assert Path(lines[0]).resolve() == work.resolve()
    assert lines[1] == "value with space"


async def test_empty_command_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        await ManagedProcess.start([])


async def test_context_manager_cleans_up() -> None:
    async with await ManagedProcess.start(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    ) as proc:
        pid = proc.pid
    assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
