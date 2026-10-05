"""UI smoke test (SPEC M1): the window starts a worker scan and lists its events."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from secscope.core.config import Settings
from secscope.core.events import FindingEvent, ScanFinished
from secscope.ui.main_window import MainWindow
from secscope.worker.main import EXTRA_MODULES_ENV
from tests.fakes import FAKE_REFS

REPO = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.e2e


def worker_env() -> dict[str, str]:
    env = dict(os.environ)
    env[EXTRA_MODULES_ENV] = "1"
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> MainWindow:
    w = MainWindow(
        Settings(data_dir=tmp_path / "data", language="en"),
        worker_env=worker_env(),
        modules=["fake_fast", "fake_needs_tool"],
        extra_modules=FAKE_REFS,
    )
    qtbot.addWidget(w)
    return w


def test_start_requires_scope_statement(window: MainWindow) -> None:
    window.target.setText("http://localhost:3000")
    assert not window.start_btn.isEnabled()
    window.scope_ok.setChecked(True)
    assert window.start_btn.isEnabled()


def test_scan_runs_and_lists_events(window: MainWindow, qtbot: QtBot) -> None:
    window.target.setText("http://127.0.0.1:9/")
    window.scope_ok.setChecked(True)
    window.start_scan()
    qtbot.waitUntil(lambda: any(isinstance(e, ScanFinished) for e in window.events), timeout=60_000)
    qtbot.waitUntil(lambda: not window.bridge.running, timeout=30_000)
    assert sum(isinstance(e, FindingEvent) for e in window.events) == 3
    texts = [window.event_list.item(i).text() for i in range(window.event_list.count())]
    assert any("SKIPPED" in t for t in texts)
    assert "completed" in window.status.text()
    assert window.start_btn.isEnabled()


def test_cancel_from_ui(window: MainWindow, qtbot: QtBot) -> None:
    window._modules = ["fake_slow"]  # pyright: ignore[reportPrivateUsage]
    window.target.setText("http://127.0.0.1:9/")
    window.scope_ok.setChecked(True)
    window.start_scan()
    qtbot.waitUntil(lambda: len(window.events) >= 2, timeout=30_000)
    window.cancel_scan()
    qtbot.waitUntil(lambda: any(isinstance(e, ScanFinished) for e in window.events), timeout=30_000)
    finished = [e for e in window.events if isinstance(e, ScanFinished)]
    assert finished[0].status == "cancelled"
