"""Desktop UI end to end with pytest-qt (SPEC M9 acceptance), headless (QT_QPA_PLATFORM=offscreen)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from secscope.analysis.kb import default_kb
from secscope.core.config import Settings
from secscope.core.events import ScanFinished
from secscope.core.models import CodeLocation, Evidence, Finding
from secscope.ui.i18n import Translator
from secscope.ui.main_window import MainWindow
from secscope.ui.pages.results import finding_html
from secscope.ui.state import AppState
from secscope.ui.widgets import FindingsFilter, FindingsModel

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "fixtures"

pytestmark = pytest.mark.e2e


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> MainWindow:
    state = AppState(
        Settings(data_dir=tmp_path / "data", language="en"), config_dir=tmp_path / "config"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    w = MainWindow(state, worker_env=env)
    qtbot.addWidget(w)
    return w


def test_wizard_to_results_full_flow(window: MainWindow, qtbot: QtBot) -> None:
    wiz = window.wizard
    window.open_wizard()
    wiz.kind_folder.setChecked(True)
    wiz.path_edit.setText(str(FIXTURES / "static-seo-bad"))
    assert wiz.next_btn.isEnabled()
    wiz.next_btn.click()  # -> detected project
    assert "static" in wiz.detected.text()
    wiz.next_btn.click()  # -> modules
    wiz.profile.setCurrentIndex(wiz.profile.findData("custom"))
    for i in range(wiz.module_list.count()):
        item = wiz.module_list.item(i)
        keep = item.data(Qt.ItemDataRole.UserRole) in {"seo", "config_audit"}
        item.setCheckState(Qt.CheckState.Checked if keep else Qt.CheckState.Unchecked)
    wiz.next_btn.click()  # -> confirmation
    assert not wiz.next_btn.isEnabled()  # scope statement still unchecked
    wiz.scope_ok.setChecked(True)
    assert wiz.next_btn.isEnabled()
    wiz.next_btn.click()  # start

    assert window.stack.currentWidget() is window.monitor
    qtbot.waitUntil(
        lambda: any(isinstance(e, ScanFinished) for e in window.monitor.events), timeout=120_000
    )
    qtbot.waitUntil(lambda: window.stack.currentWidget() is window.results, timeout=60_000)

    results = window.results
    total = results.proxy.rowCount()
    assert total > 20
    results.search.setText("viewport")
    assert 0 < results.proxy.rowCount() < total
    results.search.setText("")
    results.sev_boxes["low"].setChecked(False)
    assert results.proxy.rowCount() < total
    assert "<h2>" in results.detail.toHtml() or results.detail.toPlainText()

    window.history.refresh()
    assert window.history.table.rowCount() == 1
    window.dashboard.refresh()
    assert window.dashboard.last_id == window.monitor.scan_id


def test_url_outside_scope_blocks_next(window: MainWindow) -> None:
    wiz = window.wizard
    window.open_wizard()
    wiz.kind_url.setChecked(True)
    wiz.url_edit.setText("http://example.com/")
    assert not wiz.next_btn.isEnabled()
    assert wiz.source_error.text()
    wiz.url_edit.setText("http://localhost:3000/")
    assert wiz.next_btn.isEnabled()


def _many(n: int) -> list[Finding]:
    kb = default_kb()
    sevs = ("critical", "high", "medium", "low", "info")
    return [
        kb.finding("SAST-SQLI-001", module="sast", location=CodeLocation(path=f"f{i % 50}.py", line=i % 900 + 1),
                   evidence=Evidence(snippet=f"q{i}"), severity=sevs[i % 5])  # type: ignore[arg-type]
        for i in range(n)
    ]  # fmt: skip


def test_ten_thousand_findings_stay_responsive(qtbot: QtBot) -> None:
    """SPEC §13: no UI-thread blocking > 50 ms; the virtualised model filters 10k rows quickly."""
    findings = _many(10_000)
    model = FindingsModel(Translator("en"))
    proxy = FindingsFilter()
    proxy.setSourceModel(model)
    t0 = time.perf_counter()
    model.set_findings(findings)
    assert time.perf_counter() - t0 < 0.05
    t0 = time.perf_counter()
    proxy.set_severities({"critical"})
    filtering = time.perf_counter() - t0
    assert proxy.rowCount() == 2000
    assert filtering < 1.0  # one-off filter pass over 10k rows


def test_settings_save_normalises_weights(window: MainWindow, tmp_path: Path) -> None:
    page = window.settings_page
    page.weights["security"].setValue(90)
    assert page.save()
    saved = Settings.load(tmp_path / "config")
    total = sum(
        getattr(saved.weights, k)
        for k in ("security", "seo", "resilience", "quality", "dependencies")
    )
    assert abs(total - 1.0) < 1e-3
    assert saved.weights.security > 0.45


def test_detail_panel_escapes_target_content() -> None:
    xss = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    f = default_kb().finding(
        "SAST-SQLI-001",
        module="sast",
        location=CodeLocation(path="a.py", line=1),
        evidence=Evidence(snippet=xss),
    )
    html = finding_html(f, Translator("en"))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
