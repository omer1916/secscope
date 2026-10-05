# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
# (pyqtgraph ships without type information)
"""Live monitoring (SPEC §11.2.3): module status, streaming findings, log console, live charts."""

from __future__ import annotations

import time
from collections.abc import Mapping

import pyqtgraph as pg
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from secscope.core.events import (
    CancelCommand,
    ErrorEvent,
    Event,
    FindingEvent,
    Metric,
    ModuleFinished,
    ModuleLog,
    ModuleProgress,
    ModuleSkipped,
    ModuleStarted,
    PauseCommand,
    ResumeCommand,
    ScanFinished,
    ScanStarted,
    ScopeViolationEvent,
    StartCommand,
)
from secscope.ui.formatting import describe
from secscope.ui.state import AppState
from secscope.ui.theme import SEVERITY_COLORS
from secscope.ui.widgets import label
from secscope.ui.worker_bridge import WorkerBridge

LOG_LEVELS = ("debug", "info", "warning", "error")
MAX_POINTS = 600


class MonitorPage(QWidget):
    scan_finished = Signal(str, str, bool)  # scan id, status, worker crashed

    def __init__(self, state: AppState, *, worker_env: Mapping[str, str] | None = None) -> None:
        super().__init__()
        self.state = state
        t = state.t
        self.worker_env = worker_env
        self.bridge = WorkerBridge(self)
        self.bridge.event_received.connect(self.on_event)
        self.bridge.finished.connect(self._on_worker_exit)
        self.events: list[Event] = []
        self.scan_id: str | None = None
        self._status = "running"
        self._paused = False
        self._rows: dict[str, int] = {}
        self._t0 = time.monotonic()
        self._series: dict[str, tuple[list[float], list[float]]] = {}

        self.heading = label(t("ui.monitor.idle"), "h1")
        self.pause_btn = QPushButton(t("action.pause"))
        self.cancel_btn = QPushButton(t("action.cancel"))
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.cancel_btn.clicked.connect(self.cancel)
        self.breaker = label("", "muted")

        self.modules = QTableWidget(0, 4)
        self.modules.setHorizontalHeaderLabels(
            [t("ui.monitor.col.module"), t("report.status"), "%", t("report.duration")]
        )
        self.modules.horizontalHeader().setStretchLastSection(True)
        self.modules.verticalHeader().setVisible(False)
        self.modules.setAccessibleName(t("report.meta.modules"))

        self.findings = QListWidget()
        self.findings.setAccessibleName(t("report.findings"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setAccessibleName(t("ui.monitor.log"))
        self.log_level = QComboBox()
        for level in LOG_LEVELS:
            self.log_level.addItem(t(f"ui.log.{level}"), level)
        self.log_level.setCurrentIndex(1)
        self._log_entries: list[tuple[str, str]] = []
        self.log_level.currentIndexChanged.connect(self._refilter_log)

        self.chart = pg.PlotWidget()
        self.chart.addLegend()
        self.chart.setLabel("bottom", t("ui.monitor.seconds"))
        self.chart.showGrid(x=True, y=True, alpha=0.2)
        self._curves: dict[str, pg.PlotDataItem] = {}

        top = QHBoxLayout()
        top.addWidget(self.heading, 1)
        top.addWidget(self.pause_btn)
        top.addWidget(self.cancel_btn)
        log_box = QWidget()
        log_layout = QVBoxLayout(log_box)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_head = QHBoxLayout()
        log_head.addWidget(label(t("ui.monitor.log"), "h2"), 1)
        log_head.addWidget(self.log_level)
        log_layout.addLayout(log_head)
        log_layout.addWidget(self.log)
        findings_box = QWidget()
        fl = QVBoxLayout(findings_box)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.addWidget(label(t("report.findings"), "h2"))
        fl.addWidget(self.findings)
        upper = QSplitter()
        upper.addWidget(self.modules)
        upper.addWidget(self.chart)
        lower = QSplitter()
        lower.addWidget(findings_box)
        lower.addWidget(log_box)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.breaker)
        layout.addWidget(upper, 1)
        layout.addWidget(lower, 1)
        self._buttons()

    # --------------------------------------------------------------- control

    def start(self, command: StartCommand) -> None:
        self.events.clear()
        self.findings.clear()
        self.log.clear()
        self._log_entries.clear()
        self.modules.setRowCount(0)
        self._rows.clear()
        self.chart.clear()
        self.chart.addLegend()
        self._curves.clear()
        self._series.clear()
        self._paused = False
        self.scan_id = command.scan_id
        self._t0 = time.monotonic()
        self.heading.setText(self.state.t("status.running"))
        self.bridge.start(command, env=self.worker_env)
        self._buttons()

    def toggle_pause(self) -> None:
        t = self.state.t
        self._paused = not self._paused
        self.bridge.send(PauseCommand() if self._paused else ResumeCommand())
        self.pause_btn.setText(t("action.resume") if self._paused else t("action.pause"))

    def cancel(self) -> None:
        self.bridge.send(CancelCommand())

    def _buttons(self) -> None:
        running = self.bridge.running
        self.pause_btn.setEnabled(running)
        self.cancel_btn.setEnabled(running)

    # ---------------------------------------------------------------- events

    def _row(self, module: str) -> int:
        if module not in self._rows:
            row = self.modules.rowCount()
            self.modules.insertRow(row)
            for col, text in enumerate((module, "", "0", "")):
                self.modules.setItem(row, col, QTableWidgetItem(text))
            self._rows[module] = row
        return self._rows[module]

    def _set(self, module: str, col: int, text: str) -> None:
        item = self.modules.item(self._row(module), col)
        if item is not None:
            item.setText(text)

    def on_event(self, event: Event) -> None:
        t = self.state.t
        self.events.append(event)
        match event:
            case ScanStarted():
                self.scan_id = event.scan_id
            case ModuleStarted():
                self._set(event.module, 1, t("ui.monitor.running"))
            case ModuleProgress():
                self._set(event.module, 2, f"{event.pct:.0f}")
            case ModuleSkipped():
                self._set(event.module, 1, t("report.module.skipped"))
                self._set(event.module, 3, event.reason.get(t.lang))
            case ModuleFinished():
                self._set(event.module, 1, t(f"report.module.{event.status}"))
                self._set(event.module, 2, "100" if event.status == "ok" else "")
                self._set(event.module, 3, f"{event.duration_s:.1f} s · {event.finding_count}")
            case FindingEvent():
                line = describe(event, t) or ""
                self.findings.addItem(line)
                item = self.findings.item(self.findings.count() - 1)
                item.setForeground(pg.mkColor(SEVERITY_COLORS[event.finding.severity]))
            case Metric():
                self._plot(event)
            case ScopeViolationEvent():
                self.breaker.setText(describe(event, t) or "")
            case ScanFinished():
                self._status = event.status
                self.heading.setText(t("status.finished", status=event.status))
            case ModuleLog() | ErrorEvent():
                pass
            case _:
                pass
        line = describe(event, t)
        if line is not None and not isinstance(event, FindingEvent):
            level = (
                event.level
                if isinstance(event, ModuleLog)
                else ("error" if isinstance(event, ErrorEvent) else "info")
            )
            self._log_entries.append((level, line))
            if LOG_LEVELS.index(level) >= self.log_level.currentIndex():
                self.log.appendPlainText(line)

    def _refilter_log(self) -> None:
        threshold = self.log_level.currentIndex()
        self.log.setPlainText(
            "\n".join(
                line for level, line in self._log_entries if LOG_LEVELS.index(level) >= threshold
            )
        )

    def _plot(self, event: Metric) -> None:
        now = time.monotonic() - self._t0
        palette = ["#2457d6", "#d1501f", "#2e7d32", "#7b1fa2", "#00838f", "#b7791f"]
        for key, value in event.values.items():
            name = f"{event.series}:{key}"
            xs, ys = self._series.setdefault(name, ([], []))
            xs.append(now)
            ys.append(value)
            if len(xs) > MAX_POINTS:
                del xs[0], ys[0]
            if name not in self._curves:
                pen = pg.mkPen(palette[len(self._curves) % len(palette)], width=2)
                self._curves[name] = self.chart.plot(name=name, pen=pen)
            self._curves[name].setData(xs, ys)

    def _on_worker_exit(self, _code: int, crashed: bool) -> None:
        t = self.state.t
        if crashed:
            self.heading.setText(t("status.worker_crashed"))
            self._status = "interrupted"
        self._buttons()
        self.state.scans_changed.emit()
        if self.scan_id:
            self.scan_finished.emit(self.scan_id, self._status, crashed)
