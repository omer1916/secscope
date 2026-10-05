# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
# (pyqtgraph ships without type information)
"""Dashboard (SPEC §11.2.1): last scan scores, score trend, open critical/high, quick actions."""

from __future__ import annotations

import pyqtgraph as pg
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from secscope.reporting.json_export import report_findings
from secscope.ui.state import AppState
from secscope.ui.widgets import ScoreRing, card, label

SUBS = ("security", "seo", "resilience", "quality", "dependencies")


class DashboardPage(QWidget):
    new_scan = Signal()
    open_scan = Signal(str)

    def __init__(self, state: AppState) -> None:
        super().__init__()
        self.state = state
        t = state.t
        self.last_id: str | None = None
        self.title = label(t("ui.dashboard.title"), "h1")
        self.subtitle = label(t("ui.dashboard.empty"), "muted")
        self.overall = ScoreRing(t("report.overall"))
        self.subs = {k: ScoreRing(t(f"report.sub.{k}")) for k in SUBS}
        self.open_counts = label("", "h2")
        new_btn = QPushButton(t("ui.dashboard.new_scan"))
        new_btn.setProperty("role", "primary")
        new_btn.clicked.connect(self.new_scan.emit)
        self.open_btn = QPushButton(t("ui.dashboard.open_last"))
        self.open_btn.clicked.connect(
            lambda: self.open_scan.emit(self.last_id) if self.last_id else None
        )
        self.trend = pg.PlotWidget()
        self.trend.setLabel("left", t("report.overall"))
        self.trend.setYRange(0, 100)
        self.trend.showGrid(x=False, y=True, alpha=0.2)
        self.trend.setMinimumHeight(180)
        self.trend.getAxis("bottom").setTickSpacing(1, 1)  # scans are whole numbers

        rings = QHBoxLayout()
        box = QVBoxLayout()
        box.addWidget(self.overall)
        box.addWidget(label(t("report.overall"), "muted"))
        rings.addLayout(box)
        for key, ring in self.subs.items():
            b = QVBoxLayout()
            b.addWidget(ring)
            b.addWidget(label(t(f"report.sub.{key}"), "muted"))
            rings.addLayout(b)
        rings.addStretch(1)
        rings_widget = QWidget()
        rings_widget.setLayout(rings)
        actions = QHBoxLayout()
        actions.addWidget(new_btn)
        actions.addWidget(self.open_btn)
        actions.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addLayout(actions)
        layout.addWidget(card(rings_widget, self.open_counts))
        layout.addWidget(label(t("ui.dashboard.trend"), "h2"))
        layout.addWidget(self.trend, 1)
        state.scans_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        t = self.state.t
        scans = self.state.scans()
        self.open_btn.setEnabled(bool(scans))
        self.trend.clear()
        if not scans:
            self.subtitle.setText(t("ui.dashboard.empty"))
            return
        last = scans[0]
        self.last_id = last.scan_id
        self.subtitle.setText(
            t("ui.dashboard.last", target=last.target, date=last.created_at[:16].replace("T", " "))
        )
        report = self.state.report(last.scan_id)
        scores = (report or {}).get("scores") or {}
        self.overall.set_score(scores.get("overall"), scores.get("grade"))
        for key, ring in self.subs.items():
            ring.set_score(scores.get(key))
        findings = report_findings(report) if report else []
        crit = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        self.open_counts.setText(t("ui.dashboard.open", critical=crit, high=high))
        history = [s for s in reversed(scans) if s.overall is not None]
        if history:
            self.trend.plot(
                list(range(1, len(history) + 1)),
                [s.overall for s in history],
                pen=pg.mkPen("#2457d6", width=2),
                symbol="o",
            )
