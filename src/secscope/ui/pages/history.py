"""History and comparison (SPEC §11.2.5): stored scans, open one, diff two."""

from __future__ import annotations

import html

from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from secscope.reporting.diff import diff_reports
from secscope.ui.state import AppState, ScanRow
from secscope.ui.theme import SEVERITY_COLORS
from secscope.ui.widgets import label


class HistoryPage(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self.state = state
        t = state.t
        self.rows: list[ScanRow] = []
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            [
                t("ui.history.date"),
                t("report.target"),
                t("report.status"),
                t("report.overall"),
                t("ui.history.grade"),
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAccessibleName(t("ui.nav.history"))
        self.table.itemSelectionChanged.connect(self._buttons)
        self.open_btn = QPushButton(t("ui.history.open"))
        self.diff_btn = QPushButton(t("ui.history.compare"))
        self.open_btn.clicked.connect(self.open_selected)
        self.diff_btn.clicked.connect(self.compare_selected)
        self.diff_view = QTextBrowser()
        self.diff_view.setAccessibleName(t("ui.history.compare"))
        buttons = QHBoxLayout()
        buttons.addWidget(label(t("ui.history.hint"), "muted"), 1)
        buttons.addWidget(self.open_btn)
        buttons.addWidget(self.diff_btn)
        split = QSplitter()
        split.addWidget(self.table)
        split.addWidget(self.diff_view)
        split.setSizes([650, 450])
        layout = QVBoxLayout(self)
        layout.addWidget(label(t("ui.nav.history"), "h1"))
        layout.addLayout(buttons)
        layout.addWidget(split, 1)
        state.scans_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        self.rows = self.state.scans()
        self.table.setRowCount(len(self.rows))
        for i, r in enumerate(self.rows):
            values = (
                r.created_at[:19].replace("T", " "),
                r.target,
                r.status,
                "" if r.overall is None else f"{r.overall:.1f}",
                r.grade or "",
            )
            for col, value in enumerate(values):
                self.table.setItem(i, col, QTableWidgetItem(value))
        self._buttons()

    def _selected(self) -> list[ScanRow]:
        return [self.rows[i.row()] for i in self.table.selectionModel().selectedRows()]

    def _buttons(self) -> None:
        n = len(self._selected())
        self.open_btn.setEnabled(n == 1)
        self.diff_btn.setEnabled(n == 2)

    def open_selected(self) -> None:
        chosen = self._selected()
        if len(chosen) == 1:
            self.state.scan_opened.emit(chosen[0].scan_id)

    def compare_selected(self) -> None:
        t = self.state.t
        chosen = sorted(self._selected(), key=lambda r: r.created_at)
        if len(chosen) != 2:
            return
        before, after = (self.state.report(r.scan_id) for r in chosen)
        if before is None or after is None:
            self.diff_view.setPlainText(
                t("ui.results.missing", scan=", ".join(r.scan_id for r in chosen))
            )
            return
        d = diff_reports(before, after)
        s = d.summary()
        e = html.escape
        lines = [
            f"<h2>{e(t('ui.history.compare'))}</h2>",
            f"<p>{e(t('ui.diff.summary', new=s['new'], high=s['new_critical_or_high'], fixed=s['fixed'], persistent=s['persistent'], regressed=s['regressed']))}</p>",
        ]
        deltas = ", ".join(
            f"{e(t('report.sub.' + k) if k != 'overall' else t('report.overall'))} {v:+}"
            for k, v in s["score_delta"].items()
            if v is not None
        )
        if deltas:
            lines.append(f"<p>{deltas}</p>")
        for title_key, items in (("ui.diff.new", d.new), ("ui.diff.fixed", d.fixed)):
            if items:
                rows = "".join(
                    f"<li><b style='color:{SEVERITY_COLORS[f.severity]}'>{e(t('report.sev.' + f.severity))}</b> {e(f.title.get(t.lang))} <code>{e(f.location.display())}</code></li>"
                    for f in items[:200]
                )
                lines.append(f"<h3>{e(t(title_key))} ({len(items)})</h3><ul>{rows}</ul>")
        if d.regressed:
            rows = "".join(
                f"<li>{e(a.severity)} → {e(b.severity)} {e(b.title.get(t.lang))}</li>"
                for a, b in d.regressed
            )
            lines.append(
                f"<h3>{e(t('ui.diff.regressed'))} ({len(d.regressed)})</h3><ul>{rows}</ul>"
            )
        self.diff_view.setHtml("".join(lines))
