"""Settings (SPEC §11.2.6): language, theme, limits, SLOs, weights, tools, suppressions, data."""

from __future__ import annotations

import asyncio

from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from secscope.core.advisories import osv_status, trivy_status, update_databases
from secscope.core.config import RateLimits, ScoreWeights, Settings, Slo
from secscope.core.downloader import install_tool
from secscope.core.scoring import DISPLAYED_SUBSCORES
from secscope.ui.state import AppState
from secscope.ui.widgets import label, run_in_background

WEIGHT_KEYS = ("security", "seo", "resilience", "quality", "dependencies")  # all of ScoreWeights


class SettingsPage(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self.state = state
        t = state.t
        s = state.settings
        self._tasks: list[object] = []

        self.language = QComboBox()
        self.language.addItem("Türkçe", "tr")  # language names are shown in their own language
        self.language.addItem("English", "en")
        self.language.setCurrentIndex(0 if s.language == "tr" else 1)
        self.theme = QComboBox()
        for value in ("system", "light", "dark"):
            self.theme.addItem(t(f"ui.settings.theme.{value}"), value)
        self.theme.setCurrentIndex(("system", "light", "dark").index(s.theme))
        self.log_level = QComboBox()
        for value in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self.log_level.addItem(value, value)
        self.log_level.setCurrentIndex(("DEBUG", "INFO", "WARNING", "ERROR").index(s.log_level))
        self.rps = self._spin(1, 1000, s.rate_limits.dast_rps, 1)
        self.p95 = self._spin(10, 60000, s.slo.p95_ms, 0)
        self.err_rate = self._spin(0, 100, s.slo.error_rate * 100, 1)
        self.weights = {k: self._spin(0, 100, getattr(s.weights, k) * 100, 0) for k in WEIGHT_KEYS}
        reset = QPushButton(t("ui.settings.weights.reset"))
        reset.clicked.connect(self._reset_weights)

        general = QFormLayout()
        general.addRow(t("ui.settings.language"), self.language)
        general.addRow(t("ui.settings.theme"), self.theme)
        general.addRow(t("ui.settings.log_level"), self.log_level)
        general.addRow(t("ui.settings.data_dir"), label(str(s.data_dir), "muted"))
        limits = QFormLayout()
        limits.addRow(t("ui.settings.rps"), self.rps)
        limits.addRow(t("ui.settings.p95"), self.p95)
        limits.addRow(t("ui.settings.error_rate"), self.err_rate)
        weights = QFormLayout()
        for key, spin in self.weights.items():
            name = t(f"report.sub.{key}")
            if key not in DISPLAYED_SUBSCORES:  # its weight is redistributed (ADR-009)
                name = t("ui.settings.weights.unmeasured", name=name)
            weights.addRow(name, spin)
        weights.addRow(reset)

        self.tools = QTableWidget(0, 4)
        self.tools.setHorizontalHeaderLabels(
            [t("ui.settings.tool"), t("report.status"), t("ui.settings.version"), ""]
        )
        self.tools.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tools.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.tools.setMinimumHeight(260)
        self.tools.verticalHeader().setVisible(False)
        self.tools.setAccessibleName(t("report.meta.tools"))
        self.db_status = label("", "muted")
        update_db = QPushButton(t("ui.settings.update_db"))
        update_db.clicked.connect(self._update_db)

        self.suppressions = QTableWidget(0, 3)
        self.suppressions.setHorizontalHeaderLabels(
            [t("ui.settings.suppressed_item"), t("ui.settings.reason"), t("ui.history.date")]
        )
        self.suppressions.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.suppressions.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.suppressions.verticalHeader().setVisible(False)
        remove = QPushButton(t("ui.settings.remove_suppression"))
        remove.clicked.connect(self._remove_suppression)
        delete_all = QPushButton(t("ui.settings.delete_all"))
        delete_all.clicked.connect(self._delete_all)
        save = QPushButton(t("ui.settings.save"))
        save.setProperty("role", "primary")
        save.clicked.connect(self.save)

        inner = QWidget()
        col = QVBoxLayout(inner)
        for title, layout in (
            ("ui.settings.general", general),
            ("ui.settings.limits", limits),
            ("ui.settings.weights", weights),
        ):
            box = QGroupBox(t(title))
            box.setLayout(layout)
            col.addWidget(box)
        tools_box = QGroupBox(t("ui.settings.tools"))
        tl = QVBoxLayout(tools_box)
        tl.addWidget(self.tools)
        row = QHBoxLayout()
        row.addWidget(self.db_status, 1)
        row.addWidget(update_db)
        tl.addLayout(row)
        col.addWidget(tools_box)
        sup_box = QGroupBox(t("report.meta.suppressed"))
        sl = QVBoxLayout(sup_box)
        sl.addWidget(self.suppressions)
        sl.addWidget(remove)
        col.addWidget(sup_box)
        data_box = QGroupBox(t("ui.settings.data"))
        dl = QVBoxLayout(data_box)
        dl.addWidget(delete_all)
        col.addWidget(data_box)
        col.addWidget(save)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        layout = QVBoxLayout(self)
        layout.addWidget(label(t("ui.nav.settings"), "h1"))
        layout.addWidget(scroll, 1)
        self.refresh()

    @staticmethod
    def _spin(lo: float, hi: float, value: float, decimals: int) -> QDoubleSpinBox:
        spin = QDoubleSpinBox()
        spin.setRange(lo, hi)
        spin.setDecimals(decimals)
        spin.setValue(value)
        return spin

    # ------------------------------------------------------------------ data

    def refresh(self) -> None:
        t = self.state.t
        manager = self.state.tools
        manager.refresh()
        statuses = manager.statuses()
        self.tools.setRowCount(len(statuses))
        for i, st in enumerate(statuses):
            text = (
                t("ui.settings.tool_ok")
                if st.available
                else (
                    st.install_hint.get(t.lang)
                    if st.install_hint
                    else t("ui.settings.tool_missing")
                )
            )
            self.tools.setItem(i, 0, QTableWidgetItem(st.name))
            self.tools.setItem(i, 1, QTableWidgetItem(text))
            self.tools.setItem(i, 2, QTableWidgetItem(st.version or ""))
            spec = manager.spec(st.name)
            if spec.downloads and not (st.available and st.source == "managed"):
                btn = QPushButton(t("ui.settings.install"))
                btn.setToolTip(t("ui.settings.install.tip"))
                btn.clicked.connect(lambda _c=False, name=st.name: self._install(name))
                self.tools.setCellWidget(i, 3, btn)
            else:
                self.tools.removeCellWidget(i, 3)
        data_dir = self.state.settings.data_dir
        dates = [
            f"{s.tool} {s.updated_at:%Y-%m-%d}"
            for s in (trivy_status(data_dir), osv_status(data_dir))
            if s.present and s.updated_at
        ]
        self.db_status.setText(
            t("report.meta.advisory_db") + ": " + (", ".join(dates) or t("ui.settings.no_db"))
        )
        sups = self.state.suppressions()
        self.suppressions.setRowCount(len(sups))
        for i, r in enumerate(sups):
            item = QTableWidgetItem(r["rule_id"] or r["finding_id"])
            item.setData(256, r["id"])
            self.suppressions.setItem(i, 0, item)
            self.suppressions.setItem(i, 1, QTableWidgetItem(r["reason"]))
            self.suppressions.setItem(
                i, 2, QTableWidgetItem(str(r["created_at"])[:19].replace("T", " "))
            )

    def _reset_weights(self) -> None:
        defaults = ScoreWeights()
        for key, spin in self.weights.items():
            spin.setValue(getattr(defaults, key) * 100)

    def save(self) -> bool:
        t = self.state.t
        try:
            total = sum(s.value() for s in self.weights.values()) or 1
            settings = self.state.settings.model_copy(
                update={
                    "language": self.language.currentData(),
                    "theme": self.theme.currentData(),
                    "log_level": self.log_level.currentData(),
                    "rate_limits": RateLimits(
                        dast_rps=self.rps.value(),
                        circuit_breaker_5xx_ratio=self.state.settings.rate_limits.circuit_breaker_5xx_ratio,
                    ),
                    "slo": Slo(p95_ms=self.p95.value(), error_rate=self.err_rate.value() / 100),
                    "weights": ScoreWeights(
                        **{k: round(s.value() / total, 4) for k, s in self.weights.items()}
                    ),
                }
            )
            settings = Settings.model_validate(settings.model_dump())
        except ValueError as exc:
            QMessageBox.warning(self, t("ui.settings.save"), str(exc))
            return False
        language_changed = settings.language != self.state.settings.language
        self.state.save_settings(settings)
        if language_changed:
            QMessageBox.information(self, t("ui.settings.save"), t("ui.settings.restart"))
        return True

    # --------------------------------------------------------------- actions

    def _install(self, name: str) -> None:
        t = self.state.t
        self.db_status.setText(t("ui.settings.installing", tool=name))
        manager = self.state.tools
        task = run_in_background(
            lambda: install_tool(manager, name),
            lambda _r: self.refresh(),
            lambda err: self._warn(t("ui.settings.install"), err),
        )
        self._tasks.append(task)

    def _update_db(self) -> None:
        t = self.state.t
        self.db_status.setText(t("ui.settings.updating_db"))
        tools, data_dir = self.state.tools, self.state.settings.data_dir
        task = run_in_background(
            lambda: asyncio.run(update_databases(tools, data_dir)),
            lambda _r: self.refresh(),
            lambda err: self._warn(t("ui.settings.update_db"), err),
        )
        self._tasks.append(task)

    def _warn(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)

    def _remove_suppression(self) -> None:
        for index in self.suppressions.selectionModel().selectedRows():
            item = self.suppressions.item(index.row(), 0)
            if item is not None:
                self.state.remove_suppression(int(item.data(256)))
        self.refresh()

    def _delete_all(self) -> None:
        t = self.state.t
        answer = QMessageBox.question(
            self, t("ui.settings.delete_all"), t("ui.settings.delete_all.confirm")
        )
        if answer == QMessageBox.StandardButton.Yes:
            n = self.state.delete_all_scans()
            QMessageBox.information(
                self, t("ui.settings.delete_all"), t("ui.settings.deleted", count=n)
            )
