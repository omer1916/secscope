"""Main window (SPEC §11.2): navigation + dashboard, wizard, live monitor, results, history, settings.

All scanning happens in the worker process; the UI thread only renders events.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from PySide6.QtCore import QByteArray, QSettings, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QMainWindow, QStackedWidget, QWidget

from secscope.__about__ import __app_id__, __app_name__
from secscope.core.config import ScanConfig
from secscope.core.events import StartCommand
from secscope.core.session import new_scan_id
from secscope.modules.registry import load_builtin
from secscope.ui.pages.dashboard import DashboardPage
from secscope.ui.pages.history import HistoryPage
from secscope.ui.pages.monitor import MonitorPage
from secscope.ui.pages.results import ResultsPage
from secscope.ui.pages.settings_page import SettingsPage
from secscope.ui.pages.wizard import WizardPage
from secscope.ui.state import AppState

PAGES = ("dashboard", "wizard", "monitor", "results", "history", "settings")


class MainWindow(QMainWindow):
    def __init__(
        self,
        state: AppState | None = None,
        *,
        worker_env: Mapping[str, str] | None = None,
        extra_modules: Sequence[str] = (),
    ) -> None:
        super().__init__()
        self.state = state or AppState()
        t = self.state.t
        self.extra_modules = list(extra_modules)
        registry = load_builtin(self.extra_modules)
        self.setWindowTitle(t("app.title"))

        self.dashboard = DashboardPage(self.state)
        self.wizard = WizardPage(self.state, registry)
        self.monitor = MonitorPage(self.state, worker_env=worker_env)
        self.results = ResultsPage(self.state)
        self.history = HistoryPage(self.state)
        self.settings_page = SettingsPage(self.state)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setAccessibleName(t("ui.nav.title"))
        self.stack = QStackedWidget()
        for key, page in zip(
            PAGES,
            (
                self.dashboard,
                self.wizard,
                self.monitor,
                self.results,
                self.history,
                self.settings_page,
            ),
            strict=True,
        ):
            self.nav.addItem(t(f"ui.nav.{key}"))
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        self.dashboard.new_scan.connect(self.open_wizard)
        self.dashboard.open_scan.connect(self.open_results)
        self.wizard.start_requested.connect(self.start_scan)
        self.monitor.scan_finished.connect(self._scan_finished)
        self.state.scan_opened.connect(self.open_results)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.addWidget(self.nav)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        self.resize(1280, 820)
        self._restore_geometry()
        self.go("dashboard")

    # -------------------------------------------------------------- navigation

    def go(self, page: str) -> None:
        self.nav.setCurrentRow(PAGES.index(page))

    def open_wizard(self) -> None:
        self.wizard.reset()
        self.go("wizard")

    def open_results(self, scan_id: str) -> None:
        if self.results.load(scan_id):
            self.go("results")

    def start_scan(self, config: ScanConfig, modules: list[str]) -> None:
        command = StartCommand(
            config=config.model_dump(mode="json"),
            settings=self.state.settings.model_dump(mode="json"),
            scan_id=new_scan_id(),
            modules=modules,
            extra_modules=self.extra_modules,
        )
        self.monitor.start(command)
        self.go("monitor")

    def _scan_finished(self, scan_id: str, _status: str, _crashed: bool) -> None:
        # Partial results of an interrupted scan are still in report.json when available.
        self.open_results(scan_id)

    # ------------------------------------------------------------- geometry

    def _qsettings(self) -> QSettings:
        return QSettings(__app_name__, __app_id__)

    def _restore_geometry(self) -> None:
        geometry = self._qsettings().value("window/geometry")
        if isinstance(geometry, QByteArray):
            self.restoreGeometry(geometry)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override
        self._qsettings().setValue("window/geometry", self.saveGeometry())
        self.monitor.bridge.shutdown()
        super().closeEvent(event)
