"""Minimal main window (M1): start a scan against a loopback URL and watch events.

The full multi-page UI (dashboard, wizard, results…) arrives in M9.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.events import CancelCommand, Event, PauseCommand, ResumeCommand, StartCommand
from secscope.ui.formatting import describe
from secscope.ui.i18n import Translator
from secscope.ui.worker_bridge import WorkerBridge


class MainWindow(QMainWindow):
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        worker_env: Mapping[str, str] | None = None,
        modules: Sequence[str] = (),
        extra_modules: Sequence[str] = (),
    ) -> None:
        super().__init__()
        self.settings = settings or Settings.load()
        self.t = Translator(self.settings.language)
        self._worker_env = worker_env
        self._modules = list(modules)
        self._extra_modules = list(extra_modules)
        self._paused = False
        self.events: list[Event] = []

        self.setWindowTitle(self.t("app.title"))
        self.bridge = WorkerBridge(self)
        self.bridge.event_received.connect(self._on_event)
        self.bridge.finished.connect(self._on_finished)

        self.target = QLineEdit()
        self.target.setPlaceholderText(self.t("target.placeholder"))
        self.target.setAccessibleName(self.t("target.label"))
        self.scope_ok = QCheckBox(self.t("scope.statement"))
        self.start_btn = QPushButton(self.t("action.start"))
        self.pause_btn = QPushButton(self.t("action.pause"))
        self.cancel_btn = QPushButton(self.t("action.cancel"))
        self.event_list = QListWidget()
        self.event_list.setAccessibleName(self.t("window.events"))
        self.status = QLabel(self.t("status.idle"))

        self.start_btn.clicked.connect(self.start_scan)
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.scope_ok.toggled.connect(self._update_buttons)
        self.target.textChanged.connect(self._update_buttons)

        top = QHBoxLayout()
        top.addWidget(QLabel(self.t("target.label")))
        top.addWidget(self.target, 1)
        buttons = QHBoxLayout()
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.pause_btn)
        buttons.addWidget(self.cancel_btn)
        buttons.addStretch(1)
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.scope_ok)
        layout.addLayout(buttons)
        layout.addWidget(QLabel(self.t("window.events")))
        layout.addWidget(self.event_list, 1)
        layout.addWidget(self.status)
        root = QWidget()
        root.setLayout(layout)
        self.setCentralWidget(root)
        self.resize(900, 600)
        self._update_buttons()

    def _update_buttons(self) -> None:
        running = self.bridge.running
        self.start_btn.setEnabled(
            not running and self.scope_ok.isChecked() and bool(self.target.text().strip())
        )
        self.pause_btn.setEnabled(running)
        self.cancel_btn.setEnabled(running)

    def start_scan(self) -> None:
        config = ScanConfig(
            target=Target(kind=TargetKind.URL, value=self.target.text().strip()),
            scope_statement_accepted=self.scope_ok.isChecked(),
        )
        command = StartCommand(
            config=config.model_dump(mode="json"),
            settings=self.settings.model_dump(mode="json"),
            modules=self._modules,
            extra_modules=self._extra_modules,
        )
        self.event_list.clear()
        self.events.clear()
        self._paused = False
        self.pause_btn.setText(self.t("action.pause"))
        self.bridge.start(command, env=self._worker_env)
        self.status.setText(self.t("status.running"))
        self._update_buttons()

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        self.bridge.send(PauseCommand() if self._paused else ResumeCommand())
        self.pause_btn.setText(self.t("action.resume" if self._paused else "action.pause"))

    def cancel_scan(self) -> None:
        self.bridge.send(CancelCommand())

    def _on_event(self, event: Event) -> None:
        self.events.append(event)
        line = describe(event, self.t)
        if line is not None:
            self.event_list.addItem(line)
            self.event_list.scrollToBottom()
        if event.type == "scan.finished":
            self.status.setText(self.t("status.finished", status=event.status))

    def _on_finished(self, _code: int, crashed: bool) -> None:
        if crashed:
            self.status.setText(self.t("status.worker_crashed"))
        self._update_buttons()

    def closeEvent(self, event: object) -> None:  # noqa: N802 - Qt override
        self.bridge.shutdown()
        super().closeEvent(event)  # type: ignore[arg-type]
