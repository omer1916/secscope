"""New-scan wizard (SPEC §11.2.2): source → detected project → modules → confirmation.

The authentication step of the spec is omitted in this build because authenticated
dynamic testing is not part of it (ADR-009).
"""

from __future__ import annotations

import shlex
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from secscope.core.archive import is_archive
from secscope.core.config import RunConfig, ScanConfig, ScanProfile, Target, TargetKind
from secscope.core.fingerprint import Fingerprint, fingerprint
from secscope.core.scope_guard import ScopeGuard
from secscope.modules.registry import ModuleRegistry
from secscope.ui.state import AppState
from secscope.ui.widgets import label


class WizardPage(QWidget):
    start_requested = Signal(object, list)  # ScanConfig, module ids

    def __init__(self, state: AppState, registry: ModuleRegistry) -> None:
        super().__init__()
        self.state = state
        self.registry = registry
        t = state.t
        self.fp: Fingerprint | None = None
        self.setAcceptDrops(True)

        self.steps = QStackedWidget()
        self.title = label("", "h1")
        self.back_btn = QPushButton(t("ui.wizard.back"))
        self.next_btn = QPushButton(t("ui.wizard.next"))
        self.next_btn.setProperty("role", "primary")
        self.back_btn.clicked.connect(self._back)
        self.next_btn.clicked.connect(self._next)

        # Step 1: source
        self.kind_folder = QRadioButton(t("ui.wizard.kind.folder"))
        self.kind_archive = QRadioButton(t("ui.wizard.kind.archive"))
        self.kind_url = QRadioButton(t("ui.wizard.kind.url"))
        self.kind_folder.setChecked(True)
        group = QButtonGroup(self)
        for b in (self.kind_folder, self.kind_archive, self.kind_url):
            group.addButton(b)
            b.toggled.connect(self._validate)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(t("ui.wizard.path.placeholder"))
        self.path_edit.setAccessibleName(t("ui.wizard.path.placeholder"))
        self.path_edit.textChanged.connect(self._validate)
        browse = QPushButton(t("ui.wizard.browse"))
        browse.clicked.connect(self._browse)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText(t("target.placeholder"))
        self.url_edit.setAccessibleName(t("target.label"))
        self.url_edit.textChanged.connect(self._validate)
        self.source_error = label("", "muted")
        row = QHBoxLayout()
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse)
        s1 = QVBoxLayout()
        s1.addWidget(label(t("ui.wizard.source.hint"), "muted"))
        for b in (self.kind_folder, self.kind_archive, self.kind_url):
            s1.addWidget(b)
        s1.addLayout(row)
        s1.addWidget(self.url_edit)
        s1.addWidget(self.source_error)
        s1.addStretch(1)
        self.steps.addWidget(self._wrap(s1))

        # Step 2: detected project
        self.detected = label("", "h2")
        self.notes = label("", "muted")
        self.run_cmd = QLineEdit()
        self.run_cmd.setAccessibleName(t("ui.wizard.run_command"))
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText(t("ui.wizard.port_auto"))
        self.ready_path = QLineEdit("/")
        self.install = QCheckBox(t("ui.wizard.install"))
        self.public_url = QLineEdit()
        self.public_url.setPlaceholderText("https://www.example.com")  # an example URL, not UI copy
        self.exclude = QLineEdit()
        self.exclude.setPlaceholderText(t("ui.wizard.exclude.placeholder"))
        self.exclude.setToolTip(t("ui.wizard.exclude.hint"))
        form = QFormLayout()
        form.addRow(t("ui.wizard.run_command"), self.run_cmd)
        form.addRow(t("ui.wizard.port"), self.port)
        form.addRow(t("ui.wizard.ready_path"), self.ready_path)
        form.addRow(t("ui.wizard.public_url"), self.public_url)
        form.addRow(t("ui.wizard.exclude"), self.exclude)
        s2 = QVBoxLayout()
        s2.addWidget(self.detected)
        s2.addWidget(self.notes)
        s2.addLayout(form)
        s2.addWidget(self.install)
        s2.addWidget(label(t("ui.wizard.install.hint"), "muted"))
        s2.addStretch(1)
        self.steps.addWidget(self._wrap(s2))

        # Step 3: profile and modules
        self.profile = QComboBox()
        for p in (ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.CUSTOM):
            self.profile.addItem(t(f"ui.profile.{p.value}"), p.value)
        self.profile.setCurrentIndex(1)
        self.profile.currentIndexChanged.connect(self._apply_profile)
        self.module_list = QListWidget()
        self.module_list.setAccessibleName(t("ui.wizard.modules"))
        form3 = QFormLayout()
        form3.addRow(t("ui.wizard.profile"), self.profile)
        s3 = QVBoxLayout()
        s3.addLayout(form3)
        s3.addWidget(label(t("ui.wizard.modules"), "h2"))
        s3.addWidget(self.module_list, 1)
        self.steps.addWidget(self._wrap(s3))

        # Step 4: confirmation
        self.scope_ok = QCheckBox(t("scope.statement"))
        self.scope_ok.toggled.connect(self._validate)
        self.snapshot = QCheckBox(t("ui.wizard.snapshot"))
        self.snapshot.setChecked(True)
        self.summary = QTextBrowser()
        s4 = QVBoxLayout()
        s4.addWidget(self.summary, 1)
        s4.addWidget(self.snapshot)
        s4.addWidget(self.scope_ok)
        s4.addWidget(label(t("ui.wizard.scope.hint"), "muted"))
        self.steps.addWidget(self._wrap(s4))

        nav = QHBoxLayout()
        nav.addWidget(self.back_btn)
        nav.addStretch(1)
        nav.addWidget(self.next_btn)
        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addWidget(self.steps, 1)
        layout.addLayout(nav)
        self._populate_modules()
        self._show(0)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _wrap(inner: QVBoxLayout) -> QWidget:
        w = QWidget()
        w.setLayout(inner)
        return w

    def reset(self) -> None:
        self.path_edit.clear()
        self.url_edit.clear()
        self.scope_ok.setChecked(False)
        self._show(0)

    def _kind(self) -> TargetKind:
        if self.kind_url.isChecked():
            return TargetKind.URL
        return TargetKind.ARCHIVE if self.kind_archive.isChecked() else TargetKind.FOLDER

    def _browse(self) -> None:
        t = self.state.t
        if self.kind_folder.isChecked():
            path = QFileDialog.getExistingDirectory(self, t("ui.wizard.kind.folder"))
        else:
            path, _ = QFileDialog.getOpenFileName(
                self,
                t("ui.wizard.kind.archive"),
                filter="*.zip *.tar *.tar.gz *.tgz *.tar.bz2 *.tar.xz",
            )
        if path:
            self.path_edit.setText(path)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 - Qt override
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802 - Qt override
        urls = event.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        (self.kind_archive if path.is_file() else self.kind_folder).setChecked(True)
        self.path_edit.setText(str(path))

    def _source_problem(self) -> str | None:
        t = self.state.t
        kind = self._kind()
        self.path_edit.setEnabled(kind != TargetKind.URL)
        self.url_edit.setEnabled(kind == TargetKind.URL)
        if kind == TargetKind.URL:
            url = self.url_edit.text().strip()
            if not url:
                return ""
            decision = ScopeGuard().check(url)
            return (
                None
                if decision.allowed
                else t("ui.wizard.error.scope", reason=decision.reason.value)
            )
        path = Path(self.path_edit.text().strip())
        if not self.path_edit.text().strip():
            return ""
        if kind == TargetKind.FOLDER and not path.is_dir():
            return t("ui.wizard.error.folder")
        if kind == TargetKind.ARCHIVE and not (path.is_file() and is_archive(path)):
            return t("ui.wizard.error.archive")
        return None

    def _validate(self) -> None:
        index = self.steps.currentIndex()
        if index == 0:
            problem = self._source_problem()
            self.source_error.setText(problem or "")
            self.next_btn.setEnabled(problem is None)
        elif index == self.steps.count() - 1:
            self.next_btn.setEnabled(self.scope_ok.isChecked() and bool(self.selected_modules()))
        else:
            self.next_btn.setEnabled(True)

    def _show(self, index: int) -> None:
        t = self.state.t
        self.steps.setCurrentIndex(index)
        self.title.setText(
            t(
                "ui.wizard.title",
                step=index + 1,
                total=self.steps.count(),
                name=t(f"ui.wizard.step.{index + 1}"),
            )
        )
        self.back_btn.setEnabled(index > 0)
        last = index == self.steps.count() - 1
        self.next_btn.setText(t("action.start") if last else t("ui.wizard.next"))
        if index == 1:
            self._detect()
        if last:
            self._summarise()
        self._validate()

    def _back(self) -> None:
        self._show(max(0, self.steps.currentIndex() - 1))

    def _next(self) -> None:
        index = self.steps.currentIndex()
        if index == self.steps.count() - 1:
            self.start_requested.emit(self.config(), self.selected_modules())
            return
        if index == 0 and self._kind() == TargetKind.URL:
            self._show(2)  # nothing to detect for a running URL
            return
        self._show(index + 1)

    # ------------------------------------------------------------ steps 2 – 4

    def _detect(self) -> None:
        t = self.state.t
        self.fp = None
        if self._kind() == TargetKind.FOLDER:
            self.fp = fingerprint(Path(self.path_edit.text().strip()))
        if self.fp is None:
            self.detected.setText(t("ui.wizard.detect.later"))
            self.notes.setText("")
            return
        fp = self.fp
        self.detected.setText(
            t("ui.wizard.detected", stack=fp.stack, kind=t(f"ui.wizard.kind.{fp.kind}"))
        )
        self.notes.setText(" · ".join([*fp.languages, *fp.notes]))
        self.run_cmd.setText(shlex.join(fp.run_command) if fp.run_command else "")
        self.ready_path.setText(fp.ready_path)

    def _populate_modules(self) -> None:
        t = self.state.t
        self.module_list.clear()
        for cls in self.registry.classes():
            missing = [
                tool for tool in cls.requires.tools if not self.state.tools.status(tool).available
            ]
            text = cls.title.get(t.lang)
            if missing:
                text += " — " + t("ui.wizard.tool_missing", tools=", ".join(missing))
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, cls.id)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.module_list.addItem(item)
        self._apply_profile()

    def _apply_profile(self) -> None:
        value = self.profile.currentData()
        if value == ScanProfile.CUSTOM.value:
            return
        wanted = set(self.registry.for_profile(ScanProfile(value)))
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            checked = item.data(Qt.ItemDataRole.UserRole) in wanted
            item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)

    def selected_modules(self) -> list[str]:
        out: list[str] = []
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                out.append(str(item.data(Qt.ItemDataRole.UserRole)))
        return out

    def config(self) -> ScanConfig:
        kind = self._kind()
        value = (
            self.url_edit.text().strip()
            if kind == TargetKind.URL
            else str(Path(self.path_edit.text().strip()).resolve())
        )
        command = (
            shlex.split(self.run_cmd.text(), posix=True) if self.run_cmd.text().strip() else None
        )
        return ScanConfig(
            target=Target(kind=kind, value=value),
            profile=ScanProfile(self.profile.currentData()),
            modules=self.selected_modules(),
            run=RunConfig(
                command=command if command != (self.fp.run_command if self.fp else None) else None,
                port=self.port.value() or None,
                ready_path=self.ready_path.text().strip() or "/",
                install=self.install.isChecked(),
            ),
            scope_statement_accepted=self.scope_ok.isChecked(),
            snapshot_sqlite=self.snapshot.isChecked(),
            public_url=self.public_url.text().strip() or None,
            exclude=[p.strip() for p in self.exclude.text().split(",") if p.strip()],
        )

    def _summarise(self) -> None:
        t = self.state.t
        cfg = self.config()
        titles = [self.registry.get(m).title.get(t.lang) for m in cfg.modules]
        rows = [
            (t("report.target"), cfg.target.value),
            (t("ui.wizard.profile"), t(f"ui.profile.{cfg.profile.value}")),
            (t("ui.wizard.modules"), ", ".join(titles) or "–"),
        ]
        if cfg.run.install:
            rows.append((t("ui.wizard.install"), "✓"))
        import html  # noqa: PLC0415

        body = "".join(
            f"<tr><th align=left>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
            for k, v in rows
        )
        self.summary.setHtml(
            f"<h3>{html.escape(t('ui.wizard.summary'))}</h3><table cellpadding=4>{body}</table>"
        )
