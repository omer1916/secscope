"""Results (SPEC §11.2.4): score cards, category tree, findings table, detail panel."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from PySide6.QtCore import QModelIndex, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from secscope.core.models import SEVERITY_ORDER, Finding
from secscope.core.scoring import DISPLAYED_SUBSCORES
from secscope.reporting.ai_prompt import render_ai_prompt
from secscope.reporting.json_export import report_findings
from secscope.reporting.writer import ReportFormatError, write_outputs
from secscope.ui.state import AppState
from secscope.ui.theme import SEVERITY_COLORS
from secscope.ui.widgets import FindingsFilter, FindingsModel, ScoreRing, label

SUB_SCORES = DISPLAYED_SUBSCORES


def _code(text: str, background: str) -> str:
    # A one-cell table is the reliable way to give a block a background in Qt rich text.
    return (
        f"<table width='100%' cellpadding='6' bgcolor='{background}'><tr><td>"
        f"<pre style='font-family: Consolas, monospace'>{html.escape(text)}</pre></td></tr></table>"
    )


def finding_html(f: Finding, t: Any, code_background: str = "#eef1f5") -> str:
    """Detail panel HTML. Every value is escaped: findings carry text from the target."""
    e = html.escape
    lang = t.lang
    color = SEVERITY_COLORS[f.severity]
    parts = [
        f"<h2>{e(f.title.get(lang))}</h2>",
        f"<p><b style='color:{color}'>{e(t(f'report.sev.{f.severity}'))}</b> · <code>{e(f.rule_id)}</code> · "
        f"{e(t('report.col.confidence'))}: {e(t.confidence(f.confidence))} · {e(t('report.col.tools'))}: {e(t.tools(f.source_tools))}</p>",
        f"<p><code>{e(f.location.short())}</code></p>",
    ]
    if f.description:
        parts.append(
            f"<h3>{e(t('report.detail.description'))}</h3><p>{e(f.description.get(lang))}</p>"
        )
    if f.impact:
        parts.append(f"<h3>{e(t('report.detail.impact'))}</h3><p>{e(f.impact.get(lang))}</p>")
    if f.evidence.snippet:
        parts.append(
            f"<h3>{e(t('report.detail.evidence'))}</h3>{_code(f.evidence.snippet, code_background)}"
        )
    if f.evidence.extra:
        rows = "".join(
            f"<tr><th align=left>{e(k)}</th><td>{e(v)}</td></tr>"
            for k, v in f.evidence.extra.items()
        )
        parts.append(f"<table cellpadding=3>{rows}</table>")
    if f.remediation:
        steps = "".join(f"<li>{e(s)}</li>" for s in f.remediation.steps.get(lang))
        parts.append(f"<h3>{e(t('report.detail.fix'))}</h3><ol>{steps}</ol>")
        for stack, snippet in list(f.remediation.snippets.items())[:3]:
            parts.append(f"<p><b>{e(stack)}</b></p>{_code(snippet.code, code_background)}")
    if f.references:
        refs = "".join(
            f"<li><a href='{e(r.href)}'>{e(r.title or r.href)}</a></li>"
            if r.href
            else f"<li>{e(r.type.upper())} {e(r.id or '')}</li>"
            for r in f.references
        )
        parts.append(f"<h3>{e(t('report.detail.references'))}</h3><ul>{refs}</ul>")
    return "".join(parts)


class ResultsPage(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self.state = state
        t = state.t
        self.report: dict[str, Any] | None = None
        self.scan_id: str | None = None

        self.heading = label(t("ui.results.empty"), "h1")
        self.rings: dict[str, ScoreRing] = {}
        rings = QHBoxLayout()
        for key in ("overall", *SUB_SCORES):
            box = QVBoxLayout()
            ring = ScoreRing(t("report.overall") if key == "overall" else t(f"report.sub.{key}"))
            self.rings[key] = ring
            box.addWidget(ring)
            caption = label(
                t("report.overall") if key == "overall" else t(f"report.sub.{key}"), "muted"
            )
            if key == "overall":
                self.overall_label = caption
            box.addWidget(caption)
            rings.addLayout(box)
        rings.addStretch(1)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAccessibleName(t("ui.results.categories"))
        self.tree.itemSelectionChanged.connect(self._category_changed)

        self.model = FindingsModel(t, self)
        self.proxy = FindingsFilter(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.table.horizontalHeader()
        for col in (0, 1, 4, 5):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.setAccessibleName(t("report.findings"))
        self.table.selectionModel().currentRowChanged.connect(self._show_detail)

        self.search = QLineEdit()
        self.search.setPlaceholderText(t("report.filter.search"))
        self.search.setAccessibleName(t("report.filter.search"))
        self.search.textChanged.connect(self.proxy.set_text)
        self.sev_boxes: dict[str, QCheckBox] = {}
        filters = QHBoxLayout()
        filters.addWidget(self.search, 1)
        for sev in sorted(SEVERITY_ORDER, key=lambda s: -SEVERITY_ORDER[s]):  # type: ignore[index]
            box = QCheckBox(t(f"report.sev.{sev}"))
            box.setChecked(True)
            box.toggled.connect(self._severity_changed)
            self.sev_boxes[sev] = box
            filters.addWidget(box)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        self.detail.setAccessibleName(t("ui.results.detail"))
        self.copy_btn = QPushButton(t("ui.results.copy_fix"))
        self.suppress_btn = QPushButton(t("ui.results.suppress"))
        self.copy_btn.clicked.connect(self.copy_fix)
        self.suppress_btn.clicked.connect(self.suppress_selected)
        detail_box = QWidget()
        dl = QVBoxLayout(detail_box)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addWidget(self.detail, 1)
        dbtns = QHBoxLayout()
        dbtns.addWidget(self.copy_btn)
        dbtns.addWidget(self.suppress_btn)
        dl.addLayout(dbtns)

        self.open_btn = QPushButton(t("ui.results.open_report"))
        self.ai_btn = QPushButton(t("ui.results.copy_ai"))
        self.ai_btn.setToolTip(t("ui.results.copy_ai.hint"))
        self.export_btn = QPushButton(t("ui.results.export"))
        self.open_btn.clicked.connect(self.open_report)
        self.ai_btn.clicked.connect(self.copy_for_ai)
        self.export_btn.clicked.connect(self.export)
        top = QHBoxLayout()
        top.addWidget(self.heading, 1)
        top.addWidget(self.open_btn)
        top.addWidget(self.ai_btn)
        top.addWidget(self.export_btn)

        middle = QWidget()
        ml = QVBoxLayout(middle)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.addLayout(filters)
        ml.addWidget(self.table, 1)
        split = QSplitter()
        split.addWidget(self.tree)
        split.addWidget(middle)
        split.addWidget(detail_box)
        split.setSizes([180, 620, 420])
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addLayout(rings)
        layout.addWidget(split, 1)
        self._enable(False)

    # -------------------------------------------------------------------- load

    def _enable(self, on: bool) -> None:
        for w in (self.open_btn, self.export_btn, self.copy_btn, self.suppress_btn):
            w.setEnabled(on)

    def load(self, scan_id: str) -> bool:
        t = self.state.t
        report = self.state.report(scan_id)
        if report is None:
            self.heading.setText(t("ui.results.missing", scan=scan_id))
            self._enable(False)
            return False
        self.report = report
        self.scan_id = scan_id
        findings = report_findings(report)
        self.model.set_findings(findings)
        self.proxy.sort(0, Qt.SortOrder.AscendingOrder)
        scores: dict[str, Any] = report.get("scores") or {}
        self.heading.setText(
            t("ui.results.heading", target=report["target"]["value"], count=len(findings))
        )
        self.rings["overall"].set_score(scores.get("overall"))
        grade = scores.get("grade")
        self.overall_label.setText(
            t("report.overall")
            + (f" · {t('ui.dashboard.grade', grade=grade)}" if grade and grade != "–" else "")
        )
        for key in SUB_SCORES:
            self.rings[key].set_score(scores.get(key))
        self._fill_tree(findings)
        self.detail.clear()
        self._enable(True)
        if self.proxy.rowCount():
            self.table.selectRow(0)
        return True

    def _fill_tree(self, findings: list[Finding]) -> None:
        t = self.state.t
        self.tree.clear()
        root = QTreeWidgetItem([t("ui.results.all", count=len(findings))])
        root.setData(0, Qt.ItemDataRole.UserRole, None)
        self.tree.addTopLevelItem(root)
        by_cat: dict[str, dict[str, int]] = {}
        for f in findings:
            by_cat.setdefault(f.category.value, {}).setdefault(f.module, 0)
            by_cat[f.category.value][f.module] += 1
        for cat, modules in sorted(by_cat.items()):
            item = QTreeWidgetItem([f"{t(f'ui.category.{cat}')} ({sum(modules.values())})"])
            item.setData(0, Qt.ItemDataRole.UserRole, cat)
            for module, n in sorted(modules.items()):
                child = QTreeWidgetItem([f"{t.module(module)} ({n})"])
                child.setData(0, Qt.ItemDataRole.UserRole, module)
                item.addChild(child)
            root.addChild(item)
        self.tree.expandAll()

    # ---------------------------------------------------------------- actions

    def _category_changed(self) -> None:
        items = self.tree.selectedItems()
        self.proxy.set_category(items[0].data(0, Qt.ItemDataRole.UserRole) if items else None)

    def _severity_changed(self) -> None:
        self.proxy.set_severities({s for s, b in self.sev_boxes.items() if b.isChecked()})

    def selected(self) -> list[Finding]:
        rows = {self.proxy.mapToSource(i).row() for i in self.table.selectionModel().selectedRows()}
        return [self.model.finding(r) for r in sorted(rows)]

    def _show_detail(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            return
        f = self.model.finding(self.proxy.mapToSource(current).row())
        background = self.detail.palette().alternateBase().color().name()
        self.detail.setHtml(finding_html(f, self.state.t, background))

    def copy_fix(self) -> None:
        chosen = self.selected()
        if not chosen or chosen[0].remediation is None:
            return
        rem = chosen[0].remediation
        text = "\n".join(rem.steps.get(self.state.t.lang))
        snippets = list(rem.snippets.values())
        if snippets:
            text += "\n\n" + snippets[0].code
        QGuiApplication.clipboard().setText(text)

    def suppress_selected(self) -> None:
        t = self.state.t
        chosen = self.selected()
        if not chosen:
            return
        reason, ok = QInputDialog.getText(
            self, t("ui.results.suppress"), t("ui.results.suppress.reason")
        )
        if not ok or not reason.strip():
            return
        for f in chosen:
            self.state.suppress(reason, finding_id=f.id)
        QMessageBox.information(
            self, t("ui.results.suppress"), t("ui.results.suppress.done", count=len(chosen))
        )

    def copy_for_ai(self) -> None:
        t = self.state.t
        if self.report is None:
            return
        text = render_ai_prompt(self.report, lang=t.lang)
        QGuiApplication.clipboard().setText(text)
        QMessageBox.information(self, t("ui.results.copy_ai"), t("ui.results.copy_ai.done"))

    def _html_path(self) -> Path:
        assert self.report is not None
        assert self.scan_id is not None
        out = self.state.settings.data_dir / "scans" / self.scan_id
        return write_outputs(self.report, out, ["html"], lang=self.state.t.lang)["html"]

    def open_report(self) -> None:
        if self.report is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._html_path())))

    def export(self) -> None:
        t = self.state.t
        if self.report is None:
            return
        folder = QFileDialog.getExistingDirectory(self, t("ui.results.export"))
        if not folder:
            return
        try:
            written = write_outputs(
                self.report, Path(folder), ["html", "json", "sarif", "csv"], lang=t.lang
            )
        except ReportFormatError as exc:
            QMessageBox.warning(self, t("ui.results.export"), str(exc))
            return
        QMessageBox.information(
            self, t("ui.results.export"), "\n".join(str(p) for p in written.values())
        )
