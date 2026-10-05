"""Reusable widgets: score ring, cards, the virtualised findings table, a background task runner."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QRectF,
    QRunnable,
    QSortFilterProxyModel,
    Qt,
    QThreadPool,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QFrame, QLabel, QSizePolicy, QVBoxLayout, QWidget

from secscope.core.models import SEVERITY_ORDER, Finding
from secscope.ui.i18n import Translator
from secscope.ui.theme import SEVERITY_COLORS

GRADE_COLORS = {"A": "#2e7d32", "B": "#558b2f", "C": "#b7791f", "D": "#d1501f", "F": "#b3261e"}

Index = QModelIndex | QPersistentModelIndex


def label(text: str, role: str | None = None) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    if role:
        lbl.setProperty("role", role)
    return lbl


def card(*widgets: QWidget) -> QFrame:
    frame = QFrame()
    frame.setProperty("role", "card")
    layout = QVBoxLayout(frame)
    for w in widgets:
        layout.addWidget(w)
    return frame


class ScoreRing(QWidget):
    """A circular gauge showing a 0–100 score and a caption (grade or label)."""

    def __init__(self, caption: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: float | None = None
        self._caption = caption
        self._center = "–"
        self.setMinimumSize(110, 110)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def set_score(self, score: float | None, center: str | None = None) -> None:
        self._score = score
        self._center = center if center is not None else ("–" if score is None else f"{score:.0f}")
        self.setAccessibleName(f"{self._caption} {self._center}")
        self.update()

    def paintEvent(self, _event: object) -> None:  # noqa: N802 - Qt override
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 16
        rect = QRectF((self.width() - side) / 2, 6, side, side)
        track = QPen(self.palette().mid().color(), 10)
        p.setPen(track)
        p.drawArc(rect, 0, 360 * 16)
        if self._score is not None:
            color = GRADE_COLORS.get(self._center) or (
                "#2e7d32" if self._score >= 90 else "#b7791f" if self._score >= 70 else "#b3261e"
            )
            pen = QPen(QColor(color), 10)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(pen)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * self._score / 100))
        p.setPen(self.palette().text().color())
        font = QFont(self.font())
        font.setPointSize(16)
        font.setBold(True)
        p.setFont(font)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self._center)
        p.end()


class FindingsModel(QAbstractTableModel):
    """Virtualised table of findings: Qt only asks for visible rows (10k+ findings stay smooth)."""

    COLUMNS = ("severity", "rule", "title", "location", "confidence", "tools")

    def __init__(self, t: Translator, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._t = t
        self._rows: list[Finding] = []

    def set_findings(self, findings: list[Finding]) -> None:
        self.beginResetModel()
        self._rows = list(findings)
        self.endResetModel()

    def append(self, finding: Finding) -> None:
        n = len(self._rows)
        self.beginInsertRows(QModelIndex(), n, n)
        self._rows.append(finding)
        self.endInsertRows()

    def finding(self, row: int) -> Finding:
        return self._rows[row]

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: N802, B008
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: N802, B008
        return len(self.COLUMNS)

    # Qt API name.
    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._t(f"report.col.{self.COLUMNS[section]}")
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        f = self._rows[index.row()]
        col = self.COLUMNS[index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            match col:
                case "severity":
                    return self._t(f"report.sev.{f.severity}")
                case "rule":
                    return f.rule_id
                case "title":
                    return f.title.get(self._t.lang)
                case "location":
                    return f.location.display()
                case "confidence":
                    return f.confidence
                case _:
                    return ", ".join(f.source_tools)
        if role == Qt.ItemDataRole.ForegroundRole and col == "severity":
            return QColor(SEVERITY_COLORS[f.severity])
        if role == Qt.ItemDataRole.UserRole:  # sort key
            return -SEVERITY_ORDER[f.severity] if col == "severity" else str(self.data(index))
        return None


class FindingsFilter(QSortFilterProxyModel):
    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self._text = ""
        self._severities: set[str] = set(SEVERITY_ORDER)
        self._category: str | None = None

    def _refilter(self, apply: Callable[[], None]) -> None:
        # Qt 6.9+ API (invalidateFilter is deprecated): announce, change, then re-filter rows.
        self.beginFilterChange()
        apply()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_text(self, text: str) -> None:
        self._refilter(lambda: setattr(self, "_text", text.strip().lower()))

    def set_severities(self, severities: set[str]) -> None:
        self._refilter(lambda: setattr(self, "_severities", set(severities)))

    def set_category(self, category: str | None) -> None:
        self._refilter(lambda: setattr(self, "_category", category))

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:  # noqa: N802
        model = self.sourceModel()
        assert isinstance(model, FindingsModel)
        f = model.finding(source_row)
        if f.severity not in self._severities:
            return False
        if self._category and self._category not in (f.category.value, f.module):
            return False
        if self._text:
            haystack = (
                f"{f.rule_id} {f.title.tr} {f.title.en} {f.location.display()} {f.module}".lower()
            )
            return self._text in haystack
        return True


class _TaskSignals(QObject):
    done = Signal(object)
    failed = Signal(str)


class BackgroundTask(QRunnable):
    """Run a blocking callable on the thread pool; results come back as Qt signals."""

    def __init__(self, fn: Callable[[], object]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = _TaskSignals()

    def run(self) -> None:
        try:
            result = self.fn()
        except Exception as exc:  # reported to the UI, never crashes it
            self.signals.failed.emit(str(exc))
            return
        self.signals.done.emit(result)


def run_in_background(
    fn: Callable[[], object], on_done: Callable[[object], None], on_failed: Callable[[str], None]
) -> BackgroundTask:
    task = BackgroundTask(fn)
    task.signals.done.connect(on_done)
    task.signals.failed.connect(on_failed)
    QThreadPool.globalInstance().start(task)
    return task
