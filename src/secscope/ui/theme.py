"""Light / dark themes (Fusion style + palette + a small stylesheet)."""

from __future__ import annotations

import pyqtgraph as pg  # type: ignore[import-untyped]
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#d1501f",
    "medium": "#b7791f",
    "low": "#3c7a3c",
    "info": "#6b7280",
}

_LIGHT = {
    "window": "#f6f7f9",
    "base": "#ffffff",
    "text": "#1d2127",
    "alt": "#f0f2f5",
    "button": "#ffffff",
    "highlight": "#2457d6",
    "muted": "#5d6670",
    "line": "#dfe3e8",
}
_DARK = {
    "window": "#16191e",
    "base": "#1e2228",
    "text": "#e8eaed",
    "alt": "#23282f",
    "button": "#262b33",
    "highlight": "#5b8cff",
    "muted": "#a2aab3",
    "line": "#323840",
}


def system_prefers_dark() -> bool:
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is None:
        return False
    return str(scheme()).endswith("Dark")


def apply_theme(app: QApplication, theme: str) -> None:
    dark = theme == "dark" or (theme == "system" and system_prefers_dark())
    c = _DARK if dark else _LIGHT
    app.setStyle("Fusion")
    pg.setConfigOptions(background=c["base"], foreground=c["text"], antialias=True)  # pyright: ignore[reportUnknownMemberType]
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(c["window"]))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Base, QColor(c["base"]))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(c["alt"]))
    pal.setColor(QPalette.ColorRole.Text, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Button, QColor(c["button"]))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(c["highlight"]))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(c["base"]))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(c["text"]))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(c["muted"]))
    app.setPalette(pal)
    app.setStyleSheet(
        f"""
        QListWidget#nav {{ outline: 0; border: none; background: {c["alt"]}; font-size: 14px; }}
        QListWidget#nav::item {{ padding: 10px 14px; }}
        QListWidget#nav::item:selected {{ background: {c["highlight"]}; color: white; border-radius: 6px; }}
        QLabel[role="h1"] {{ font-size: 20px; font-weight: 600; }}
        QLabel[role="h2"] {{ font-size: 15px; font-weight: 600; }}
        QLabel[role="muted"] {{ color: {c["muted"]}; }}
        QFrame[role="card"] {{ background: {c["base"]}; border: 1px solid {c["line"]}; border-radius: 10px; }}
        QPushButton {{ padding: 6px 14px; }}
        QPushButton[role="primary"] {{ background: {c["highlight"]}; color: white; border-radius: 6px; font-weight: 600; }}
        QPushButton[role="primary"]:disabled {{ background: {c["line"]}; color: {c["muted"]}; }}
        """
    )
