"""Desktop entry point: ``secscope-gui``."""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from secscope.__about__ import __app_id__, __app_name__, __version__
from secscope.ui.main_window import MainWindow
from secscope.ui.state import AppState
from secscope.ui.theme import apply_theme

ICON = Path(__file__).resolve().parent / "assets" / "secscope.png"


def _windows_taskbar_identity() -> None:
    """Own taskbar group and icon instead of the Python interpreter's."""
    if sys.platform == "win32":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{__app_id__}.desktop")


def main() -> int:
    _windows_taskbar_identity()
    app = QApplication.instance() or QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    if ICON.is_file():
        app.setWindowIcon(QIcon(str(ICON)))
    state = AppState()
    apply_theme(app, state.settings.theme)
    window = MainWindow(state)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
