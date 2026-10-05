"""Desktop entry point: ``secscope-gui``."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from secscope.__about__ import __app_name__
from secscope.ui.main_window import MainWindow


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setApplicationName(__app_name__)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
