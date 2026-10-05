"""Render the desktop UI offscreen after a real scan and save page screenshots to docs/screenshots/.

uv run python scripts/ui_screenshots.py [tr|en]
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if sys.platform == "win32":
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

from PySide6.QtWidgets import QApplication

from secscope.cli import main as cli_main
from secscope.core.config import Settings
from secscope.ui.main_window import MainWindow
from secscope.ui.state import AppState
from secscope.ui.theme import apply_theme

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "screenshots"


def main() -> int:
    lang = sys.argv[1] if len(sys.argv) > 1 else "tr"
    data = Path(tempfile.mkdtemp(prefix="secscope-shots-"))
    cli_main(["scan", "--path", str(REPO / "fixtures" / "static-seo-bad"), "--modules", "seo,sast,config_audit,secrets",
              "--accept-scope-statement", "--format", "json", "--out", str(data / "out"), "--data-dir", str(data)])  # fmt: skip
    app = QApplication.instance() or QApplication(sys.argv)
    assert isinstance(app, QApplication)
    apply_theme(app, "light")
    state = AppState(Settings(data_dir=data, language=lang), config_dir=data / "config")  # type: ignore[arg-type]
    window = MainWindow(state)
    window.resize(1400, 880)
    window.show()
    OUT.mkdir(parents=True, exist_ok=True)
    scans = state.scans()
    window.open_results(scans[0].scan_id)
    for page in ("dashboard", "wizard", "results", "history", "settings"):
        window.go(page)
        if page == "dashboard":
            window.dashboard.refresh()
        app.processEvents()
        window.grab().save(str(OUT / f"{page}-{lang}.png"))
        print(f"docs/screenshots/{page}-{lang}.png")
    window.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
