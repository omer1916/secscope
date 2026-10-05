"""Shared UI state: settings, the scan database and stored reports."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal

from secscope.core.config import Settings
from secscope.core.session import database_path, tool_manager
from secscope.core.toolmgr import ToolManager
from secscope.reporting.json_export import REPORT_FILE, load_report
from secscope.storage import db
from secscope.storage.repo import ScanRepository
from secscope.ui.i18n import Translator


@dataclass(frozen=True, slots=True)
class ScanRow:
    scan_id: str
    created_at: str
    target: str
    status: str
    overall: float | None
    grade: str | None


class AppState(QObject):
    """Owns settings and gives pages read access to scans; emits when things change."""

    scans_changed = Signal()
    scan_opened = Signal(str)  # scan id to show on the results page

    def __init__(self, settings: Settings | None = None, *, config_dir: Path | None = None) -> None:
        super().__init__()
        self.settings = settings or Settings.load(config_dir)
        self.config_dir = config_dir
        self.t = Translator(self.settings.language)
        self._tools: ToolManager | None = None

    # ----------------------------------------------------------------- settings

    def save_settings(self, settings: Settings) -> None:
        self.settings = settings
        settings.save(self.config_dir)
        self._tools = None

    @property
    def tools(self) -> ToolManager:
        if self._tools is None:
            self._tools = tool_manager(self.settings)
        return self._tools

    # -------------------------------------------------------------------- scans

    def db_connection(self) -> sqlite3.Connection:
        return db.connect(database_path(self.settings))

    def scans(self) -> list[ScanRow]:
        import json  # noqa: PLC0415

        conn = self.db_connection()
        try:
            rows = conn.execute(
                "SELECT id, created_at, target, status, scores_json FROM scans ORDER BY created_at DESC"
            ).fetchall()
        finally:
            conn.close()
        out: list[ScanRow] = []
        for r in rows:
            scores: dict[str, Any] = json.loads(r["scores_json"]) if r["scores_json"] else {}
            out.append(
                ScanRow(
                    r["id"],
                    r["created_at"],
                    r["target"],
                    r["status"],
                    scores.get("overall"),
                    scores.get("grade"),
                )
            )
        return out

    def report_path(self, scan_id: str) -> Path:
        return self.settings.data_dir / "scans" / scan_id / REPORT_FILE

    def report(self, scan_id: str) -> dict[str, Any] | None:
        path = self.report_path(scan_id)
        if not path.is_file():
            return None
        try:
            return load_report(path)
        except ValueError:
            return None

    def suppress(
        self, reason: str, *, finding_id: str | None = None, rule_id: str | None = None
    ) -> None:
        conn = self.db_connection()
        try:
            ScanRepository(conn).add_suppression(reason, finding_id=finding_id, rule_id=rule_id)
        finally:
            conn.close()

    def suppressions(self) -> list[sqlite3.Row]:
        conn = self.db_connection()
        try:
            return ScanRepository(conn).suppressions()
        finally:
            conn.close()

    def remove_suppression(self, suppression_id: int) -> None:
        conn = self.db_connection()
        try:
            ScanRepository(conn).remove_suppression(suppression_id)
        finally:
            conn.close()

    def delete_all_scans(self) -> int:
        """Delete every stored scan (database rows and work folders)."""
        from secscope.core.intake import remove_tree  # noqa: PLC0415

        conn = self.db_connection()
        try:
            ids = [r[0] for r in conn.execute("SELECT id FROM scans")]
            repo = ScanRepository(conn)
            for scan_id in ids:
                repo.delete_scan(scan_id)
        finally:
            conn.close()
        remove_tree(self.settings.data_dir / "scans")
        self.scans_changed.emit()
        return len(ids)
