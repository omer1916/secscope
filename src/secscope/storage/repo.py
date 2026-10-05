"""Persistence of scans and findings (thin layer over SQLite)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime

from secscope.__about__ import __version__
from secscope.core.config import ScanConfig
from secscope.core.models import Finding


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ScanRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create_scan(self, scan_id: str, config: ScanConfig) -> None:
        accepted_at = _now() if config.scope_statement_accepted else None
        self._conn.execute(
            "INSERT INTO scans (id, created_at, target_kind, target, profile,"
            " scope_accepted_at, config_json, app_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                _now(),
                config.target.kind.value,
                config.target.value,
                config.profile.value,
                accepted_at,
                config.model_dump_json(),
                __version__,
            ),
        )

    def finish_scan(self, scan_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?", (status, _now(), scan_id)
        )

    def get_scan(self, scan_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return row

    def add_findings(self, scan_id: str, findings: Iterable[Finding]) -> int:
        rows = [
            (
                scan_id,
                f.id,
                f.rule_id,
                f.module,
                f.category.value,
                f.severity,
                f.confidence,
                f.model_dump_json(),
            )
            for f in findings
        ]
        self._conn.execute("BEGIN")
        try:
            # Same fingerprint within a scan = same finding; keep the latest data.
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings (scan_id, finding_id, rule_id, module, category,"
                " severity, confidence, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return len(rows)

    def list_findings(self, scan_id: str) -> list[Finding]:
        cur = self._conn.execute(
            "SELECT data_json FROM findings WHERE scan_id = ? ORDER BY rule_id, finding_id",
            (scan_id,),
        )
        return [Finding.model_validate_json(row[0]) for row in cur]

    def delete_scan(self, scan_id: str) -> None:
        self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
