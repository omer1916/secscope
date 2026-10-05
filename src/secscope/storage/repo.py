"""Persistence of scans and findings (thin layer over SQLite)."""

from __future__ import annotations

import json
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

    def finish_scan(
        self, scan_id: str, status: str, scores: dict[str, object] | None = None
    ) -> None:
        self._conn.execute(
            "UPDATE scans SET status = ?, finished_at = ?, scores_json = ? WHERE id = ?",
            (status, _now(), json.dumps(scores) if scores is not None else None, scan_id),
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

    def replace_findings(self, scan_id: str, findings: Iterable[Finding]) -> int:
        """Swap the per-module raw findings for the final, de-duplicated list."""
        self._conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        return self.add_findings(scan_id, findings)

    def add_suppression(
        self, reason: str, *, finding_id: str | None = None, rule_id: str | None = None
    ) -> None:
        self._conn.execute(
            "INSERT INTO suppressions (finding_id, rule_id, reason, created_at) VALUES (?, ?, ?, ?)",
            (finding_id, rule_id, reason.strip(), _now()),
        )

    def suppressions(self) -> list[sqlite3.Row]:
        return list(self._conn.execute("SELECT * FROM suppressions ORDER BY id"))

    def remove_suppression(self, suppression_id: int) -> None:
        self._conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))

    def record_module_run(
        self, scan_id: str, module: str, status: str, reason: str | None, duration_s: float
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO module_runs (scan_id, module, status, reason, duration_s)"
            " VALUES (?, ?, ?, ?, ?)",
            (scan_id, module, status, reason, duration_s),
        )

    def module_runs(self, scan_id: str) -> dict[str, str]:
        cur = self._conn.execute(
            "SELECT module, status FROM module_runs WHERE scan_id = ?", (scan_id,)
        )
        return {row[0]: row[1] for row in cur}

    def list_findings(self, scan_id: str) -> list[Finding]:
        cur = self._conn.execute(
            "SELECT data_json FROM findings WHERE scan_id = ? ORDER BY rule_id, finding_id",
            (scan_id,),
        )
        return [Finding.model_validate_json(row[0]) for row in cur]

    def delete_scan(self, scan_id: str) -> None:
        self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
