from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from secscope.core.config import ScanConfig, Target, TargetKind
from secscope.storage import db
from secscope.storage.repo import ScanRepository
from tests.unit.test_models import make_finding


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = db.connect(tmp_path / "data dir" / "secscope.db")
    yield connection
    connection.close()


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {r[0] for r in rows if not r[0].startswith("sqlite_")}


def test_fresh_database_is_migrated(conn: sqlite3.Connection) -> None:
    assert db.schema_version(conn) == db.load_migrations()[-1].version
    assert {"scans", "findings", "module_runs", "suppressions"} <= _tables(conn)


def test_migrate_is_idempotent(conn: sqlite3.Connection) -> None:
    version = db.schema_version(conn)
    assert db.migrate(conn) == version


def test_newer_schema_refused(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA user_version = 999")
    with pytest.raises(RuntimeError, match="newer"):
        db.migrate(conn)


def test_failed_migration_rolls_back() -> None:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    broken = [
        db.Migration(1, "0001_ok.sql", "CREATE TABLE a (x INTEGER);"),
        db.Migration(
            2, "0002_bad.sql", "CREATE TABLE b (y INTEGER);\nINSERT INTO nope VALUES (1);"
        ),
    ]
    with pytest.raises(sqlite3.OperationalError):
        db.migrate(conn, broken)
    assert db.schema_version(conn) == 1
    assert _tables(conn) == {"a"}
    conn.close()


def test_split_sql_handles_semicolons_in_strings() -> None:
    script = "-- c\nCREATE TABLE t (x TEXT DEFAULT ';');\nINSERT INTO t VALUES ('a;b');\n"
    assert len(db._split_sql(script)) == 2  # pyright: ignore[reportPrivateUsage]


def test_repository_roundtrip(conn: sqlite3.Connection) -> None:
    repo = ScanRepository(conn)
    cfg = ScanConfig(
        target=Target(kind=TargetKind.URL, value="http://localhost:3000"),
        scope_statement_accepted=True,
    )
    repo.create_scan("scan-1", cfg)
    findings = [make_finding(), make_finding(rule_id="SEC-HDR-002")]
    assert repo.add_findings("scan-1", findings) == 2
    repo.add_findings("scan-1", findings[:1])  # same fingerprint: replaced, not doubled
    assert sorted(f.id for f in repo.list_findings("scan-1")) == sorted(f.id for f in findings)
    row = repo.get_scan("scan-1")
    assert row is not None
    assert row["scope_accepted_at"] is not None
    repo.finish_scan("scan-1", "completed")
    repo.delete_scan("scan-1")
    assert repo.list_findings("scan-1") == []  # cascade


def test_suppression_requires_reason(conn: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO suppressions (rule_id, reason, created_at) VALUES ('X-1', '  ', 'now')"
        )
