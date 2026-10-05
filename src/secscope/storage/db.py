"""SQLite connection handling and schema migrations."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str


def load_migrations() -> list[Migration]:
    """Bundled migrations, sorted by version. Versions must be contiguous from 1."""
    found: list[Migration] = []
    for entry in resources.files("secscope.storage.migrations").iterdir():
        match = _MIGRATION_NAME.match(entry.name)
        if match:
            found.append(Migration(int(match.group(1)), entry.name, entry.read_text("utf-8")))
    found.sort(key=lambda m: m.version)
    for expected, migration in enumerate(found, start=1):
        if migration.version != expected:
            raise RuntimeError(f"migration versions must be contiguous: {migration.name}")
    return found


def connect(path: Path | str) -> sqlite3.Connection:
    """Open the database and bring the schema up to date."""
    if isinstance(path, Path):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None)  # explicit transactions only
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return conn


def schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection, migrations: list[Migration] | None = None) -> int:
    """Apply pending migrations, each atomically. Returns the resulting version."""
    pending = migrations if migrations is not None else load_migrations()
    current = schema_version(conn)
    latest = pending[-1].version if pending else 0
    if current > latest:
        raise RuntimeError(
            f"database schema v{current} is newer than this build supports (v{latest})"
        )
    for migration in pending:
        if migration.version <= current:
            continue
        try:
            conn.execute("BEGIN IMMEDIATE")
            # executescript would COMMIT first; run statements one by one instead.
            for statement in _split_sql(migration.sql):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {migration.version:d}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        current = migration.version
    return current


def _split_sql(script: str) -> list[str]:
    """Split a migration into statements using sqlite's own completeness check."""
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement and statement != ";":
                statements.append(statement)
            buffer = ""
    if buffer.strip() and not all(
        ln.strip().startswith("--") or not ln.strip() for ln in buffer.splitlines()
    ):
        raise ValueError("incomplete SQL statement at end of migration")
    return statements
