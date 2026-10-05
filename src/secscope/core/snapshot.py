"""SQLite snapshots of the running copy (SPEC §6.1 "veri güvenliği").

The target always runs in a copy of the project, so the user's own database is
never touched. Snapshots additionally let us put the copy's databases back to
their pre-scan state (e.g. after active scanning, before a load test).
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from secscope.core.fingerprint import DEPENDENCY_DIRS

SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3", ".db3"})


def find_sqlite_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if any(part in DEPENDENCY_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.suffix.lower() in SQLITE_SUFFIXES and path.is_file():
            try:
                with path.open("rb") as fh:
                    if fh.read(16) == SQLITE_MAGIC:
                        found.append(path)
            except OSError:
                continue
    return sorted(found)


@dataclass
class Snapshot:
    root: Path
    store: Path
    files: list[Path]

    @classmethod
    def take(cls, root: Path, store: Path) -> Snapshot:
        store.mkdir(parents=True, exist_ok=True)
        files = find_sqlite_files(root)
        for db_path in files:
            dest = store / db_path.relative_to(root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            # The backup API gives a consistent copy even if the app has it open.
            src = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
            try:
                dst = sqlite3.connect(dest)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
        return cls(root=root, store=store, files=files)

    def restore(self) -> list[Path]:
        """Put every snapshotted database back. Call only while the target is stopped."""
        restored: list[Path] = []
        for db_path in self.files:
            saved = self.store / db_path.relative_to(self.root)
            for suffix in ("-wal", "-shm", "-journal"):
                db_path.with_name(db_path.name + suffix).unlink(missing_ok=True)
            shutil.copy2(saved, db_path)
            restored.append(db_path)
        return restored
