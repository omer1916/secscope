"""Assemble everything a scan needs: directories, database, tools, guard, context."""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from secscope.core.config import ScanConfig, Settings, TargetKind
from secscope.core.scope_guard import ScopeGuard, ScopePolicy
from secscope.core.toolmgr import Manifest, ToolManager
from secscope.modules.base import ScanContext
from secscope.storage import db
from secscope.storage.repo import ScanRepository


def new_scan_id() -> str:
    """Sortable and unique: 20261005-142233-3f9a1c."""
    return f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


class InvalidTargetError(ValueError):
    pass


@dataclass
class ScanSession:
    ctx: ScanContext
    conn: sqlite3.Connection
    repo: ScanRepository

    def close(self) -> None:
        self.conn.close()


def database_path(settings: Settings) -> Path:
    return settings.data_dir / "secscope.db"


def tool_manager(settings: Settings, manifest: Manifest | None = None) -> ToolManager:
    return ToolManager(manifest or Manifest.load(), settings.data_dir / "tools")


def open_session(
    config: ScanConfig,
    settings: Settings,
    *,
    scan_id: str | None = None,
    tools: ToolManager | None = None,
) -> ScanSession:
    scan_id = scan_id or new_scan_id()
    work_dir = settings.data_dir / "scans" / scan_id
    work_dir.mkdir(parents=True, exist_ok=False)
    guard = ScopeGuard(policy=ScopePolicy.from_strings(settings.allowed_lan_networks))

    source_dir: Path | None = None
    target_url: str | None = None
    match config.target.kind:
        case TargetKind.URL:
            decision = guard.check(config.target.value)
            if not decision.allowed:
                raise InvalidTargetError(
                    f"target {config.target.value!r} is outside the allowed scope "
                    f"({decision.reason}); only localhost/127.0.0.1/::1 are allowed"
                )
            target_url = config.target.value
        case TargetKind.FOLDER:
            source_dir = Path(config.target.value)
            if not source_dir.is_dir():
                raise InvalidTargetError(f"not a directory: {source_dir}")
        case TargetKind.ARCHIVE:
            # Extracted by the intake step (M2); until then the archive is not readable.
            pass

    conn = db.connect(database_path(settings))
    repo = ScanRepository(conn)
    repo.create_scan(scan_id, config)
    ctx = ScanContext(
        scan_id=scan_id,
        config=config,
        settings=settings,
        work_dir=work_dir,
        guard=guard,
        tools=tools or tool_manager(settings),
        source_dir=source_dir,
        target_url=target_url,
    )
    return ScanSession(ctx=ctx, conn=conn, repo=repo)
