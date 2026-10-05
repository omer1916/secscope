"""Offline vulnerability databases for Trivy and osv-scanner (SPEC §6.2 SCA, ADR-006).

Databases are downloaded only by an explicit user action (``secscope tools update-db`` /
the UI's "update" button). Scans run fully offline and report the data date.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from secscope.core.process import run_capture
from secscope.core.toolmgr import ToolManager

TRIVY_PRIVACY_FLAGS = ("--disable-telemetry", "--skip-version-check")

# Minimal lockfiles so osv-scanner downloads the databases of every ecosystem we support.
_TEMPLATE_FILES = {
    "requirements.txt": "requests==2.31.0\n",
    "package-lock.json": json.dumps(
        {
            "name": "t",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"ms": "2.1.3"}},
                "node_modules/ms": {"version": "2.1.3"},
            },
        }
    ),
    "composer.lock": json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}),
}


@dataclass(frozen=True, slots=True)
class DbStatus:
    tool: str
    present: bool
    updated_at: datetime | None


def trivy_cache(data_dir: Path) -> Path:
    return data_dir / "trivy-cache"


def osv_cache(data_dir: Path) -> Path:
    return data_dir / "osv-db"


def osv_env(data_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(osv_cache(data_dir))
    return env


def trivy_status(data_dir: Path) -> DbStatus:
    meta = trivy_cache(data_dir) / "db" / "metadata.json"
    if not meta.is_file():
        return DbStatus("trivy", False, None)
    try:
        raw = json.loads(meta.read_text(encoding="utf-8"))["UpdatedAt"]
        updated = datetime.fromisoformat(raw[:26].rstrip("Z") + "+00:00") if raw else None
    except (ValueError, KeyError):
        updated = None
    return DbStatus("trivy", True, updated)


def osv_status(data_dir: Path) -> DbStatus:
    zips = list(osv_cache(data_dir).rglob("all.zip"))
    if not zips:
        return DbStatus("osv-scanner", False, None)
    newest = max(z.stat().st_mtime for z in zips)
    return DbStatus("osv-scanner", True, datetime.fromtimestamp(newest, UTC))


async def update_databases(tools: ToolManager, data_dir: Path) -> list[str]:
    """Download/refresh offline databases; returns human-readable result lines."""
    lines: list[str] = []
    trivy = tools.status("trivy")
    if trivy.available and trivy.path is not None:
        run = await run_capture(
            [str(trivy.path), "fs", "--download-db-only", "--cache-dir", str(trivy_cache(data_dir)),
             *TRIVY_PRIVACY_FLAGS, "--no-progress", "-q"],
            timeout=1800,
        )  # fmt: skip
        lines.append(f"trivy: {'ok' if run.returncode == 0 else 'failed: ' + run.stderr[-300:]}")
    else:
        lines.append("trivy: not installed")
    osv = tools.status("osv-scanner")
    if osv.available and osv.path is not None:
        with tempfile.TemporaryDirectory(prefix="secscope-osv-") as tmp:
            for name, content in _TEMPLATE_FILES.items():
                (Path(tmp) / name).write_text(content, encoding="utf-8")
            run = await run_capture(
                [str(osv.path), "scan", "source", "--offline", "--offline-vulnerabilities",
                 "--download-offline-databases", "-r", tmp, "--format", "json", "--verbosity", "error"],
                env=osv_env(data_dir),
                timeout=1800,
            )  # fmt: skip
        lines.append(
            f"osv-scanner: {'ok' if run.returncode in (0, 1) else 'failed: ' + run.stderr[-300:]}"
        )
    else:
        lines.append("osv-scanner: not installed")
    return lines
