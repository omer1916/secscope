"""Locate bundled data directories (rules/, remediation/, tools/).

In a source checkout they live at the repository root; frozen builds ship them
under ``secscope/_data/`` (see packaging/).
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _PACKAGE_DIR.parents[1]


def data_path(name: str) -> Path:
    for candidate in (_REPO_ROOT / name, _PACKAGE_DIR / "_data" / name):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"bundled data {name!r} not found")
