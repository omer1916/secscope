"""Published JSON schemas must match the models (regenerate with the command below)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscope.cli import SCHEMA_KINDS, _schema  # pyright: ignore[reportPrivateUsage]

SCHEMAS = Path(__file__).resolve().parents[2] / "docs" / "schemas"


@pytest.mark.parametrize("kind", SCHEMA_KINDS)
def test_schema_file_up_to_date(kind: str) -> None:
    path = SCHEMAS / f"{kind}.schema.json"
    assert path.exists(), f"missing {path.name}; run: uv run secscope schema {kind}"
    assert json.loads(path.read_text(encoding="utf-8")) == _schema(kind), (
        f"{path.name} is stale; regenerate with: uv run python scripts/regen_schemas.py"
    )
