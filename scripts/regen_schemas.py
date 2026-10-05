"""Regenerate docs/schemas/*.schema.json after an intentional model change."""

import json
from pathlib import Path

from secscope.cli import SCHEMA_KINDS, _schema  # pyright: ignore[reportPrivateUsage]

OUT = Path(__file__).resolve().parents[1] / "docs" / "schemas"

for kind in SCHEMA_KINDS:
    path = OUT / f"{kind}.schema.json"
    text = json.dumps(_schema(kind), indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {path.relative_to(OUT.parents[1])}")
