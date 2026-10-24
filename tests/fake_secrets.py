"""Fake, realistically shaped secrets for the detector tests — kept out of the repository text.

GitHub's secret scanning (rightly) blocks pushes that contain strings shaped like live AWS or
Stripe keys, even fake ones. So the fixtures hold placeholders, and the values below are written
with escapes so the source never contains them literally. :func:`materialize` copies a fixture
and fills the placeholders in; that copy is what the detection tests scan.

None of these values is a real credential.

    uv run python -m tests.fake_secrets vuln-flask <out-dir>   # a scannable copy of a fixture
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# "\x5a" is "Z", "\x71" is "q", "\x6c" is "l": the runtime values are the plain strings.
AWS_KEY_ID = "AKIA\x5a5YQ7Q3XJ2KQ7W4P"
AWS_SECRET = "\x718Vb3kT9yLm2Nx7Rp4Wz6Hs1Jd5Fg0Ac2Ue8Io3K"
STRIPE_KEY = "sk_\x6cive_51HfakeFAKEfake0123456789abcdEFGH"
STRIPE_KEY_SHORT = "sk_\x6cive_51HfakeFAKEfake0123456789"
STRIPE_KEY_DOCS = "sk_\x6cive_4eC39HqLyjWDarjtT1zdp7dc"
ALL = (AWS_KEY_ID, AWS_SECRET, STRIPE_KEY, STRIPE_KEY_SHORT, STRIPE_KEY_DOCS)

PLACEHOLDERS = {
    "__SECSCOPE_FAKE_AWS_KEY_ID__": AWS_KEY_ID,
    "__SECSCOPE_FAKE_AWS_SECRET__": AWS_SECRET,
    "__SECSCOPE_FAKE_STRIPE_KEY__": STRIPE_KEY,
}


def fill(text: str) -> str:
    for placeholder, value in PLACEHOLDERS.items():
        text = text.replace(placeholder, value)
    return text


def materialize(fixture: str, dest: Path) -> Path:
    """Copy ``fixtures/<fixture>`` to ``dest`` with every placeholder replaced by its fake value."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(FIXTURES / fixture, dest)
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if (filled := fill(text)) != text:
            path.write_text(filled, encoding="utf-8", newline="")
    return dest


def escape_for_json(text: str) -> str:
    """JSON text with each fake value's fifth character \\u-escaped, so a recorded golden file
    never contains the value literally while ``json.loads`` still returns the same strings."""
    for value in sorted(ALL, key=len, reverse=True):
        text = text.replace(value, f"{value[:4]}\\u{ord(value[4]):04x}{value[5:]}")
    return text


if __name__ == "__main__":
    print(materialize(sys.argv[1], Path(sys.argv[2])))
