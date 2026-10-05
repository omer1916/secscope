"""Generate the binary images used by the static SEO fixtures (no third-party deps).

Run once; outputs are committed. Deterministic (seeded) so re-running gives identical bytes.
"""

import base64
import random
import struct
import zlib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures"

# 1x1 lossless WebP.
TINY_WEBP = base64.b64decode("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")


def png(width: int, height: int, pixel: Callable[[int, int], bytes]) -> bytes:
    rows = bytearray()
    for y in range(height):
        rows.append(0)  # filter: none
        for x in range(width):
            rows.extend(pixel(x, y))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return (
            struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def main() -> None:
    rng = random.Random(7)  # noqa: S311 - deterministic test data, not crypto
    bad = ROOT / "static-seo-bad" / "images"
    bad.mkdir(parents=True, exist_ok=True)
    # Noise does not compress: ~500 KB "hero" image (oversized, no dimensions, lazy LCP).
    (bad / "hero.png").write_bytes(
        png(420, 400, lambda _x, _y: bytes(rng.randrange(256) for _ in range(3)))
    )
    (bad / "logo.png").write_bytes(png(32, 32, lambda _x, _y: b"\x20\x60\xc0"))

    good = ROOT / "static-seo-good" / "images"
    good.mkdir(parents=True, exist_ok=True)
    (good / "hero.webp").write_bytes(TINY_WEBP)
    (good / "logo.webp").write_bytes(TINY_WEBP)
    (good / "og-image.png").write_bytes(png(1200, 630, lambda _x, _y: b"\x10\x50\x90"))
    for p in sorted([*bad.iterdir(), *good.iterdir()]):
        print(f"{p.relative_to(ROOT)}: {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
