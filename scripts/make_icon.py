"""Draw the SecScope app icon (shield + magnifier) and write it as PNG and multi-size ICO.

    uv run python scripts/make_icon.py

Output: src/secscope/ui/assets/secscope.png (256 px, window icon) and secscope.ico
(16-256 px, executable icon). Drawn with Qt so no image editor or extra package is needed.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QGuiApplication,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)

OUT = Path(__file__).resolve().parents[1] / "src" / "secscope" / "ui" / "assets"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 256.0

    # Shield
    shield = QPainterPath()
    shield.moveTo(128 * s, 14 * s)
    shield.cubicTo(170 * s, 38 * s, 204 * s, 44 * s, 226 * s, 44 * s)
    shield.cubicTo(228 * s, 140 * s, 196 * s, 206 * s, 128 * s, 244 * s)
    shield.cubicTo(60 * s, 206 * s, 28 * s, 140 * s, 30 * s, 44 * s)
    shield.cubicTo(52 * s, 44 * s, 86 * s, 38 * s, 128 * s, 14 * s)
    shield.closeSubpath()
    grad = QLinearGradient(QPointF(0, 0), QPointF(0, size))
    grad.setColorAt(0.0, QColor("#3d6ff0"))
    grad.setColorAt(1.0, QColor("#1b3fa8"))
    p.setPen(QPen(QColor("#12307f"), max(1.0, 6 * s)))
    p.setBrush(QBrush(grad))
    p.drawPath(shield)

    # Magnifier: lens ring + handle
    ring = QPen(QColor("#ffffff"), max(1.5, 20 * s))
    ring.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(ring)
    p.setBrush(QColor(255, 255, 255, 40))
    lens = QRectF(70 * s, 70 * s, 92 * s, 92 * s)
    p.drawEllipse(lens)
    handle = QPen(QColor("#ffffff"), max(2.0, 26 * s))
    handle.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(handle)
    p.drawLine(QPointF(150 * s, 150 * s), QPointF(186 * s, 186 * s))

    # Check mark inside the lens (only where it stays readable)
    if size >= 32:
        tick = QPen(QColor("#7ee08a"), max(1.5, 14 * s))
        tick.setCapStyle(Qt.PenCapStyle.RoundCap)
        tick.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(tick)
        p.setBrush(Qt.BrushStyle.NoBrush)
        path = QPainterPath()
        path.moveTo(94 * s, 118 * s)
        path.lineTo(111 * s, 135 * s)
        path.lineTo(140 * s, 100 * s)
        p.drawPath(path)
    p.end()
    return img


def png_bytes(img: QImage) -> bytes:
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, b"PNG")
    return bytes(data.data())


def write_ico(path: Path, images: list[tuple[int, bytes]]) -> None:
    """ICO with PNG-compressed entries (supported since Windows Vista)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    blobs = b""
    for size, blob in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        blobs += blob
    path.write_bytes(header + entries + blobs)


def main() -> int:
    _app = QGuiApplication(sys.argv)
    OUT.mkdir(parents=True, exist_ok=True)
    images = [(size, png_bytes(draw(size))) for size in SIZES]
    write_ico(OUT / "secscope.ico", images)
    (OUT / "secscope.png").write_bytes(images[-1][1])
    print(f"wrote {OUT / 'secscope.ico'} and secscope.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
