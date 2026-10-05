"""CLI end to end: scan → report.json → suppress → rescan → diff → re-render (SPEC M8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscope.cli import main
from secscope.storage import db
from secscope.storage.repo import ScanRepository
from tests.detection import FIXTURES


def scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    code = main(
        ["scan", "--path", str(FIXTURES / "static-seo-bad"), "--modules", "seo", "--accept-scope-statement",
         "--format", "html,json,sarif,csv", "--out", str(tmp_path / "out"), "--data-dir", str(tmp_path / "data")]
    )  # fmt: skip
    assert code == 0
    printed = [Path(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    return next(p for p in printed if p.suffix == ".json")


def test_full_report_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first = scan(tmp_path, capsys)
    data = json.loads(first.read_text(encoding="utf-8"))
    assert data["seo"]["score"]["capped_by_index_blocker"] is True
    assert any(f["rule_id"] == "SEO-OG-001" for f in data["findings"])
    stored = tmp_path / "data" / "scans" / data["scan_id"] / "report.json"
    assert stored.is_file()

    conn = db.connect(tmp_path / "data" / "secscope.db")
    ScanRepository(conn).add_suppression("social previews are not needed", rule_id="SEO-OG-001")
    conn.close()

    second = scan(tmp_path, capsys)
    data2 = json.loads(second.read_text(encoding="utf-8"))
    assert data2["suppressed"] > 0
    assert not any(f["rule_id"] == "SEO-OG-001" for f in data2["findings"])

    assert main(["diff", str(first), str(second), "--json"]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["fixed"] == data2["suppressed"]
    assert diff["new"] == 0

    assert (
        main(
            [
                "report",
                str(stored),
                "--format",
                "html",
                "--out",
                str(tmp_path / "again"),
                "--lang",
                "en",
            ]
        )
        == 0
    )
    html_path = next(p for p in capsys.readouterr().out.split() if p.endswith(".html"))
    html = Path(html_path).read_text(encoding="utf-8")
    assert "Visibility in Google" in html


def test_report_unknown_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", str(tmp_path / "nope.json")]) == 2
