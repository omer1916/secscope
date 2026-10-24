"""Dogfooding (SPEC §12 CI): SecScope's own source must pass its own static analysis."""

from __future__ import annotations

import shutil
from pathlib import Path

from secscope.core.models import SEVERITY_ORDER
from tests.detection import run_static

SRC = Path(__file__).resolve().parents[2] / "src"


def test_secscope_source_is_clean(tmp_path: Path) -> None:
    project = tmp_path / "secscope-src"
    shutil.copytree(SRC, project)
    # run_static scans fixtures by name; an absolute path points it at the copied source instead.
    run = run_static(str(project), tmp_path / "data")
    serious = [
        (f.rule_id, f.location.display(), f.evidence.snippet)
        for f in run.findings
        if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["medium"] and f.rule_id != "SCA-VULN-001"
    ]
    assert serious == []
