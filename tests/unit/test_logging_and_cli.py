from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from secscope.__about__ import __version__
from secscope.cli import SCHEMA_KINDS, main
from secscope.core.logging import LOG_FILE, setup_logging


def test_log_file_masks_secrets(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs dir"
    setup_logging(log_dir, "DEBUG")
    try:
        log = logging.getLogger("secscope.test")
        log.info("connecting with password=%s", "hunter2hunter2")
        try:
            raise ValueError("token=abcdef0123456789abcdef")
        except ValueError:
            log.exception("failed")
        text = (log_dir / LOG_FILE).read_text(encoding="utf-8")
    finally:
        setup_logging(None)  # closes the file handler (Windows keeps files locked)
    assert "connecting with" in text
    assert "hunter2hunter2" not in text
    assert "abcdef0123456789abcdef" not in text


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("kind", SCHEMA_KINDS)
def test_cli_schema(kind: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", kind]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), dict)


def test_python_dash_m_entry_point() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "secscope", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == f"SecScope {__version__}"
