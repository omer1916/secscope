"""Logging setup: rotating file log with secrets masked in every record (SPEC §13)."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from secscope.core.redact import redact

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
LOG_FILE = "secscope.log"


class RedactingFormatter(logging.Formatter):
    """Masks secrets in the fully formatted record, including tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_logging(
    log_dir: Path | None,
    level: str = "INFO",
    *,
    max_bytes: int = 5 * 1024 * 1024,
    backups: int = 5,
    console: bool = False,
) -> logging.Logger:
    """Configure the ``secscope`` logger hierarchy. Safe to call more than once."""
    root = logging.getLogger("secscope")
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    formatter = RedactingFormatter(LOG_FORMAT)
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / LOG_FILE, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)
    root.propagate = False
    return root
