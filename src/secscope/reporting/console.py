"""Human-readable progress lines for the headless CLI."""

from __future__ import annotations

from typing import TextIO

from secscope.core.events import (
    ErrorEvent,
    Event,
    FindingEvent,
    ModuleFinished,
    ModuleSkipped,
    ModuleStarted,
    ScanFinished,
    ScanStarted,
    ScopeViolationEvent,
)
from secscope.core.models import Language


class ConsoleReporter:
    def __init__(self, stream: TextIO, lang: Language = "tr") -> None:
        self._out = stream
        self._lang: Language = lang

    def _write(self, line: str) -> None:
        try:
            self._out.write(line + "\n")
            self._out.flush()
        except UnicodeEncodeError:  # legacy console code page
            self._out.write(line.encode("ascii", "replace").decode("ascii") + "\n")

    def __call__(self, event: Event) -> None:
        match event:
            case ScanStarted():
                self._write(f"[scan] {event.scan_id}: {', '.join(event.modules) or '-'}")
            case ModuleStarted():
                self._write(f"[{event.module}] started")
            case ModuleSkipped():
                hint = f" ({event.install_hint.get(self._lang)})" if event.install_hint else ""
                self._write(f"[{event.module}] SKIPPED: {event.reason.get(self._lang)}{hint}")
            case FindingEvent():
                f = event.finding
                self._write(
                    f"  {f.severity.upper():<8} {f.rule_id:<16} {f.title.get(self._lang)}"
                    f" @ {f.location.display()}"
                )
            case ModuleFinished():
                self._write(
                    f"[{event.module}] {event.status} in {event.duration_s:.1f}s,"
                    f" {event.finding_count} finding(s)"
                )
            case ErrorEvent():
                self._write(f"[error] {event.message}")
            case ScopeViolationEvent():
                self._write(f"[scope] blocked {event.url} ({event.reason})")
            case ScanFinished():
                self._write(f"[scan] {event.status} in {event.duration_s:.1f}s")
            case _:
                pass
