"""Turn protocol events into localized one-line descriptions."""

from __future__ import annotations

from secscope.core.events import (
    ErrorEvent,
    Event,
    FindingEvent,
    Metric,
    ModuleFinished,
    ModuleLog,
    ModuleProgress,
    ModuleSkipped,
    ModuleStarted,
    ScanFinished,
    ScanStarted,
    ScopeViolationEvent,
)
from secscope.ui.i18n import Translator


def describe(event: Event, t: Translator) -> str | None:
    """A log line for ``event``, or None for high-frequency events (progress, metrics)."""
    match event:
        case ScanStarted():
            return t("event.scan_started", modules=", ".join(event.modules) or "-")
        case ModuleStarted():
            return t("event.module_started", module=event.module)
        case ModuleProgress() | Metric():
            return None
        case ModuleLog():
            return t("event.log", module=event.module, message=event.message)
        case ModuleSkipped():
            return t("event.module_skipped", module=event.module, reason=event.reason.get(t.lang))
        case FindingEvent():
            f = event.finding
            return t(
                "event.finding",
                severity=f.severity.upper(),
                title=f.title.get(t.lang),
                location=f.location.display(),
            )
        case ModuleFinished():
            return t(
                "event.module_finished",
                module=event.module,
                status=event.status,
                count=event.finding_count,
                duration=f"{event.duration_s:.1f}",
            )
        case ScopeViolationEvent():
            return t("event.scope_violation", url=event.url, reason=event.reason)
        case ErrorEvent():
            return t("event.error", message=event.message)
        case ScanFinished():
            return t("event.scan_finished", status=event.status, duration=f"{event.duration_s:.1f}")
