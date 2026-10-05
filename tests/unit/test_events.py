from __future__ import annotations

import pytest
from pydantic import ValidationError

from secscope.core.events import (
    CancelCommand,
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
    StartCommand,
    decode_command,
    decode_event,
    encode,
)
from secscope.core.models import LocalizedStr
from tests.unit.test_models import make_finding

EVENTS: list[Event] = [
    ScanStarted(scan_id="s1", profile="quick", modules=["sast"], target="./proj"),
    ModuleStarted(scan_id="s1", module="sast"),
    ModuleProgress(scan_id="s1", module="sast", pct=42.5, message="files 10/20"),
    ModuleLog(scan_id="s1", module="sast", level="warning", message="slow"),
    FindingEvent(scan_id="s1", finding=make_finding()),
    Metric(scan_id="s1", module="load", series="load", values={"rps": 120.0, "p95_ms": 340.0}),
    ModuleSkipped(
        scan_id="s1",
        module="dast_zap",
        reason=LocalizedStr(tr="Java yok", en="java missing"),
        install_hint=LocalizedStr(tr="Java 17 kurun", en="Install Java 17"),
    ),
    ModuleFinished(scan_id="s1", module="sast", status="ok", duration_s=1.5, finding_count=3),
    ScanFinished(scan_id="s1", status="completed", duration_s=9.0),
    ErrorEvent(scan_id="s1", message="boom"),
    ScopeViolationEvent(scan_id="s1", url="http://evil.com/", reason="name_not_allowed"),
]


@pytest.mark.parametrize("event", EVENTS, ids=lambda e: e.type)
def test_event_roundtrip(event: Event) -> None:
    line = encode(event)
    assert line.endswith("\n")
    assert "\n" not in line[:-1]
    assert decode_event(line) == event


def test_every_event_type_covered() -> None:
    assert len({e.type for e in EVENTS}) == len(EVENTS)


def test_event_has_version_and_timestamp() -> None:
    line = encode(EVENTS[0])
    assert '"v":1' in line
    assert '"ts":' in line


def test_unknown_version_rejected() -> None:
    line = encode(EVENTS[1]).replace('"v":1', '"v":2')
    with pytest.raises(ValidationError):
        decode_event(line)


def test_unknown_type_rejected() -> None:
    with pytest.raises(ValidationError):
        decode_event('{"v":1,"type":"nope","scan_id":"s","ts":"2026-01-01T00:00:00Z"}')


def test_progress_bounds() -> None:
    with pytest.raises(ValidationError):
        ModuleProgress(scan_id="s", module="m", pct=101)


def test_command_roundtrip() -> None:
    start = StartCommand(config={"target": {"kind": "url", "value": "x"}})
    assert decode_command(encode(start)) == start
    assert decode_command(encode(CancelCommand())) == CancelCommand()
    assert decode_command('{"v":1,"cmd":"kill_target"}').cmd == "kill_target"
