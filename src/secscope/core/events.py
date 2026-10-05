"""Worker <-> UI protocol: JSON-Lines events and commands (SPEC §3.2).

Each line on the worker's stdout is one :data:`Event`; each line on its stdin
is one :data:`Command`. Every message carries ``v`` (protocol version) so a UI
and worker from different builds fail loudly instead of misinterpreting data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from secscope.core.models import Finding

PROTOCOL_VERSION = 1


def _now() -> datetime:
    return datetime.now(UTC)


class _Message(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: Literal[1] = PROTOCOL_VERSION


class _Event(_Message):
    ts: datetime = Field(default_factory=_now)
    scan_id: str


class ScanStarted(_Event):
    type: Literal["scan.started"] = "scan.started"
    profile: str
    modules: list[str]
    target: str


class ModuleStarted(_Event):
    type: Literal["module.started"] = "module.started"
    module: str


class ModuleProgress(_Event):
    type: Literal["module.progress"] = "module.progress"
    module: str
    pct: float = Field(ge=0, le=100)
    message: str = ""


LogLevel = Literal["debug", "info", "warning", "error"]


class ModuleLog(_Event):
    type: Literal["module.log"] = "module.log"
    module: str
    level: LogLevel = "info"
    message: str


class FindingEvent(_Event):
    type: Literal["finding"] = "finding"
    finding: Finding


class Metric(_Event):
    """A live chart sample, e.g. series="load" values={"rps": 120, "p95_ms": 340}."""

    type: Literal["metric"] = "metric"
    module: str
    series: str
    values: dict[str, float]


class ModuleSkipped(_Event):
    type: Literal["module.skipped"] = "module.skipped"
    module: str
    reason: str
    install_hint: str | None = None


ModuleStatus = Literal["ok", "failed", "cancelled", "timeout"]


class ModuleFinished(_Event):
    type: Literal["module.finished"] = "module.finished"
    module: str
    status: ModuleStatus
    duration_s: float = Field(ge=0)
    finding_count: int = Field(default=0, ge=0)


ScanStatus = Literal["completed", "cancelled", "failed", "interrupted"]


class ScanFinished(_Event):
    type: Literal["scan.finished"] = "scan.finished"
    status: ScanStatus
    duration_s: float = Field(ge=0)


class ErrorEvent(_Event):
    type: Literal["error"] = "error"
    module: str | None = None
    message: str
    detail: str | None = None


class ScopeViolationEvent(_Event):
    """A request outside the allowed scope was blocked (SPEC §4.6)."""

    type: Literal["scope.violation"] = "scope.violation"
    module: str | None = None
    url: str
    reason: str
    via_redirect: bool = False


Event = Annotated[
    ScanStarted
    | ModuleStarted
    | ModuleProgress
    | ModuleLog
    | FindingEvent
    | Metric
    | ModuleSkipped
    | ModuleFinished
    | ScanFinished
    | ErrorEvent
    | ScopeViolationEvent,
    Field(discriminator="type"),
]


# ------------------------------------------------------------------- commands


class StartCommand(_Message):
    cmd: Literal["start"] = "start"
    # Validated against ScanConfig by the worker; kept loose here so the
    # protocol module does not depend on configuration models.
    config: dict[str, Any]


class PauseCommand(_Message):
    cmd: Literal["pause"] = "pause"


class ResumeCommand(_Message):
    cmd: Literal["resume"] = "resume"


class CancelCommand(_Message):
    cmd: Literal["cancel"] = "cancel"


class KillTargetCommand(_Message):
    cmd: Literal["kill_target"] = "kill_target"


Command = Annotated[
    StartCommand | PauseCommand | ResumeCommand | CancelCommand | KillTargetCommand,
    Field(discriminator="cmd"),
]

EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)
COMMAND_ADAPTER: TypeAdapter[Command] = TypeAdapter(Command)


def encode(message: _Message) -> str:
    """Serialise one event/command as a single JSON line (with trailing newline)."""
    return message.model_dump_json() + "\n"


def decode_event(line: str | bytes) -> Event:
    return EVENT_ADAPTER.validate_json(line)


def decode_command(line: str | bytes) -> Command:
    return COMMAND_ADAPTER.validate_json(line)
