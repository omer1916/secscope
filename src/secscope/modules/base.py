"""The contract every scanner implements (SPEC §5).

Adding a scanner = one file with a ``BaseModule`` subclass + one line in
``secscope.modules.registry.BUILTIN_MODULES``.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Protocol

from secscope.core.config import ScanConfig, ScanProfile, Settings
from secscope.core.events import LogLevel
from secscope.core.models import Category, Finding, LocalizedStr
from secscope.core.scope_guard import ScopedHttpClient, ScopeGuard
from secscope.core.toolmgr import ToolManager


@dataclass(frozen=True, slots=True)
class Requirements:
    tools: tuple[str, ...] = ()
    # Needs a running target URL (DAST, browser, SEO, load...).
    target_running: bool = False
    # Needs the project's source tree (SAST, secrets, SCA...).
    needs_source: bool = False

    @property
    def dynamic(self) -> bool:
        """Dynamic modules send traffic and need the scope statement (SPEC §4.5)."""
        return self.target_running


@dataclass(frozen=True, slots=True)
class PreflightResult:
    ok: bool
    reason: LocalizedStr | None = None
    install_hint: LocalizedStr | None = None

    @classmethod
    def ready(cls) -> PreflightResult:
        return cls(ok=True)

    @classmethod
    def skipped(
        cls, reason: LocalizedStr, install_hint: LocalizedStr | None = None
    ) -> PreflightResult:
        return cls(ok=False, reason=reason, install_hint=install_hint)


@dataclass(slots=True)
class ModuleResult:
    # Artifacts for downstream modules, e.g. {"urls": [...]} from a crawler.
    data: dict[str, Any] = field(default_factory=dict[str, Any])
    notes: list[str] = field(default_factory=list[str])


class Emitter(Protocol):
    """How a module reports back. All methods are non-blocking."""

    def progress(self, pct: float, message: str = "") -> None: ...
    def log(self, message: str, level: LogLevel = "info") -> None: ...
    def finding(self, finding: Finding) -> None: ...
    def metric(self, series: str, values: dict[str, float]) -> None: ...


class ScanCancelledError(Exception):
    """Raised from :meth:`ScanContext.checkpoint` once the scan is cancelled."""


@dataclass
class ScanControl:
    """Pause/cancel switches shared by the orchestrator and every module."""

    _running: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False

    def __post_init__(self) -> None:
        self._running.set()

    @property
    def paused(self) -> bool:
        return not self._running.is_set()

    def pause(self) -> None:
        self._running.clear()

    def resume(self) -> None:
        self._running.set()

    def cancel(self) -> None:
        self.cancelled = True
        self._running.set()  # wake paused modules so they can observe the cancel

    async def checkpoint(self) -> None:
        if self.cancelled:
            raise ScanCancelledError
        await self._running.wait()
        if self.cancelled:
            raise ScanCancelledError


@dataclass
class ScanContext:
    scan_id: str
    config: ScanConfig
    settings: Settings
    work_dir: Path
    guard: ScopeGuard
    tools: ToolManager
    source_dir: Path | None = None
    target_url: str | None = None
    control: ScanControl = field(default_factory=ScanControl)
    # Results of modules that ran earlier, keyed by module id.
    results: dict[str, ModuleResult] = field(default_factory=dict[str, ModuleResult])
    # Called by modules that start the target, so "kill_target" can reach it.
    on_kill_target: list[Callable[[], Any]] = field(default_factory=list[Callable[[], Any]])

    async def checkpoint(self) -> None:
        """Call regularly from long loops: honours pause and raises on cancel."""
        await self.control.checkpoint()

    def http_client(self, **kwargs: Any) -> ScopedHttpClient:
        """The only way a module gets an HTTP client."""
        return ScopedHttpClient(self.guard, **kwargs)


class ScanModule(Protocol):
    id: ClassVar[str]
    title: ClassVar[LocalizedStr]
    category: ClassVar[Category]
    requires: ClassVar[Requirements]
    depends_on: ClassVar[tuple[str, ...]]
    exclusive: ClassVar[bool]
    timeout_s: ClassVar[float]

    def preflight(self, ctx: ScanContext) -> PreflightResult: ...
    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult: ...


class BaseModule(ABC):
    """Convenience base with sensible defaults; subclasses set the ClassVars."""

    id: ClassVar[str]
    title: ClassVar[LocalizedStr]
    category: ClassVar[Category]
    requires: ClassVar[Requirements] = Requirements()
    # Modules that must finish first *if they are part of the same scan*.
    depends_on: ClassVar[tuple[str, ...]] = ()
    # Exclusive modules (load tests, ZAP) never run concurrently with others.
    exclusive: ClassVar[bool] = False
    timeout_s: ClassVar[float] = 30 * 60
    # Built-in scan profiles that include this module (custom = explicit list).
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset(
        {ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP}
    )

    def preflight(self, ctx: ScanContext) -> PreflightResult:
        for tool in self.requires.tools:
            status = ctx.tools.status(tool)
            if not status.available:
                return PreflightResult.skipped(
                    LocalizedStr(
                        tr=f"{tool} kullanılamıyor: {status.problem}",
                        en=f"{tool} not available: {status.problem}",
                    ),
                    status.install_hint,
                )
        return PreflightResult.ready()

    @abstractmethod
    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult: ...
