"""Runs scan modules in dependency order with timeouts, pause and cancel (SPEC §3, §M1).

Scheduling: modules are grouped into dependency layers. Within a layer the
non-exclusive modules run concurrently (bounded), then exclusive ones (load
tests, ZAP) run alone. A module whose preconditions are not met is reported as
``module.skipped`` and never crashes the scan.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
import traceback
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from typing import Any

from secscope.core.events import (
    ErrorEvent,
    Event,
    FindingEvent,
    LogLevel,
    Metric,
    ModuleFinished,
    ModuleLog,
    ModuleProgress,
    ModuleSkipped,
    ModuleStarted,
    ModuleStatus,
    ScanFinished,
    ScanStarted,
    ScanStatus,
    ScopeViolationEvent,
)
from secscope.core.models import Finding, LocalizedStr
from secscope.core.redact import redact
from secscope.core.scope_guard import ScopeDecision
from secscope.modules.base import (
    BaseModule,
    Emitter,
    ModuleResult,
    PreflightResult,
    ScanCancelledError,
    ScanContext,
)
from secscope.modules.registry import ModuleRegistry

log = logging.getLogger(__name__)

EventSink = Callable[[Event], None]
FindingStore = Callable[[str, list[Finding]], object]
ModuleRunStore = Callable[[str, str, str, str | None, float], object]

# A scan phase that is not a scanner (preparing the project, starting/stopping the target).
Phase = Callable[[ScanContext, Emitter], Coroutine[Any, Any, None]]

_current_module: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "secscope_current_module", default=None
)


def dependency_layers(modules: Sequence[BaseModule]) -> list[list[BaseModule]]:
    """Topologically layer ``modules``; dependencies outside the selection are ignored."""
    by_id = {m.id: m for m in modules}
    remaining = {m.id: {d for d in m.depends_on if d in by_id} for m in modules}
    layers: list[list[BaseModule]] = []
    while remaining:
        ready = sorted(mid for mid, deps in remaining.items() if not deps)
        if not ready:
            raise ValueError(f"dependency cycle between modules: {sorted(remaining)}")
        layers.append([by_id[mid] for mid in ready])
        for mid in ready:
            del remaining[mid]
        for deps in remaining.values():
            deps.difference_update(ready)
    return layers


@dataclass
class ScanOutcome:
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list[Finding])
    module_status: dict[str, str] = field(default_factory=dict[str, str])
    duration_s: float = 0.0
    # Notes such as "reduced-coverage: ..." per module (from ModuleResult.notes).
    notes: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    scores: dict[str, object] = field(default_factory=dict[str, object])


class _ModuleEmitter:
    def __init__(self, orchestrator: Orchestrator, scan_id: str, module_id: str) -> None:
        self._o = orchestrator
        self._scan_id = scan_id
        self._module = module_id
        self.findings: list[Finding] = []

    def progress(self, pct: float, message: str = "") -> None:
        pct = min(max(pct, 0.0), 100.0)
        self._o.emit(
            ModuleProgress(scan_id=self._scan_id, module=self._module, pct=pct, message=message)
        )

    def log(self, message: str, level: LogLevel = "info") -> None:
        self._o.emit(
            ModuleLog(
                scan_id=self._scan_id, module=self._module, level=level, message=redact(message)
            )
        )

    def finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self._o.emit(FindingEvent(scan_id=self._scan_id, finding=finding))

    def metric(self, series: str, values: dict[str, float]) -> None:
        self._o.emit(
            Metric(scan_id=self._scan_id, module=self._module, series=series, values=values)
        )


class Orchestrator:
    def __init__(
        self,
        registry: ModuleRegistry,
        sink: EventSink,
        *,
        max_parallel: int = 3,
        store_findings: FindingStore | None = None,
        store_module_run: ModuleRunStore | None = None,
    ) -> None:
        self.registry = registry
        self._sink = sink
        self._sem = asyncio.Semaphore(max_parallel)
        self._store_findings = store_findings
        self._store_module_run = store_module_run
        self._tasks: set[asyncio.Task[None]] = set()
        self._ctx: ScanContext | None = None

    def emit(self, event: Event) -> None:
        try:
            self._sink(event)
        except Exception:  # a broken UI pipe must not kill the scan
            log.exception("event sink failed")

    # ------------------------------------------------------------- controls

    def pause(self) -> None:
        if self._ctx is not None:
            self._ctx.control.pause()

    def resume(self) -> None:
        if self._ctx is not None:
            self._ctx.control.resume()

    def cancel(self) -> None:
        if self._ctx is not None:
            self._ctx.control.cancel()
        for task in list(self._tasks):
            task.cancel()

    def kill_target(self) -> None:
        if self._ctx is None:
            return
        for callback in list(self._ctx.on_kill_target):
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    task = asyncio.ensure_future(result)
                    task.add_done_callback(lambda _t: None)
            except Exception:
                log.exception("kill_target callback failed")

    # ------------------------------------------------------------------ run

    def _on_violation(self, decision: ScopeDecision, via_redirect: bool) -> None:
        assert self._ctx is not None
        self.emit(
            ScopeViolationEvent(
                scan_id=self._ctx.scan_id,
                module=_current_module.get(),
                url=redact(decision.url),
                reason=decision.reason.value,
                via_redirect=via_redirect,
            )
        )

    async def run(
        self,
        ctx: ScanContext,
        module_ids: Sequence[str],
        *,
        setup: Phase | None = None,
        teardown: Phase | None = None,
    ) -> ScanOutcome:
        self._ctx = ctx
        if ctx.guard.on_violation is None:
            ctx.guard.on_violation = self._on_violation
        started = time.monotonic()
        modules = [self.registry.create(mid) for mid in dict.fromkeys(module_ids)]
        outcome = ScanOutcome(status="completed")
        self.emit(
            ScanStarted(
                scan_id=ctx.scan_id,
                profile=ctx.config.profile.value,
                modules=[m.id for m in modules],
                target=redact(ctx.config.target.value),
            )
        )
        try:
            if setup is not None:
                await self._run_phase(ctx, "prepare", setup, outcome)
            for layer in dependency_layers(modules):
                if ctx.control.cancelled:
                    break
                shared = [m for m in layer if not m.exclusive]
                exclusive = [m for m in layer if m.exclusive]
                await self._run_group(ctx, shared, outcome)
                for module in exclusive:
                    if ctx.control.cancelled:
                        break
                    await self._run_group(ctx, [module], outcome)
        except Exception as exc:  # orchestration bug: report, never hang the UI
            log.exception("scan failed")
            self.emit(
                ErrorEvent(
                    scan_id=ctx.scan_id, message=str(exc), detail=redact(traceback.format_exc())
                )
            )
            outcome.status = "failed"
        finally:
            if teardown is not None:
                await self._run_phase(ctx, "cleanup", teardown, outcome, always=True)
        if ctx.control.cancelled and outcome.status == "completed":
            outcome.status = "cancelled"
        outcome.duration_s = time.monotonic() - started
        self.emit(
            ScanFinished(scan_id=ctx.scan_id, status=outcome.status, duration_s=outcome.duration_s)
        )
        self._ctx = None
        return outcome

    async def _run_phase(
        self,
        ctx: ScanContext,
        name: str,
        phase: Phase,
        outcome: ScanOutcome,
        *,
        always: bool = False,
    ) -> None:
        if ctx.control.cancelled and not always:
            return
        emitter = _ModuleEmitter(self, ctx.scan_id, name)
        status: ModuleStatus = "ok"
        t0 = time.monotonic()
        self.emit(ModuleStarted(scan_id=ctx.scan_id, module=name))
        task = asyncio.create_task(phase(ctx, emitter), name=f"phase:{name}")
        if not always:
            self._tasks.add(task)  # cancellable; cleanup must always run to completion
        try:
            await task
        except (ScanCancelledError, asyncio.CancelledError):
            status = "cancelled"
        except Exception as exc:
            status = "failed"
            log.exception("phase %s failed", name)
            self.emit(
                ErrorEvent(
                    scan_id=ctx.scan_id,
                    module=name,
                    message=redact(str(exc)),
                    detail=redact(traceback.format_exc()),
                )
            )
        finally:
            self._tasks.discard(task)
        outcome.module_status[name] = status
        outcome.findings.extend(emitter.findings)
        if emitter.findings and self._store_findings is not None:
            self._store_findings(ctx.scan_id, emitter.findings)
        self.emit(
            ModuleFinished(
                scan_id=ctx.scan_id,
                module=name,
                status=status,
                duration_s=time.monotonic() - t0,
                finding_count=len(emitter.findings),
            )
        )

    async def _run_group(
        self, ctx: ScanContext, modules: list[BaseModule], outcome: ScanOutcome
    ) -> None:
        if not modules:
            return
        tasks = [
            asyncio.create_task(self._run_one(ctx, m, outcome), name=f"module:{m.id}")
            for m in modules
        ]
        self._tasks.update(tasks)
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._tasks.difference_update(tasks)

    def _preconditions(self, ctx: ScanContext, module: BaseModule) -> PreflightResult:
        req = module.requires
        if req.dynamic and not ctx.config.scope_statement_accepted:
            return PreflightResult.skipped(
                LocalizedStr(
                    tr="Kapsam beyanı onaylanmadı; dinamik testler çalışmaz.",
                    en="Scope statement not accepted; dynamic tests do not run.",
                ),
                LocalizedStr(
                    tr="Sihirbazda 'Bu sistem bana aittir' onayını verin "
                    "(CLI: --accept-scope-statement).",
                    en="Confirm 'This system is mine' in the wizard "
                    "(CLI: --accept-scope-statement).",
                ),
            )
        if req.target_running and ctx.target_url is None:
            return PreflightResult.skipped(
                LocalizedStr(tr="Çalışan hedef yok.", en="No running target."),
                LocalizedStr(
                    tr="Çalıştırma komutunu veya localhost adresini girin.",
                    en="Provide a run command or a localhost URL.",
                ),
            )
        if req.needs_source and ctx.source_dir is None:
            return PreflightResult.skipped(
                LocalizedStr(
                    tr="Kaynak kod yok (yalnızca URL verildi).",
                    en="No source code (only a URL was given).",
                ),
                LocalizedStr(
                    tr="Statik analiz için proje klasörünü veya zip dosyasını verin.",
                    en="Provide the project folder or zip for static analysis.",
                ),
            )
        try:
            return module.preflight(ctx)
        except Exception as exc:
            log.exception("preflight of %s failed", module.id)
            return PreflightResult.skipped(
                LocalizedStr(tr=f"Ön kontrol hatası: {exc}", en=f"Preflight error: {exc}")
            )

    async def _run_one(self, ctx: ScanContext, module: BaseModule, outcome: ScanOutcome) -> None:
        scan_id = ctx.scan_id
        pre = self._preconditions(ctx, module)
        if not pre.ok:
            assert pre.reason is not None
            self.emit(
                ModuleSkipped(
                    scan_id=scan_id,
                    module=module.id,
                    reason=pre.reason,
                    install_hint=pre.install_hint,
                )
            )
            outcome.module_status[module.id] = "skipped"
            self._record_run(scan_id, module.id, "skipped", pre.reason.en, 0.0)
            return

        async with self._sem:
            token = _current_module.set(module.id)
            emitter = _ModuleEmitter(self, scan_id, module.id)
            status: ModuleStatus = "ok"
            reason: str | None = None
            t0 = time.monotonic()
            self.emit(ModuleStarted(scan_id=scan_id, module=module.id))
            try:
                await ctx.checkpoint()
                async with asyncio.timeout(module.timeout_s):
                    result = await module.run(ctx, emitter)
                ctx.results[module.id] = result
            except (ScanCancelledError, asyncio.CancelledError):
                status = "cancelled"
                ctx.results[module.id] = ModuleResult()
            except TimeoutError:
                status, reason = "timeout", f"exceeded {module.timeout_s:g}s"
                self.emit(
                    ErrorEvent(scan_id=scan_id, module=module.id, message=f"{module.id} timed out")
                )
            except Exception as exc:
                status, reason = "failed", str(exc)
                log.exception("module %s failed", module.id)
                self.emit(
                    ErrorEvent(
                        scan_id=scan_id,
                        module=module.id,
                        message=redact(f"{module.id} failed: {exc}"),
                        detail=redact(traceback.format_exc()),
                    )
                )
            finally:
                _current_module.reset(token)
            duration = time.monotonic() - t0
            outcome.findings.extend(emitter.findings)
            outcome.module_status[module.id] = status
            if emitter.findings and self._store_findings is not None:
                self._store_findings(scan_id, emitter.findings)
            self._record_run(scan_id, module.id, status, reason, duration)
            self.emit(
                ModuleFinished(
                    scan_id=scan_id,
                    module=module.id,
                    status=status,
                    duration_s=duration,
                    finding_count=len(emitter.findings),
                )
            )

    def _record_run(
        self, scan_id: str, module_id: str, status: str, reason: str | None, duration: float
    ) -> None:
        if self._store_module_run is not None:
            try:
                self._store_module_run(scan_id, module_id, status, reason, duration)
            except Exception:
                log.exception("could not persist module run")
