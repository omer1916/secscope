"""Fake scan modules for orchestrator, worker and UI tests (SPEC M1)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import ClassVar

from secscope.core.models import Category, Evidence, Finding, HttpLocation, LocalizedStr
from secscope.core.process import ManagedProcess
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext
from secscope.modules.registry import ModuleRegistry

TREE = Path(__file__).resolve().parent / "helpers" / "tree.py"


def fake_finding(module: str, n: int) -> Finding:
    return Finding(
        rule_id="TEST-FAKE-001",
        module=module,
        category=Category.SECURITY,
        title=LocalizedStr(tr="Sahte bulgu", en="Fake finding"),
        severity="low",
        confidence="high",
        location=HttpLocation(url=f"http://localhost/{module}/{n}"),
        evidence=Evidence(snippet=f"{module}-{n}"),
        source_tools=["fake"],
    )


class FastModule(BaseModule):
    id: ClassVar[str] = "fake_fast"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Hızlı", en="Fast")
    category: ClassVar[Category] = Category.SECURITY

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        for i in range(3):
            await ctx.checkpoint()
            emit.progress((i + 1) * 33.3, f"step {i + 1}")
            emit.finding(fake_finding(self.id, i))
        emit.metric("demo", {"value": 1.0})
        return ModuleResult(data={"urls": ["http://localhost/a"]})


class DependentModule(BaseModule):
    id: ClassVar[str] = "fake_dependent"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Bağımlı", en="Dependent")
    category: ClassVar[Category] = Category.SEO
    depends_on: ClassVar[tuple[str, ...]] = ("fake_fast",)

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        upstream = ctx.results.get("fake_fast")
        urls: list[str] = upstream.data.get("urls", []) if upstream else []
        emit.log(f"got {len(urls)} urls from upstream")
        return ModuleResult(data={"seen": urls})


class SlowModule(BaseModule):
    id: ClassVar[str] = "fake_slow"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Yavaş", en="Slow")
    category: ClassVar[Category] = Category.PERFORMANCE

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        for i in range(600):
            await ctx.checkpoint()
            emit.progress(i / 6)
            await asyncio.sleep(0.05)
        return ModuleResult()


class ProcessModule(BaseModule):
    """Starts a process tree with a listening grandchild and waits forever."""

    id: ClassVar[str] = "fake_process"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Süreç", en="Process")
    category: ClassVar[Category] = Category.RESILIENCE
    exclusive: ClassVar[bool] = True
    started: ClassVar[list[tuple[int, int, int]]] = []  # (pid, grandchild pid, port)

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        async with await ManagedProcess.start([sys.executable, str(TREE)]) as proc:
            ctx.on_kill_target.append(proc.terminate_tree)
            line = await anext(proc.lines())
            gpid, port = (int(x) for x in line.split())
            ProcessModule.started.append((proc.pid, gpid, port))
            emit.log(f"tree up: {proc.pid} {gpid} port {port}")
            # Print a machine-readable marker for worker-level tests.
            emit.metric("tree", {"pid": float(proc.pid), "gpid": float(gpid), "port": float(port)})
            while True:
                await ctx.checkpoint()
                await asyncio.sleep(0.05)


class FailingModule(BaseModule):
    id: ClassVar[str] = "fake_failing"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Hatalı", en="Failing")
    category: ClassVar[Category] = Category.QUALITY

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        raise RuntimeError("boom with password=hunter2hunter2")


class TimeoutModule(BaseModule):
    id: ClassVar[str] = "fake_timeout"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Zaman aşımı", en="Timeout")
    category: ClassVar[Category] = Category.QUALITY
    timeout_s: ClassVar[float] = 0.2

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        await asyncio.sleep(10)
        return ModuleResult()


class MissingToolModule(BaseModule):
    id: ClassVar[str] = "fake_needs_tool"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Araç gerekli", en="Needs tool")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(tools=("nonexistent_tool",))

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:  # pragma: no cover
        raise AssertionError("must be skipped")


class DynamicModule(BaseModule):
    id: ClassVar[str] = "fake_dynamic"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Dinamik", en="Dynamic")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(target_running=True)

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        async with ctx.http_client() as client:
            try:
                await client.get("http://example.com/")
            except Exception as exc:
                emit.log(f"blocked as expected: {type(exc).__name__}")
        return ModuleResult()


class SourceModule(BaseModule):
    id: ClassVar[str] = "fake_source"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Kaynak", en="Source")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(needs_source=True)

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        return ModuleResult()


class ProbeModule(BaseModule):
    """Fetches the target's home page through the scope guard."""

    id: ClassVar[str] = "fake_probe"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Yokla", en="Probe")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(target_running=True)

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        assert ctx.target_url is not None
        async with ctx.http_client() as client:
            response = await client.get(ctx.target_url)
        return ModuleResult(
            data={
                "status": response.status_code,
                "url": ctx.target_url,
                "body": response.text[:500],
            }
        )


ALL_FAKES: tuple[type[BaseModule], ...] = (
    ProbeModule,
    FastModule,
    DependentModule,
    SlowModule,
    ProcessModule,
    FailingModule,
    TimeoutModule,
    MissingToolModule,
    DynamicModule,
    SourceModule,
)

FAKE_REFS: tuple[str, ...] = tuple(f"tests.fakes:{cls.__name__}" for cls in ALL_FAKES)


def fake_registry() -> ModuleRegistry:
    return ModuleRegistry(ALL_FAKES)
