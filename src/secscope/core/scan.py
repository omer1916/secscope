"""One complete scan: prepare the project, start the target, run modules, clean up.

Used by both the worker (desktop) and the headless CLI so they behave identically.
The user's code is executed only when a selected module needs a running target
*and* the scope statement was accepted.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from secscope.core.config import TargetKind
from secscope.core.dedup import deduplicate
from secscope.core.fingerprint import fingerprint
from secscope.core.intake import make_run_copy, prepare_source
from secscope.core.orchestrator import Orchestrator, ScanOutcome
from secscope.core.sandbox import SandboxRunner, TargetStartError
from secscope.core.scoring import compute_scores
from secscope.core.snapshot import Snapshot
from secscope.modules.base import Emitter, ScanContext


def _needs_target(orchestrator: Orchestrator, ctx: ScanContext, module_ids: Sequence[str]) -> bool:
    if ctx.config.target.kind == TargetKind.URL or not ctx.config.scope_statement_accepted:
        return False
    return any(orchestrator.registry.get(m).requires.target_running for m in module_ids)


async def _python_for(ctx: ScanContext, runner: SandboxRunner, emit: Emitter) -> str:
    system_python = str(ctx.tools.path("python"))
    if not ctx.config.run.install:
        return system_python
    emit.log("creating a virtualenv for the target")
    return await runner.prepare_python_env(system_python)


async def _start_target(ctx: ScanContext, emit: Emitter, state: dict[str, object]) -> None:
    assert ctx.source_dir is not None
    fp = ctx.fingerprint
    run_dir = make_run_copy(ctx.source_dir, ctx.work_dir)
    if ctx.config.snapshot_sqlite:
        snap = Snapshot.take(run_dir, ctx.work_dir / "snapshots")
        state["snapshot"] = snap
        if snap.files:
            emit.log(f"snapshot of {len(snap.files)} SQLite database(s) taken")

    runner = SandboxRunner(
        ctx.work_dir,
        ctx.guard,
        on_log=lambda line: emit.log(line, "debug"),
        on_metric=lambda values: emit.metric("target", values),
    )
    ctx.runner = runner
    run = ctx.config.run
    command = run.command or (fp.run_command if fp else None)
    try:
        if command is None and fp is not None and fp.kind == "static":
            root = run_dir / (fp.static_root or ".")
            emit.log(f"serving static site from {root.relative_to(run_dir).as_posix() or '.'}")
            info = await runner.start_static(root, timeout=run.startup_timeout_s)
        elif command is None:
            raise TargetStartError(
                "no run command detected; enter one in the wizard (or --run on the CLI)"
            )
        else:
            needs_python = any("{python}" in a for a in [*command, *(run.install_command or [])])
            if fp is not None and fp.install_command and not run.install_command:
                needs_python = needs_python or any("{python}" in a for a in fp.install_command)
            python = await _python_for(ctx, runner, emit) if needs_python else None
            install = run.install_command or (fp.install_command if fp else None)
            if run.install and install:
                emit.log("installing dependencies: " + " ".join(install))
                await runner.install(install, cwd=run_dir, python=python, extra_env=run.env)
            cwd = run_dir / run.workdir if run.workdir else run_dir
            env = {**(fp.env if fp else {}), **run.env}
            info = await runner.start(
                command,
                cwd=cwd,
                port=run.port,
                extra_env=env,
                python=python,
                ready_path=run.ready_path,
                timeout=run.startup_timeout_s,
            )
    except TargetStartError as exc:
        for line in exc.log_tail:
            emit.log(line, "error")
        raise
    ctx.target = info
    ctx.target_url = info.url
    ctx.on_kill_target.append(runner.stop)
    emit.log(f"target is up at {info.url} (pid {info.pid})")
    for address in info.exposed_beyond_loopback:
        emit.log(f"target also listens on {address}", "warning")


async def run_scan(
    orchestrator: Orchestrator, ctx: ScanContext, module_ids: Sequence[str]
) -> ScanOutcome:
    state: dict[str, object] = {}
    module_ids = list(dict.fromkeys(module_ids))

    async def prepare(ctx: ScanContext, emit: Emitter) -> None:
        kind = ctx.config.target.kind
        if kind in (TargetKind.FOLDER, TargetKind.ARCHIVE):
            emit.progress(5, "copying project")
            report = prepare_source(Path(ctx.config.target.value), ctx.work_dir)
            ctx.source_dir = report.root
            emit.log(f"project copied: {report.files} files, {report.bytes / 1e6:.1f} MB")
            if report.skipped_links:
                emit.log(f"{len(report.skipped_links)} symbolic link(s) skipped", "warning")
            fp = fingerprint(report.root)
            ctx.fingerprint = fp
            emit.log(
                f"detected stack: {fp.stack} ({', '.join(fp.languages) or '-'})"
                + (f", run: {' '.join(fp.run_command)}" if fp.run_command else "")
            )
        if _needs_target(orchestrator, ctx, module_ids):
            emit.progress(40, "starting target")
            await _start_target(ctx, emit, state)
        emit.progress(100)

    async def cleanup(ctx: ScanContext, emit: Emitter) -> None:
        if ctx.runner is not None:
            await ctx.runner.stop()
            ctx.runner.close()
            emit.log("target stopped")
        snap = state.get("snapshot")
        if isinstance(snap, Snapshot) and snap.files:
            restored = snap.restore()
            emit.log(f"restored {len(restored)} SQLite database(s)")

    outcome = await orchestrator.run(ctx, module_ids, setup=prepare, teardown=cleanup)
    outcome.findings = deduplicate(outcome.findings)
    outcome.notes = {mid: list(res.notes) for mid, res in ctx.results.items() if res.notes}
    ran = [m for m, status in outcome.module_status.items() if status == "ok"]
    outcome.scores = compute_scores(
        outcome.findings, weights=ctx.settings.weights, ran=ran
    ).as_dict()
    return outcome
