"""One complete scan: prepare the project, start the target, run modules, clean up.

Used by both the worker (desktop) and the headless CLI so they behave identically.
The user's code is executed only when a selected module needs a running target
*and* the scope statement was accepted.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from secscope.core.config import TargetKind
from secscope.core.coverage import background_reason, build_coverage
from secscope.core.dedup import deduplicate
from secscope.core.fingerprint import fingerprint
from secscope.core.gitinfo import changed_files, revision
from secscope.core.intake import make_run_copy, prepare_source
from secscope.core.models import CodeLocation, Finding
from secscope.core.orchestrator import Orchestrator, ScanOutcome
from secscope.core.sandbox import SandboxRunner, TargetStartError
from secscope.core.scoring import compute_scores
from secscope.core.snapshot import Snapshot
from secscope.modules.base import Emitter, ScanContext


def background_code(findings: Sequence[Finding]) -> list[Finding]:
    """Code findings in tests, fixtures, examples or generated files are shown as "info"
    (visible, not scored): they are not the application. Secrets are never demoted: a real
    key committed in a fixture is still a leaked key."""
    out: list[Finding] = []
    for f in findings:
        reason = (
            background_reason(f.location.path)
            if isinstance(f.location, CodeLocation) and f.module == "sast"
            else None
        )
        if reason is None or f.severity == "info":
            out.append(f)
            continue
        extra = {**f.evidence.extra, "background": reason, "original_severity": f.severity}
        out.append(
            f.model_copy(
                update={
                    "severity": "info",
                    "evidence": f.evidence.model_copy(update={"extra": extra}),
                }
            )
        )
    return out


def only_changed(findings: Sequence[Finding], changed: set[str] | None) -> list[Finding]:
    """``--changed-since``: keep code findings in changed files (plus every non-code
    finding, e.g. SEO or HTTP checks, which have no file)."""
    if changed is None:
        return list(findings)
    return [
        f
        for f in findings
        if not isinstance(f.location, CodeLocation) or f.location.path in changed
    ]


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
            original = Path(ctx.config.target.value)
            report = prepare_source(original, ctx.work_dir, exclude=ctx.config.exclude)
            ctx.source_dir = report.root
            emit.log(f"project copied: {report.files} files, {report.bytes / 1e6:.1f} MB")
            if report.excluded:
                emit.log(f"{len(report.excluded)} path(s) excluded by request")
            ctx.coverage = build_coverage(
                report.root,
                files=report.files,
                total_bytes=report.bytes,
                excluded=report.excluded,
                exclude_patterns=ctx.config.exclude,
                skipped_links=report.skipped_links,
                dependency_dirs=report.dependency_dirs,
            )
            if kind == TargetKind.FOLDER:
                rev = await revision(original)
                ctx.revision = rev.as_dict() if rev else None
                if ctx.config.changed_since:
                    ctx.changed_files = await changed_files(original, ctx.config.changed_since)
                    emit.log(
                        f"{len(ctx.changed_files)} file(s) changed since {ctx.config.changed_since}"
                    )
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
    outcome.findings = deduplicate(
        only_changed(background_code(outcome.findings), ctx.changed_files)
    )
    outcome.notes = {mid: list(res.notes) for mid, res in ctx.results.items() if res.notes}
    score_outcome(ctx, outcome)
    return outcome


def score_outcome(ctx: ScanContext, outcome: ScanOutcome) -> None:
    """(Re)compute scores, e.g. after suppressions were applied."""
    ran = [m for m, status in outcome.module_status.items() if status == "ok"]
    outcome.tool_versions = {t.name: t.version or "?" for t in ctx.tools.detected() if t.available}
    seo = ctx.results.get("seo")
    seo_value = seo.data.get("seo_score", {}).get("score") if seo is not None else None
    sca = ctx.results.get("sca")
    outcome.scores = compute_scores(
        outcome.findings,
        weights=ctx.settings.weights,
        ran=ran,
        seo=seo_value,
        dependencies_measured=sca is None or bool(sca.data.get("advisories_assessed", True)),
    ).as_dict()
