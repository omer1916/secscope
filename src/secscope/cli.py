"""Command line entry point (headless mode, SPEC §11.3).

Exit codes: 0 success · 1 scan failed · 2 usage/configuration error ·
3 findings at or above ``--fail-on`` severity.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from secscope.__about__ import __app_id__, __app_name__, __version__

SCHEMA_KINDS = ("finding", "event", "command", "settings", "scan-config")
SEVERITIES = ("critical", "high", "medium", "low", "info")

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_FAIL_ON = 0, 1, 2, 3


def _schema(kind: str) -> dict[str, object]:
    # Imported lazily so `--version` stays instant.
    from secscope.core import config, events, models  # noqa: PLC0415

    match kind:
        case "finding":
            return models.Finding.model_json_schema()
        case "event":
            return events.EVENT_ADAPTER.json_schema()
        case "command":
            return events.COMMAND_ADAPTER.json_schema()
        case "settings":
            return config.Settings.model_json_schema()
        case "scan-config":
            return config.ScanConfig.model_json_schema()
        case _:
            raise ValueError(kind)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__app_id__,
        description=f"{__app_name__}: local-only security, SEO and resilience testing.",
    )
    parser.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", help="scan a local project or a loopback URL")
    target = scan.add_mutually_exclusive_group(required=True)
    target.add_argument("--path", type=Path, help="project folder")
    target.add_argument("--zip", type=Path, help="project archive (.zip/.tar.gz)")
    target.add_argument("--url", help="already running app, e.g. http://localhost:3000")
    scan.add_argument(
        "--profile", choices=["quick", "standard", "deep", "custom"], default="standard"
    )
    scan.add_argument("--modules", help="comma-separated module ids (overrides the profile)")
    scan.add_argument("--run", help='command that starts the app, e.g. "npm start"')
    scan.add_argument("--port", type=int, help="port the app listens on")
    scan.add_argument("--ready-path", default="/", help="path polled until the app is ready")
    scan.add_argument("--out", type=Path, default=Path("reports"), help="output directory")
    scan.add_argument(
        "--format", default="html,json", help="comma-separated: html,json,sarif,csv,pdf"
    )
    scan.add_argument(
        "--fail-on", choices=SEVERITIES, help="exit 3 if a finding is at least this severe"
    )
    scan.add_argument(
        "--accept-scope-statement",
        action="store_true",
        help="I own this system and it is tested locally only (required for dynamic modules)",
    )
    scan.add_argument("--data-dir", type=Path, help="override the data directory")
    scan.add_argument(
        "--public-url", help="production address of the site (SEO), e.g. https://example.com"
    )
    scan.add_argument(
        "--install",
        action="store_true",
        help="install the project's dependencies before starting it",
    )

    tools = sub.add_parser("tools", help="external tool management")
    tools_sub = tools.add_subparsers(dest="tools_command", metavar="<action>", required=True)
    tools_sub.add_parser("list", help="show detected tools and versions")
    install = tools_sub.add_parser("install", help="download a pinned tool (SHA-256 verified)")
    install.add_argument("names", nargs="+")
    tools_sub.add_parser("update-db", help="download/refresh offline vulnerability databases")
    verify = tools_sub.add_parser("verify", help="re-check managed tools")
    verify.add_argument("names", nargs="*")

    modules = sub.add_parser("modules", help="list available scan modules")
    modules.add_argument("--profile", choices=["quick", "standard", "deep"])

    report = sub.add_parser("report", help="render a stored scan again")
    report.add_argument("scan_id")
    report.add_argument("--format", default="html", help="comma-separated: html,json,sarif,csv,pdf")
    report.add_argument("--out", type=Path, default=Path("reports"))
    report.add_argument("--lang", choices=["tr", "en"])

    diff = sub.add_parser("diff", help="compare two scans (new / fixed / persistent / regressed)")
    diff.add_argument("before", help="scan id or report.json path")
    diff.add_argument("after", help="scan id or report.json path")
    diff.add_argument("--json", action="store_true", help="machine-readable output")

    suppress = sub.add_parser("suppress", help="mark a finding or a whole rule as a false positive")
    target_group = suppress.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--finding", help="finding id")
    target_group.add_argument("--rule", help="rule id, e.g. SEO-OG-001")
    suppress.add_argument("--reason", required=True, help="why this is not a real problem")

    schema = sub.add_parser("schema", help="print the JSON schema of a data model")
    schema.add_argument("kind", choices=SCHEMA_KINDS)

    # Internal: frozen builds start the worker as `secscope worker`.
    sub.add_parser("worker", help=argparse.SUPPRESS)
    return parser


def _cmd_tools_list(out: TextIO) -> int:
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.core.session import tool_manager  # noqa: PLC0415

    settings = Settings.load()
    manager = tool_manager(settings)
    lang = settings.language
    for status in manager.statuses():
        if status.available:
            version = status.version or "?"
            where = f"{status.path} ({status.source})"
            out.write(f"  OK      {status.name:<14} {version:<12} {where}\n")
        else:
            hint = status.install_hint.get(lang) if status.install_hint else ""
            out.write(f"  MISSING {status.name:<14} {status.problem}\n          -> {hint}\n")
    return EXIT_OK


def _cmd_tools_install(names: list[str], out: TextIO, err: TextIO) -> int:
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.core.downloader import DownloadError, install_tool  # noqa: PLC0415
    from secscope.core.session import tool_manager  # noqa: PLC0415

    manager = tool_manager(Settings.load())
    code = EXIT_OK
    for name in names:
        try:
            path = install_tool(manager, name)
        except (DownloadError, KeyError, OSError) as exc:
            err.write(f"  FAILED  {name}: {exc}\n")
            code = EXIT_FAILED
            continue
        status = manager.status(name)
        out.write(f"  OK      {name} {status.version} -> {path} (sha256 verified)\n")
    return code


def _cmd_tools_update_db(out: TextIO) -> int:
    from secscope.core.advisories import update_databases  # noqa: PLC0415
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.core.session import tool_manager  # noqa: PLC0415

    settings = Settings.load()
    lines = asyncio.run(update_databases(tool_manager(settings), settings.data_dir))
    for line in lines:
        out.write(f"  {line}\n")
    return EXIT_OK if all("failed" not in line for line in lines) else EXIT_FAILED


def _cmd_tools_verify(names: list[str], out: TextIO) -> int:
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.core.downloader import verify_tool  # noqa: PLC0415
    from secscope.core.session import tool_manager  # noqa: PLC0415

    manager = tool_manager(Settings.load())
    targets = names or [n for n, s in manager.manifest.tools.items() if s.downloads]
    ok = True
    for name in targets:
        good = verify_tool(manager, name)
        ok = ok and good
        out.write(f"  {'OK' if good else 'MISSING':<7} {name}\n")
    return EXIT_OK if ok else EXIT_FAILED


def _cmd_modules(profile: str | None, out: TextIO) -> int:
    from secscope.core.config import ScanProfile, Settings  # noqa: PLC0415
    from secscope.modules.registry import load_builtin  # noqa: PLC0415

    registry = load_builtin()
    ids = registry.for_profile(ScanProfile(profile)) if profile else registry.ids()
    lang = Settings.load().language
    for module_id in ids:
        cls = registry.get(module_id)
        out.write(f"  {module_id:<18} {cls.category.value:<12} {cls.title.get(lang)}\n")
    if not ids:
        out.write("  (no modules registered yet)\n")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from secscope.core.config import (  # noqa: PLC0415
        RunConfig,
        ScanConfig,
        ScanProfile,
        Settings,
        Target,
        TargetKind,
    )
    from secscope.core.models import SEVERITY_ORDER  # noqa: PLC0415
    from secscope.core.orchestrator import Orchestrator  # noqa: PLC0415
    from secscope.core.scan import run_scan  # noqa: PLC0415
    from secscope.core.session import InvalidTargetError, open_session  # noqa: PLC0415
    from secscope.modules.registry import load_builtin  # noqa: PLC0415
    from secscope.reporting.console import ConsoleReporter  # noqa: PLC0415
    from secscope.reporting.finalize import finalize_scan  # noqa: PLC0415
    from secscope.reporting.writer import ReportFormatError, write_outputs  # noqa: PLC0415

    if args.path is not None:
        target = Target(kind=TargetKind.FOLDER, value=str(args.path.resolve()))
    elif args.zip is not None:
        target = Target(kind=TargetKind.ARCHIVE, value=str(args.zip.resolve()))
    else:
        target = Target(kind=TargetKind.URL, value=args.url)

    settings = Settings.load()
    if args.data_dir is not None:
        settings = settings.model_copy(update={"data_dir": args.data_dir})
    config = ScanConfig(
        target=target,
        profile=ScanProfile(args.profile),
        modules=args.modules.split(",") if args.modules else [],
        run=RunConfig(
            command=args.run.split() if args.run else None,
            port=args.port,
            ready_path=args.ready_path,
            install=args.install,
        ),
        scope_statement_accepted=args.accept_scope_statement,
        public_url=args.public_url,
    )
    registry = load_builtin()
    module_ids = config.modules or registry.for_profile(config.profile)
    try:
        for module_id in module_ids:
            registry.get(module_id)
        session = open_session(config, settings)
    except (KeyError, InvalidTargetError) as exc:
        err.write(f"error: {exc}\n")
        return EXIT_USAGE

    reporter = ConsoleReporter(err, settings.language)
    orchestrator = Orchestrator(
        registry,
        reporter,
        store_findings=session.repo.add_findings,
        store_module_run=session.repo.record_module_run,
    )
    try:
        outcome = asyncio.run(run_scan(orchestrator, session.ctx, module_ids))
    except KeyboardInterrupt:
        err.write("interrupted\n")
        session.repo.finish_scan(session.ctx.scan_id, "interrupted")
        session.close()
        return EXIT_FAILED
    report = finalize_scan(session, outcome)

    scores = outcome.scores
    if scores:
        err.write(
            f"[score] overall {scores['overall']} ({scores['grade']}) | security {scores['security']}"
            f" | dependencies {scores['dependencies']} | quality {scores['quality']}\n"
        )
    for module_id, notes in outcome.notes.items():
        for note in notes:
            err.write(f"[note] {module_id}: {note}\n")
    session.close()
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    try:
        written = write_outputs(report, args.out, formats, lang=settings.language)
    except ReportFormatError as exc:
        err.write(f"error: {exc}\n")
        return EXIT_USAGE
    for path in written.values():
        out.write(f"{path}\n")

    if outcome.status == "failed":
        return EXIT_FAILED
    if args.fail_on is not None:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in outcome.findings):
            return EXIT_FAIL_ON
    return EXIT_OK


def _report_path(ref: str) -> Path:
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.reporting.json_export import REPORT_FILE  # noqa: PLC0415

    direct = Path(ref)
    if direct.is_file():
        return direct
    return Settings.load().data_dir / "scans" / ref / REPORT_FILE


def _cmd_report(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from secscope.reporting.json_export import load_report  # noqa: PLC0415
    from secscope.reporting.writer import ReportFormatError, write_outputs  # noqa: PLC0415

    path = _report_path(args.scan_id)
    if not path.is_file():
        err.write(f"error: no stored report for {args.scan_id} ({path})\n")
        return EXIT_USAGE
    formats = [f.strip() for f in args.format.split(",")]
    try:
        written = write_outputs(load_report(path), args.out, formats, lang=args.lang)
    except (ReportFormatError, ValueError) as exc:
        err.write(f"error: {exc}\n")
        return EXIT_USAGE
    for p in written.values():
        out.write(f"{p}\n")
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from secscope.reporting.diff import diff_reports  # noqa: PLC0415
    from secscope.reporting.json_export import load_report  # noqa: PLC0415

    paths = [_report_path(args.before), _report_path(args.after)]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        err.write(f"error: report not found: {', '.join(missing)}\n")
        return EXIT_USAGE
    d = diff_reports(load_report(paths[0]), load_report(paths[1]))
    s = d.summary()
    if args.json:
        data = {
            **s,
            "new_ids": [f.id for f in d.new],
            "fixed_ids": [f.id for f in d.fixed],
            "regressed_ids": [after.id for _before, after in d.regressed],
        }
        json.dump(data, out, indent=2)
        out.write("\n")
        return EXIT_OK
    out.write(
        f"new {s['new']} (critical/high {s['new_critical_or_high']}) | fixed {s['fixed']} | "
        f"persistent {s['persistent']} | regressed {s['regressed']}\n"
    )
    deltas = ", ".join(f"{k} {v:+}" for k, v in s["score_delta"].items() if v is not None)
    if deltas:
        out.write(f"score delta: {deltas}\n")
    for label, items in (("NEW", d.new), ("FIXED", d.fixed)):
        for f in items:
            out.write(
                f"  {label:<6} {f.severity.upper():<8} {f.rule_id:<20} {f.location.display()}\n"
            )
    for before, after in d.regressed:
        out.write(
            f"  WORSE  {before.severity}->{after.severity} {after.rule_id} {after.location.display()}\n"
        )
    return EXIT_OK


def _cmd_suppress(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from secscope.core.config import Settings  # noqa: PLC0415
    from secscope.core.session import database_path  # noqa: PLC0415
    from secscope.storage import db  # noqa: PLC0415
    from secscope.storage.repo import ScanRepository  # noqa: PLC0415

    if not args.reason.strip():
        err.write("error: a reason is required\n")
        return EXIT_USAGE
    conn = db.connect(database_path(Settings.load()))
    try:
        ScanRepository(conn).add_suppression(
            args.reason, finding_id=args.finding, rule_id=args.rule
        )
    finally:
        conn.close()
    out.write(f"suppressed {args.finding or args.rule}: {args.reason}\n")
    return EXIT_OK


def _utf8_stdio() -> None:
    # Windows writes redirected/piped output in the ANSI code page (cp1254 on
    # Turkish systems), which garbles text in Git Bash, CI logs and files.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    _utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    match args.command:
        case "schema":
            json.dump(_schema(args.kind), sys.stdout, indent=2, ensure_ascii=True)
            sys.stdout.write("\n")
            return EXIT_OK
        case "tools" if args.tools_command == "install":
            return _cmd_tools_install(args.names, sys.stdout, sys.stderr)
        case "tools" if args.tools_command == "update-db":
            return _cmd_tools_update_db(sys.stdout)
        case "tools" if args.tools_command == "verify":
            return _cmd_tools_verify(args.names, sys.stdout)
        case "tools":
            return _cmd_tools_list(sys.stdout)
        case "modules":
            return _cmd_modules(args.profile, sys.stdout)
        case "scan":
            return _cmd_scan(args, sys.stdout, sys.stderr)
        case "report":
            return _cmd_report(args, sys.stdout, sys.stderr)
        case "diff":
            return _cmd_diff(args, sys.stdout, sys.stderr)
        case "suppress":
            return _cmd_suppress(args, sys.stdout, sys.stderr)
        case "worker":
            from secscope.worker.main import main as worker_main  # noqa: PLC0415

            return worker_main()
        case _:
            parser.print_help()
            return EXIT_OK
