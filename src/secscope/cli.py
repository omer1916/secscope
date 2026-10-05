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
        "--format", default="json", help="comma-separated: json (more in later versions)"
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

    tools = sub.add_parser("tools", help="external tool management")
    tools_sub = tools.add_subparsers(dest="tools_command", metavar="<action>", required=True)
    tools_sub.add_parser("list", help="show detected tools and versions")

    modules = sub.add_parser("modules", help="list available scan modules")
    modules.add_argument("--profile", choices=["quick", "standard", "deep"])

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
    from secscope.core.session import InvalidTargetError, open_session  # noqa: PLC0415
    from secscope.modules.registry import load_builtin  # noqa: PLC0415
    from secscope.reporting.console import ConsoleReporter  # noqa: PLC0415
    from secscope.reporting.json_export import write_json_report  # noqa: PLC0415

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
        ),
        scope_statement_accepted=args.accept_scope_statement,
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
        outcome = asyncio.run(orchestrator.run(session.ctx, module_ids))
    except KeyboardInterrupt:
        err.write("interrupted\n")
        session.repo.finish_scan(session.ctx.scan_id, "interrupted")
        session.close()
        return EXIT_FAILED
    session.repo.finish_scan(session.ctx.scan_id, outcome.status)

    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    args.out.mkdir(parents=True, exist_ok=True)
    if "json" in formats:
        path = write_json_report(args.out, session.ctx.scan_id, config, outcome)
        out.write(f"{path}\n")
    session.close()

    if outcome.status == "failed":
        return EXIT_FAILED
    if args.fail_on is not None:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in outcome.findings):
            return EXIT_FAIL_ON
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
        case "tools":
            return _cmd_tools_list(sys.stdout)
        case "modules":
            return _cmd_modules(args.profile, sys.stdout)
        case "scan":
            return _cmd_scan(args, sys.stdout, sys.stderr)
        case "worker":
            from secscope.worker.main import main as worker_main  # noqa: PLC0415

            return worker_main()
        case _:
            parser.print_help()
            return EXIT_OK
