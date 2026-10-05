"""Command line entry point (headless mode, SPEC §11.3)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from secscope.__about__ import __app_id__, __app_name__, __version__


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


SCHEMA_KINDS = ("finding", "event", "command", "settings", "scan-config")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__app_id__,
        description=f"{__app_name__}: local-only security, SEO and resilience testing.",
    )
    parser.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    schema = sub.add_parser("schema", help="print the JSON schema of a data model")
    schema.add_argument("kind", choices=SCHEMA_KINDS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "schema":
        json.dump(_schema(args.kind), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    parser.print_help()
    return 0
