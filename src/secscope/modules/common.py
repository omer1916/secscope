"""Helpers shared by the static-analysis modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secscope.analysis.kb import KnowledgeBase
from secscope.core.models import CodeLocation, Confidence, Evidence, Finding, Severity
from secscope.core.resources import data_path
from secscope.modules.base import ScanContext


def project_root(ctx: ScanContext) -> Path:
    assert ctx.source_dir is not None, "needs_source modules always have a source dir"
    return ctx.source_dir


def stack_of(ctx: ScanContext) -> str | None:
    return ctx.fingerprint.stack_family if ctx.fingerprint else None


def code_finding(
    kb: KnowledgeBase,
    rule_id: str,
    *,
    module: str,
    path: str,
    line: int | None,
    column: int | None = None,
    snippet: str | None = None,
    confidence: Confidence | None = None,
    severity: Severity | None = None,
    tool: str = "native",
    stack: str | None = None,
    notes: str | None = None,
    extra: dict[str, str] | None = None,
) -> Finding:
    return kb.finding(
        rule_id,
        module=module,
        location=CodeLocation(path=path, line=line, column=column),
        evidence=Evidence(snippet=snippet, notes=notes, extra=extra or {}),
        source_tool=tool,
        severity=severity,
        confidence=confidence,
        stack=stack,
    )


@dataclass
class ToolMap:
    """External rule id -> (SecScope rule id, confidence override); None = ignore."""

    mapping: dict[str, dict[str, tuple[str, Confidence | None] | None]] = field(
        default_factory=dict[str, dict[str, tuple[str, Confidence | None] | None]]
    )

    @classmethod
    def load(cls, path: Path | None = None) -> ToolMap:
        raw: dict[str, dict[str, Any]] = yaml.safe_load(
            (path or data_path("rules") / "tool_map.yaml").read_text(encoding="utf-8")
        )
        mapping: dict[str, dict[str, tuple[str, Confidence | None] | None]] = {}
        for tool, entries in raw.items():
            mapping[tool] = {
                key: (value["rule"], value.get("confidence")) if value else None
                for key, value in entries.items()
            }
        return cls(mapping)

    def lookup(self, tool: str, external_id: str) -> tuple[str, Confidence | None] | None:
        return self.mapping.get(tool, {}).get(external_id)

    def known(self, tool: str, external_id: str) -> bool:
        return external_id in self.mapping.get(tool, {})


def read_line(root: Path, rel: str, line: int) -> str:
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""
