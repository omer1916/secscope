"""Multi-language pattern rules (``rules/native/*.yaml``) — the always-available SAST baseline.

Rule format::

    - id: SAST-SQLI-001            # remediation/<id>.yaml must exist
      languages: [javascript, php]
      pattern: '...'               # Python regex, searched with MULTILINE
      not_pattern: '...'           # optional: skip if the matched *line* matches this
      file_pattern: '...'          # optional: only files whose relative path matches
      severity: high               # optional override of the KB default
      confidence: medium           # optional override

A line containing ``secscope: ignore`` (optionally followed by rule ids) is suppressed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secscope.analysis.source import SourceFile
from secscope.core.models import Confidence, Severity
from secscope.core.resources import data_path

_IGNORE = re.compile(r"secscope:\s*ignore(?P<ids>(?:[\s,]+[A-Z][A-Z0-9-]+)*)")


@dataclass(frozen=True, slots=True)
class PatternRule:
    id: str
    languages: frozenset[str]
    pattern: re.Pattern[str]
    not_pattern: re.Pattern[str] | None = None
    file_pattern: re.Pattern[str] | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None


@dataclass(frozen=True, slots=True)
class Match:
    rule: PatternRule
    file: SourceFile
    line: int
    column: int
    snippet: str


def load_rules(directory: Path | None = None) -> list[PatternRule]:
    directory = directory or data_path("rules") / "native"
    rules: list[PatternRule] = []
    for path in sorted(directory.glob("*.yaml")):
        raw: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for item in raw:
            try:
                rules.append(
                    PatternRule(
                        id=item["id"],
                        languages=frozenset(item["languages"]),
                        pattern=re.compile(item["pattern"], re.MULTILINE),
                        not_pattern=re.compile(item["not_pattern"])
                        if item.get("not_pattern")
                        else None,
                        file_pattern=re.compile(item["file_pattern"])
                        if item.get("file_pattern")
                        else None,
                        severity=item.get("severity"),
                        confidence=item.get("confidence"),
                    )
                )
            except (KeyError, re.error) as exc:
                raise ValueError(f"{path.name}: bad rule {item.get('id')!r}: {exc}") from exc
    return rules


def suppressed(line_text: str, rule_id: str) -> bool:
    m = _IGNORE.search(line_text)
    if m is None:
        return False
    ids = re.findall(r"[A-Z][A-Z0-9-]+", m.group("ids"))
    return not ids or rule_id in ids


def scan_file(file: SourceFile, rules: Iterable[PatternRule]) -> Iterator[Match]:
    if file.language is None or file.minified:
        return
    seen: set[tuple[str, int]] = set()
    for rule in rules:
        if file.language not in rule.languages:
            continue
        if rule.file_pattern is not None and not rule.file_pattern.search(file.rel):
            continue
        for m in rule.pattern.finditer(file.text):
            line = file.line_of(m.start())
            if (rule.id, line) in seen:
                continue
            text = file.line_text(line)
            if rule.not_pattern is not None and rule.not_pattern.search(text):
                continue
            if suppressed(text, rule.id):
                continue
            seen.add((rule.id, line))
            line_start = file.text.rfind("\n", 0, m.start()) + 1
            yield Match(rule, file, line, m.start() - line_start + 1, text.strip())
