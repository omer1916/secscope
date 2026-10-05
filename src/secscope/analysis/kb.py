"""Remediation knowledge base (SPEC §10): ``remediation/<rule_id>.yaml``.

The KB is the single catalogue of rules: every ``rule_id`` a module emits must
have an entry (enforced by ``tests/unit/test_kb.py``). Modules create findings
through :meth:`KnowledgeBase.finding`, which fills title, severity, category,
description, impact, remediation, references and CWE/OWASP/ASVS from the entry.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from secscope.core.models import (
    Category,
    CodeLocation,
    CodeSnippet,
    Confidence,
    Effort,
    Evidence,
    Finding,
    HttpLocation,
    LocalizedList,
    LocalizedStr,
    Ref,
    Remediation,
    Severity,
)
from secscope.core.resources import data_path

# Order in which stack-specific snippets are offered when the stack is unknown.
DEFAULT_STACK_ORDER = (
    "express",
    "flask",
    "django",
    "php",
    "nginx",
    "apache",
    "static",
    "python",
    "javascript",
)


class KBEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    title: LocalizedStr
    severity: Severity
    category: Category = Category.SECURITY
    confidence: Confidence = "medium"
    why: LocalizedStr
    impact: LocalizedStr | None = None
    fix_steps: LocalizedList
    snippets: dict[str, CodeSnippet] = Field(default_factory=dict[str, CodeSnippet])
    verify: LocalizedStr | None = None
    references: list[Ref] = Field(default_factory=list[Ref])
    effort: Effort = "M"

    @field_validator("snippets", mode="before")
    @classmethod
    def _snippets(cls, v: Any) -> Any:
        return v or {}

    @property
    def cwe(self) -> list[int]:
        return [int(r.id) for r in self.references if r.type == "cwe" and r.id and r.id.isdigit()]

    @property
    def owasp(self) -> list[str]:
        return [r.id for r in self.references if r.type == "owasp" and r.id]

    @property
    def asvs(self) -> list[str]:
        return [r.id for r in self.references if r.type == "asvs" and r.id]

    def remediation(self, stack: str | None = None) -> Remediation:
        """Remediation with the detected stack's snippet first (SPEC §10)."""
        order = [stack] if stack else []
        order += [s for s in DEFAULT_STACK_ORDER if s not in order]
        ordered = {k: self.snippets[k] for k in order if k in self.snippets}
        ordered.update({k: v for k, v in self.snippets.items() if k not in ordered})
        return Remediation(steps=self.fix_steps, snippets=ordered, verify=self.verify)


class UnknownRuleError(KeyError):
    pass


class KnowledgeBase:
    def __init__(self, entries: dict[str, KBEntry]) -> None:
        self.entries = entries

    @classmethod
    def load(cls, directory: Path | None = None) -> KnowledgeBase:
        directory = directory or data_path("remediation")
        entries: dict[str, KBEntry] = {}
        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            entry = KBEntry.model_validate(raw)
            if entry.rule_id != path.stem:
                raise ValueError(f"{path.name}: rule_id {entry.rule_id!r} does not match file name")
            entries[entry.rule_id] = entry
        return cls(entries)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self.entries

    def get(self, rule_id: str) -> KBEntry:
        try:
            return self.entries[rule_id]
        except KeyError:
            raise UnknownRuleError(f"no remediation/{rule_id}.yaml") from None

    def finding(
        self,
        rule_id: str,
        *,
        module: str,
        location: CodeLocation | HttpLocation,
        evidence: Evidence | None = None,
        source_tool: str = "native",
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        stack: str | None = None,
        title: LocalizedStr | None = None,
        extra_refs: list[Ref] | None = None,
        description: LocalizedStr | None = None,
    ) -> Finding:
        entry = self.get(rule_id)
        refs = [*entry.references, *(extra_refs or [])]
        return Finding(
            rule_id=rule_id,
            module=module,
            category=entry.category,
            title=title or entry.title,
            severity=severity or entry.severity,
            confidence=confidence or entry.confidence,
            location=location,
            evidence=evidence or Evidence(),
            description=description or entry.why,
            impact=entry.impact,
            remediation=entry.remediation(stack),
            references=refs,
            cwe=entry.cwe,
            owasp=entry.owasp,
            asvs=entry.asvs,
            effort=entry.effort,
            source_tools=[source_tool],
        )


@cache
def default_kb() -> KnowledgeBase:
    return KnowledgeBase.load()
