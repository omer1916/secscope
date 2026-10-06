"""Secrets module (SPEC §6.2): native scanner + gitleaks (working tree and git history)."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, ClassVar

from secscope.analysis.kb import KnowledgeBase, default_kb
from secscope.analysis.secret_scan import is_env_file, scan_secrets
from secscope.analysis.source import iter_project
from secscope.core.intake import iter_source_files
from secscope.core.models import Category, CodeLocation, Finding, LocalizedStr
from secscope.core.process import run_capture
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext
from secscope.modules.common import code_finding, project_root, read_line, stack_of

GITLEAKS_TIMEOUT_S = 15 * 60


def gitleaks_rule(rule: str) -> str:
    rule = rule.lower()
    if rule.startswith(("aws-", "gcp-", "azure-", "alibaba-")):
        return "SECRET-CLOUD-001"
    if "private-key" in rule:
        return "SECRET-PRIVKEY-001"
    if rule == "jwt" or rule.startswith("jwt-"):
        return "SECRET-JWT-001"
    if rule == "generic-api-key":
        return "SECRET-GENERIC-001"
    return "SECRET-TOKEN-001"


def native_secret_findings(root: Path, kb: KnowledgeBase, stack: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for file in iter_project(root, include_text=True):
        for hit in scan_secrets(file):
            findings.append(
                code_finding(kb, hit.rule_id, module="secrets", path=file.rel, line=hit.line, column=hit.column,
                             snippet=file.line_text(hit.line).strip(), confidence=hit.confidence,
                             severity=hit.severity, stack=stack,
                             extra={"kind": hit.kind, **({"example_value": "yes"} if hit.example else {})})
            )  # fmt: skip
    for path in iter_source_files(root):
        rel = path.relative_to(root).as_posix()
        if is_env_file(rel):
            findings.append(
                code_finding(
                    kb, "SECRET-ENV-001", module="secrets", path=rel, line=None, stack=stack
                )
            )
    return findings


def parse_gitleaks(
    output: str, root: Path, kb: KnowledgeBase, stack: str | None, *, history: bool
) -> list[Finding]:
    items: list[dict[str, Any]] = json.loads(output or "[]") or []
    findings: list[Finding] = []
    for item in items:
        rel = Path(item["File"]).as_posix()
        if Path(rel).is_absolute():
            rel = Path(rel).resolve().relative_to(root.resolve()).as_posix()
        line = int(item.get("StartLine") or 1)
        rule_id = "SECRET-HISTORY-001" if history else gitleaks_rule(item["RuleID"])
        extra = {"gitleaks_rule": item["RuleID"]}
        if history:
            extra.update(
                {"commit": str(item.get("Commit", ""))[:12], "date": str(item.get("Date", ""))}
            )
        snippet = None if history else read_line(root, rel, line)
        findings.append(
            code_finding(kb, rule_id, module="secrets", path=rel, line=line, snippet=snippet, tool="gitleaks",
                         stack=stack, extra=extra, notes=item.get("Description"))
        )  # fmt: skip
    return findings


class SecretsModule(BaseModule):
    id: ClassVar[str] = "secrets"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Gizli anahtar taraması", en="Secret scanning")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(needs_source=True)
    timeout_s: ClassVar[float] = 20 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        root = project_root(ctx)
        kb = default_kb()
        stack = stack_of(ctx)
        result = ModuleResult()
        emit.progress(5, "native secret scanner")
        for f in await asyncio.to_thread(native_secret_findings, root, kb, stack):
            emit.finding(f)
        await ctx.checkpoint()

        status = ctx.tools.status("gitleaks")
        if not status.available or status.path is None:
            result.notes.append(
                "reduced-coverage: gitleaks not available (git history not scanned)"
            )
            emit.log("gitleaks is not installed: git history is not scanned", "warning")
            return result
        base = [str(status.path)]
        flags = [
            "--redact=100",
            "--no-banner",
            "-f",
            "json",
            "-r",
            "-",
            "--exit-code",
            "0",
            "-l",
            "error",
        ]
        emit.progress(40, "gitleaks (working tree)")
        run = await run_capture(
            [*base, "dir", str(root), *flags], cwd=root, timeout=GITLEAKS_TIMEOUT_S
        )
        current: list[Finding] = []
        if run.returncode == 0 and run.stdout.strip():
            current = parse_gitleaks(run.stdout, root, kb, stack, history=False)
            for f in current:
                emit.finding(f)
        elif run.returncode != 0:
            emit.log(f"gitleaks dir failed (exit {run.returncode}): {run.stderr[-300:]}", "warning")
        await ctx.checkpoint()

        if (root / ".git").exists() and shutil.which("git"):
            emit.progress(70, "gitleaks (git history)")
            run = await run_capture(
                [*base, "git", str(root), *flags], cwd=root, timeout=GITLEAKS_TIMEOUT_S
            )
            if run.returncode == 0 and run.stdout.strip():
                present = {
                    (f.location.path, f.evidence.extra.get("gitleaks_rule"))
                    for f in current
                    if isinstance(f.location, CodeLocation)
                }  # type: ignore[union-attr]
                raw: list[dict[str, Any]] = json.loads(run.stdout) or []
                past = [i for i in raw if (Path(i["File"]).as_posix(), i["RuleID"]) not in present]
                for f in parse_gitleaks(json.dumps(past), root, kb, stack, history=True):
                    emit.finding(f)
            elif run.returncode != 0:
                emit.log(
                    f"gitleaks git failed (exit {run.returncode}): {run.stderr[-300:]}", "warning"
                )
        emit.progress(100)
        return result
