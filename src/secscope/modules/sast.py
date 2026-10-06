"""SAST module (SPEC §6.2): native rules always; Semgrep and Bandit when available.

Without Semgrep the native engine still runs and the module notes "reduced coverage".
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, ClassVar

from secscope.analysis.kb import KnowledgeBase, default_kb
from secscope.analysis.python_checks import check_python
from secscope.analysis.regex_rules import PatternRule, load_rules, scan_file
from secscope.analysis.source import SourceFile, iter_project
from secscope.core.models import Category, Confidence, Finding, LocalizedStr
from secscope.core.process import python_tool_command, run_capture
from secscope.core.resources import data_path
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext
from secscope.modules.common import (
    ToolMap,
    code_finding,
    project_root,
    read_statement,
    stack_of,
    statement_text,
)

SEMGREP_TIMEOUT_S = 15 * 60
BANDIT_TIMEOUT_S = 10 * 60
_BANDIT_CONF: dict[str, Confidence] = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def native_findings(
    root: Path, kb: KnowledgeBase, rules: list[PatternRule], stack: str | None
) -> list[Finding]:
    findings: list[Finding] = []
    for file in iter_project(root):
        findings += _file_findings(file, kb, rules, stack)
    return findings


def _file_findings(
    file: SourceFile, kb: KnowledgeBase, rules: list[PatternRule], stack: str | None
) -> list[Finding]:
    out: list[Finding] = []
    for m in scan_file(file, rules):
        out.append(
            code_finding(kb, m.rule.id, module="sast", path=file.rel, line=m.line, column=m.column,
                         snippet=m.snippet, confidence=m.rule.confidence, severity=m.rule.severity, stack=stack)
        )  # fmt: skip
    if file.language == "python":
        for issue in check_python(file):
            out.append(
                code_finding(kb, issue.rule_id, module="sast", path=file.rel, line=issue.line, column=issue.column,
                             snippet=statement_text(file.text.splitlines(), issue.line, issue.end_line), confidence=issue.confidence,
                             severity=issue.severity, stack=stack, notes=issue.note or None)
            )  # fmt: skip
    return out


def parse_semgrep(output: str, root: Path, kb: KnowledgeBase, stack: str | None) -> list[Finding]:
    data: dict[str, Any] = json.loads(output)
    findings: list[Finding] = []
    for r in data.get("results", []):
        meta: dict[str, Any] = r.get("extra", {}).get("metadata", {}) or {}
        rule_id = meta.get("secscope_rule")
        if not rule_id or rule_id not in kb:
            continue
        rel = Path(r["path"]).resolve().relative_to(root.resolve()).as_posix()
        line = int(r["start"]["line"])
        end = int(r.get("end", {}).get("line", line))
        findings.append(
            code_finding(kb, rule_id, module="sast", path=rel, line=line, column=int(r["start"].get("col", 1)),
                         snippet=read_statement(root, rel, line, end), confidence=meta.get("confidence"),
                         tool="semgrep", stack=stack, extra={"semgrep_rule": r["check_id"]})
        )  # fmt: skip
    return findings


def parse_bandit(
    output: str, root: Path, kb: KnowledgeBase, tool_map: ToolMap, stack: str | None
) -> tuple[list[Finding], set[str]]:
    data: dict[str, Any] = json.loads(output)
    findings: list[Finding] = []
    unmapped: set[str] = set()
    for r in data.get("results", []):
        test_id = r["test_id"]
        mapped = tool_map.lookup("bandit", test_id)
        if mapped is None:
            if not tool_map.known("bandit", test_id):
                unmapped.add(test_id)
            continue
        rule_id, conf = mapped
        path = Path(r["filename"])
        rel = (
            (path if path.is_absolute() else root / path)
            .resolve()
            .relative_to(root.resolve())
            .as_posix()
        )
        line = int(r["line_number"])
        findings.append(
            code_finding(kb, rule_id, module="sast", path=rel, line=line, column=int(r.get("col_offset", 0)) + 1,
                         snippet=read_statement(root, rel, line, max(r.get("line_range") or [line])), confidence=conf or _BANDIT_CONF.get(r.get("issue_confidence", ""), "medium"),
                         tool="bandit", stack=stack, extra={"bandit_test": test_id})
        )  # fmt: skip
    return findings, unmapped


class SastModule(BaseModule):
    id: ClassVar[str] = "sast"
    title: ClassVar[LocalizedStr] = LocalizedStr(
        tr="Statik kod analizi (SAST)", en="Static code analysis (SAST)"
    )
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(needs_source=True)
    timeout_s: ClassVar[float] = 30 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        root = project_root(ctx)
        kb = default_kb()
        stack = stack_of(ctx)
        result = ModuleResult()

        emit.progress(5, "native rules")
        native = await asyncio.to_thread(native_findings, root, kb, load_rules(), stack)
        for f in native:
            emit.finding(f)
        await ctx.checkpoint()

        semgrep = ctx.tools.status("semgrep")
        if semgrep.available and semgrep.path is not None:
            emit.progress(30, "semgrep")
            argv = [str(semgrep.path), "scan", "--config", str(data_path("rules") / "semgrep"), "--json",
                    "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--no-git-ignore",
                    "--quiet", "--timeout", "30", "--jobs", str(max(1, (os.cpu_count() or 2) - 1)), str(root)]  # fmt: skip
            run = await run_capture(argv, cwd=root, timeout=SEMGREP_TIMEOUT_S, env=_tool_env())
            if run.returncode >= 2 and not run.stdout.strip().startswith("{"):
                emit.log(f"semgrep failed (exit {run.returncode}): {run.stderr[-500:]}", "warning")
                result.notes.append("semgrep-failed")
            else:
                for f in parse_semgrep(run.stdout, root, kb, stack):
                    emit.finding(f)
        else:
            result.notes.append("reduced-coverage: semgrep not available, native rules only")
            emit.log("Semgrep is not installed: reduced coverage (native rules only)", "warning")
        await ctx.checkpoint()

        emit.progress(70, "bandit")
        if any(root.rglob("*.py")):
            argv = [*python_tool_command("bandit"), "-r", str(root), "-f", "json", "-q",
                    "-x", ",".join(str(root / d) for d in ("node_modules", ".venv", "venv", "vendor"))]  # fmt: skip
            run = await run_capture(argv, cwd=root, timeout=BANDIT_TIMEOUT_S, env=_tool_env())
            if run.stdout.strip().startswith("{"):
                found, unmapped = parse_bandit(run.stdout, root, kb, ToolMap.load(), stack)
                for f in found:
                    emit.finding(f)
                if unmapped:
                    emit.log(
                        f"bandit tests without SecScope mapping (ignored): {', '.join(sorted(unmapped))}",
                        "debug",
                    )
            else:
                emit.log(f"bandit failed (exit {run.returncode}): {run.stderr[-500:]}", "warning")
        emit.progress(100)
        return result


def _tool_env() -> dict[str, str]:
    env = dict(os.environ)
    env["SEMGREP_SEND_METRICS"] = "off"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env
