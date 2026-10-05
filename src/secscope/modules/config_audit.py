"""Configuration / infrastructure audit (SPEC §6.2): Dockerfile, compose, nginx, .htaccess, CI,
.gitignore coverage, shipped source maps and backup files."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from secscope.analysis.config_checks import check_config
from secscope.analysis.kb import default_kb
from secscope.core.models import Category, LocalizedStr
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext
from secscope.modules.common import code_finding, project_root, stack_of


class ConfigAuditModule(BaseModule):
    id: ClassVar[str] = "config_audit"
    title: ClassVar[LocalizedStr] = LocalizedStr(
        tr="Yapılandırma denetimi", en="Configuration audit"
    )
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(needs_source=True)
    timeout_s: ClassVar[float] = 10 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        root = project_root(ctx)
        kb = default_kb()
        stack = stack_of(ctx)
        issues = await asyncio.to_thread(lambda: list(check_config(root)))
        for issue in issues:
            emit.finding(
                code_finding(kb, issue.rule_id, module="config_audit", path=issue.path, line=issue.line,
                             snippet=issue.snippet or issue.path, confidence=issue.confidence,
                             severity=issue.severity, stack=stack)
            )  # fmt: skip
        emit.progress(100)
        return ModuleResult()
