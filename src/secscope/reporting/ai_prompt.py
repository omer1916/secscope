"""Export findings as one Markdown prompt to paste into an AI assistant so it fixes them.

Each finding carries what it is, where (file:line or endpoint), the offending code (secrets
already masked), why it matters, and the suggested fix with code for the project's stack. The
document starts with a short instruction so the assistant knows to apply the fixes in the repo.
"""

from __future__ import annotations

from typing import Any

from secscope.analysis.kb import STACK_GROUP
from secscope.core.jsonutil import jdict
from secscope.core.models import CodeLocation, Finding, Language
from secscope.reporting.json_export import report_findings
from secscope.ui.i18n import Translator

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Order in which a stack-specific fix snippet is chosen when several are offered.
SNIPPET_ORDER = (
    "express", "flask", "django", "fastapi", "php", "laravel", "nginx", "apache",
    "static", "python", "javascript", "github",
)  # fmt: skip
FENCE_BY_SUFFIX = {
    ".py": "python", ".js": "js", ".jsx": "js", ".ts": "ts", ".tsx": "ts", ".php": "php",
    ".html": "html", ".htm": "html", ".vue": "html", ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".sql": "sql", ".sh": "bash", ".rb": "ruby", ".go": "go",
}  # fmt: skip


def _fence(finding: Finding) -> str:
    loc = finding.location
    if isinstance(loc, CodeLocation):
        for suffix, fence in FENCE_BY_SUFFIX.items():
            if loc.path.lower().endswith(suffix):
                return fence
    return ""


def _header(report: dict[str, Any], t: Translator, counts: dict[str, int]) -> list[str]:
    stack = jdict(report.get("stack"))
    stack_name = stack.get("name")
    summary = ", ".join(f"{n} {t(f'report.sev.{sev}')}" for sev, n in counts.items() if n)
    return [
        f"# {t('ai.title')}",
        "",
        t("ai.intro"),
        "",
        f"- {t('ai.stack')}: {stack_name or '-'}",
        f"- {t('ai.summary')}: {summary or '0'}",
        "",
        t("ai.rules"),
        "",
        "---",
        "",
    ]


def _snippet_for(finding: Finding, stack_family: str | None) -> tuple[str, str] | None:
    snippets = finding.remediation.snippets if finding.remediation else {}
    if not snippets:
        return None
    group = STACK_GROUP.get(stack_family or "", ())
    order = ([stack_family] if stack_family else []) + list(group) + list(SNIPPET_ORDER)
    for key in order:
        if key in snippets:
            return snippets[key].lang, snippets[key].code
    first = next(iter(snippets.values()))
    return first.lang, first.code


def _finding_block(
    finding: Finding, t: Translator, lang: Language, stack_family: str | None
) -> list[str]:
    loc = finding.location
    where = loc.display()
    sev = t(f"report.sev.{finding.severity}")
    out = [
        f"### [{sev}] {finding.rule_id} — {where}",
        "",
        f"**{t('ai.what')}:** {finding.title.get(lang)}",
    ]
    refs = ", ".join(
        f"CWE-{r.id}" if r.type == "cwe" else (r.id or "")
        for r in finding.references
        if r.type in {"cwe", "owasp"} and r.id
    )
    if refs:
        out.append(f"**{t('ai.refs')}:** {refs}")
    if finding.evidence.snippet:
        out += [
            "",
            f"**{t('ai.evidence')}:**",
            f"```{_fence(finding)}",
            finding.evidence.snippet,
            "```",
        ]
    if finding.description:
        out += ["", f"**{t('ai.why')}:** {finding.description.get(lang)}"]
    if finding.remediation and finding.remediation.steps.get(lang):
        out += ["", f"**{t('ai.fix')}:**"]
        out += [f"{i}. {step}" for i, step in enumerate(finding.remediation.steps.get(lang), 1)]
    snippet = _snippet_for(finding, stack_family)
    if snippet is not None:
        out += ["", f"```{snippet[0]}", snippet[1], "```"]
    out.append("")
    return out


def render_ai_prompt(report: dict[str, Any], *, lang: Language | None = None) -> str:
    language: Language = lang or report.get("language") or "tr"  # type: ignore[assignment]
    t = Translator(language)
    findings = sorted(
        report_findings(report),
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            not isinstance(f.location, CodeLocation),
            f.location.display(),
        ),
    )
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    stack_family = jdict(report.get("stack")).get("family")

    detailed = [f for f in findings if f.severity != "info"]
    info = [f for f in findings if f.severity == "info"]

    lines = _header(report, t, counts)
    if not detailed and not info:
        lines.append(t("ai.clean"))
        return "\n".join(lines) + "\n"
    for finding in detailed:
        lines += _finding_block(finding, t, language, stack_family)
    if info:
        lines += [f"## {t('ai.info_heading')}", ""]
        lines += [f"- {f.rule_id} — {f.location.display()}: {f.title.get(language)}" for f in info]
        lines.append("")
    return "\n".join(lines) + "\n"
