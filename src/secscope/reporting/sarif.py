"""SARIF 2.1.0 export for IDEs and CI code scanning (SPEC §11.1)."""

from __future__ import annotations

from typing import Any

from secscope.__about__ import __app_name__, __version__
from secscope.core.models import Finding, Language

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning reads properties.security-severity (CVSS-like, 0-10).
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _rule(f: Finding, lang: Language) -> dict[str, Any]:
    help_uri = next((r.href for r in f.references if r.href), None)
    tags = [f.category.value, *[f"CWE-{c}" for c in f.cwe], *f.owasp]
    rule: dict[str, Any] = {
        "id": f.rule_id,
        "name": f.rule_id.replace("-", ""),
        "shortDescription": {"text": f.title.get(lang)},
        "fullDescription": {
            "text": (f.description.get(lang) if f.description else f.title.get(lang))
        },
        "defaultConfiguration": {"level": LEVEL[f.severity]},
        "properties": {
            "tags": tags,
            "security-severity": SECURITY_SEVERITY[f.severity],
            "precision": _precision(f),
        },
    }
    if f.remediation and f.remediation.steps.get(lang):
        rule["help"] = {"text": "\n".join(f.remediation.steps.get(lang))}
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _precision(f: Finding) -> str:
    return {"confirmed": "very-high", "high": "high", "medium": "medium", "low": "low"}[
        f.confidence
    ]


def _location(f: Finding) -> dict[str, Any]:
    loc = f.location
    if loc.kind == "code":
        region: dict[str, Any] = {}
        if loc.line:
            region["startLine"] = loc.line
            if loc.column:
                region["startColumn"] = loc.column
        if f.evidence.snippet:
            region["snippet"] = {"text": f.evidence.snippet}
        physical: dict[str, Any] = {"artifactLocation": {"uri": loc.path, "uriBaseId": "SRCROOT"}}
        if region:
            physical["region"] = region
        return {"physicalLocation": physical}
    name = f"{loc.method} {loc.url}" + (f" [{loc.parameter}]" if loc.parameter else "")
    return {"logicalLocations": [{"name": name, "kind": "resource"}]}


def to_sarif(findings: list[Finding], *, lang: Language = "en") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = _rule(f, lang)
        message = f.title.get(lang)
        if f.evidence.snippet and f.location.kind == "http":
            message += f" — {f.evidence.snippet}"
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": list(rules).index(f.rule_id),
                "level": LEVEL[f.severity],
                "message": {"text": message},
                "locations": [_location(f)],
                "partialFingerprints": {"secscopeFindingId/v1": f.id},
                "properties": {
                    "confidence": f.confidence,
                    "module": f.module,
                    "sourceTools": f.source_tools,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": __app_name__,
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"description": {"text": "Scanned project root"}}
                },
                "results": results,
            }
        ],
    }
