"""Merge duplicate findings from different tools/modules (SPEC §5 rules).

Two findings are the same issue when they share a rule *family* and a location:
code findings in the same file within ±2 lines, HTTP findings on the same method, path
and parameter. The merged finding keeps the representative's id (preferring the native
engine so ids stay stable when optional tools come and go), the union of
``source_tools``, the highest severity, and a confidence raised one step when at least
two independent tools agree (never to ``confirmed`` — that requires a live proof).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from secscope.core.models import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    CodeLocation,
    Confidence,
    Finding,
    HttpLocation,
    max_severity,
)

LINE_TOLERANCE = 2
TOOL_PREFERENCE = (
    "native",
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "osv-scanner",
    "zap",
    "nuclei",
)
_CONF_BY_RANK: dict[int, Confidence] = {v: k for k, v in CONFIDENCE_ORDER.items()}

# Rules that describe the same underlying issue from different angles; the first listed
# rule present in a group becomes the representative.
FAMILIES: tuple[tuple[str, ...], ...] = (
    (
        "SECRET-CLOUD-001",
        "SECRET-TOKEN-001",
        "SECRET-PRIVKEY-001",
        "SECRET-DBURL-001",
        "SAST-JWT-001",
        "SAST-HARDCODED-001",
        "SECRET-JWT-001",
        "SECRET-GENERIC-001",
    ),
    ("SAST-XSS-004", "SAST-XSS-003"),
)
_FAMILY_OF: dict[str, tuple[str, ...]] = {rule: fam for fam in FAMILIES for rule in fam}


def _family(rule_id: str) -> tuple[str, ...]:
    return _FAMILY_OF.get(rule_id, (rule_id,))


def _tool_rank(finding: Finding) -> int:
    tool = finding.source_tools[0]
    return TOOL_PREFERENCE.index(tool) if tool in TOOL_PREFERENCE else len(TOOL_PREFERENCE)


def _representative(group: list[Finding]) -> Finding:
    family = _family(group[0].rule_id)
    return min(
        group,
        key=lambda f: (family.index(f.rule_id) if f.rule_id in family else 99, _tool_rank(f), f.id),
    )


def _bucket_key(f: Finding) -> tuple[str, ...]:
    fam = _family(f.rule_id)[0]
    loc = f.location
    if isinstance(loc, CodeLocation):
        if f.rule_id.startswith("SCA-"):
            # One finding per package: never merge different packages of one manifest.
            return (fam, "code", loc.path, f.evidence.normalized())
        return (fam, "code", loc.path)
    assert isinstance(loc, HttpLocation)
    path = loc.url.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
    return (fam, "http", loc.method, path, loc.parameter or "")


def merge(group: list[Finding]) -> Finding:
    rep = _representative(group)
    if len(group) == 1:
        return rep
    tools = sorted(
        {t for f in group for t in f.source_tools},
        key=lambda t: TOOL_PREFERENCE.index(t) if t in TOOL_PREFERENCE else 99,
    )
    severity = max_severity([f.severity for f in group])
    rank = max(CONFIDENCE_ORDER[f.confidence] for f in group)
    if len(tools) >= 2 and rank < CONFIDENCE_ORDER["high"]:
        rank += 1
    if rep.confidence == "confirmed":
        rank = CONFIDENCE_ORDER["confirmed"]
    also = sorted({f.rule_id for f in group} - {rep.rule_id})
    extra = dict(rep.evidence.extra)
    if also:
        extra["related_rules"] = ", ".join(also)
    evidence = (
        rep.evidence
        if rep.evidence.snippet
        else next((f.evidence for f in group if f.evidence.snippet), rep.evidence)
    )
    evidence = evidence.model_copy(update={"extra": extra})
    return rep.model_copy(
        update={
            "source_tools": tools,
            "severity": severity,
            "confidence": _CONF_BY_RANK[rank],
            "evidence": evidence,
            "cwe": sorted({c for f in group for c in f.cwe}),
        }
    )


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    buckets: dict[tuple[str, ...], list[Finding]] = {}
    for f in findings:
        buckets.setdefault(_bucket_key(f), []).append(f)
    merged: list[Finding] = []
    for items in buckets.values():
        if isinstance(items[0].location, HttpLocation):
            merged.append(merge(items))
            continue
        # Cluster code findings within the tolerance of the cluster's *first* line (no chaining).
        # Secrets on neighbouring lines are different credentials: tolerance 0 for them.
        # Line drift between tools only matters for code-pattern rules.
        code_rule = (
            items[0].rule_id.startswith(("SAST-", "QUAL-")) and items[0].rule_id not in _FAMILY_OF
        )
        tolerance = LINE_TOLERANCE if code_rule else 0
        items.sort(
            key=lambda f: (f.location.line or 0) if isinstance(f.location, CodeLocation) else 0
        )
        cluster: list[Finding] = []
        first_line: int | None = None
        for f in items:
            line = f.location.line if isinstance(f.location, CodeLocation) else None
            same = (line is None and first_line is None) or (
                line is not None and first_line is not None and line - first_line <= tolerance
            )
            if cluster and not same:
                merged.append(merge(cluster))
                cluster = []
            if not cluster:
                first_line = line
            cluster.append(f)
        if cluster:
            merged.append(merge(cluster))
    # Identical code at two places of one file yields the same fingerprint (line numbers are
    # not part of it, ADR-002). Keep both: later occurrences get "#2", "#3"... in line order,
    # which stays stable across scans as long as the code above does not gain a copy.
    by_id: dict[str, list[Finding]] = {}
    for f in merged:
        by_id.setdefault(f.id, []).append(f)
    unique: list[Finding] = []
    for same in by_id.values():
        same.sort(
            key=lambda f: (f.location.line or 0) if isinstance(f.location, CodeLocation) else 0
        )
        unique.append(same[0])
        for n, f in enumerate(same[1:], start=2):
            new_id = hashlib.sha256(f"{f.id}#{n}".encode()).hexdigest()
            unique.append(f.model_copy(update={"id": new_id}))
    return sorted(unique, key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.id))
