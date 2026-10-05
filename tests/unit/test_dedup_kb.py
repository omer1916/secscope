from __future__ import annotations

import re
from pathlib import Path

import pytest

from secscope.analysis.kb import KnowledgeBase, default_kb
from secscope.core.dedup import deduplicate
from secscope.core.models import CodeLocation, Evidence, Finding, HttpLocation

SRC = Path(__file__).resolve().parents[2] / "src" / "secscope"
RULE_LITERAL = re.compile(
    r"\b(?:SAST|SECRET|CONF|SCA|QUAL|SEC|SEO|PERF|RES|A11Y)-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}\b"
)
OWASP_2025 = {f"A{n:02d}:2025" for n in range(1, 11)}


def f(
    rule: str,
    line: int | None,
    tool: str = "native",
    *,
    path: str = "app.py",
    conf: str = "medium",
    sev: str = "medium",
    snippet: str = "x",
) -> Finding:
    return default_kb().finding(
        rule, module="sast", location=CodeLocation(path=path, line=line), evidence=Evidence(snippet=snippet),
        source_tool=tool, confidence=conf, severity=sev,  # type: ignore[arg-type]
    )  # fmt: skip


# -------------------------------------------------------------------- dedup


def test_same_issue_from_three_tools_merges_and_raises_confidence() -> None:
    merged = deduplicate(
        [
            f("SAST-SQLI-001", 77, "native"),
            f("SAST-SQLI-001", 78, "semgrep", snippet="y"),
            f("SAST-SQLI-001", 78, "bandit", snippet="z"),
        ]
    )
    assert len(merged) == 1
    assert merged[0].source_tools == ["native", "semgrep", "bandit"]
    assert merged[0].confidence == "high"
    assert merged[0].evidence.snippet == "x"  # native representative keeps the id stable


def test_far_apart_lines_stay_separate() -> None:
    assert len(deduplicate([f("SAST-SQLI-001", 10), f("SAST-SQLI-001", 40)])) == 2


def test_no_chaining_across_a_long_run() -> None:
    merged = deduplicate([f("SAST-XSS-001", n, snippet=str(n)) for n in (1, 3, 5, 7)])
    assert len(merged) == 2


def test_secrets_on_neighbouring_lines_are_distinct() -> None:
    merged = deduplicate(
        [
            f("SECRET-CLOUD-001", 2, path="config.py"),
            f("SECRET-DBURL-001", 3, path="config.py", snippet="y"),
        ]
    )
    assert len(merged) == 2


def test_family_merge_keeps_most_specific_rule() -> None:
    merged = deduplicate(
        [
            f("SECRET-GENERIC-001", 3, path="c.py"),
            f("SAST-HARDCODED-001", 3, "bandit", path="c.py", snippet="y"),
            f("SECRET-CLOUD-001", 3, path="c.py", snippet="z"),
        ]
    )
    assert len(merged) == 1
    assert merged[0].rule_id == "SECRET-CLOUD-001"
    assert merged[0].evidence.extra["related_rules"] == "SAST-HARDCODED-001, SECRET-GENERIC-001"


def test_sca_packages_never_merge() -> None:
    a = f("SCA-VULN-001", None, "trivy", path="requirements.txt", snippet="flask@2.2.2")
    b = f("SCA-VULN-001", None, "trivy", path="requirements.txt", snippet="werkzeug@2.2.3")
    assert len(deduplicate([a, b])) == 2


def test_http_findings_merge_on_path_and_parameter() -> None:
    kb = default_kb()
    x = kb.finding(
        "SAST-XSS-001",
        module="dast",
        location=HttpLocation(url="http://localhost/s?q=1", parameter="q"),
        source_tool="native",
    )
    y = kb.finding(
        "SAST-XSS-001",
        module="dast",
        location=HttpLocation(url="http://localhost/s?q=2", parameter="q"),
        source_tool="zap",
        evidence=Evidence(snippet="z"),
    )
    merged = deduplicate([x, y])
    assert len(merged) == 1
    assert merged[0].source_tools == ["native", "zap"]


def test_dedup_is_idempotent_and_sorted_by_severity() -> None:
    items = [f("QUAL-EXCEPT-001", 1, sev="low"), f("SAST-CMDI-001", 5, sev="critical", snippet="c")]
    once = deduplicate(items)
    assert [x.severity for x in once] == ["critical", "low"]
    assert deduplicate(once) == once


# ----------------------------------------------------------------------- KB


def test_kb_entries_are_complete_and_bilingual() -> None:
    kb = default_kb()
    for rule_id, e in kb.entries.items():
        assert e.title.tr, rule_id
        assert e.title.en, rule_id
        assert e.why.tr, rule_id
        assert e.why.en, rule_id
        assert e.fix_steps.tr, rule_id
        assert e.fix_steps.en, rule_id
        assert len(e.fix_steps.tr) == len(e.fix_steps.en), rule_id
        assert set(e.owasp) <= OWASP_2025, rule_id
        assert all(re.fullmatch(r"5\.0-V\d{1,2}", a) for a in e.asvs), rule_id
        if e.category.value == "security" and not rule_id.startswith("SCA-LICENSE"):
            assert e.cwe, f"{rule_id} has no CWE reference"


def test_every_rule_id_in_source_and_rules_has_a_kb_entry() -> None:
    kb = default_kb()
    used: set[str] = set()
    for path in [*SRC.rglob("*.py"), *(SRC.parents[1] / "rules").rglob("*.yaml")]:
        used |= set(RULE_LITERAL.findall(path.read_text(encoding="utf-8")))
    used -= {"SEC-HDR-001"}  # example id in docstrings/spec; real once DAST lands
    missing = sorted(r for r in used if r not in kb)
    assert missing == [], f"rules without remediation/<id>.yaml: {missing}"


def test_kb_file_name_must_match(tmp_path: Path) -> None:
    src = Path(__file__).resolve().parents[2] / "remediation" / "SAST-SQLI-001.yaml"
    (tmp_path / "WRONG-NAME-001.yaml").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        KnowledgeBase.load(tmp_path)


def test_remediation_puts_detected_stack_first() -> None:
    entry = default_kb().get("SAST-SQLI-001")
    assert next(iter(entry.remediation("php").snippets)) == "php"
    assert next(iter(entry.remediation("express").snippets)) == "express"


def test_finding_from_kb_is_enriched() -> None:
    finding = f("SAST-SQLI-001", 3)
    assert finding.title.en.startswith("SQL query")
    assert finding.cwe == [89]
    assert finding.owasp == ["A05:2025"]
    assert finding.remediation is not None
