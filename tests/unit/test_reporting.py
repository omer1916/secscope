"""Report formats, report XSS safety, diff and fix plan (SPEC M8 acceptance)."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from secscope.analysis.kb import default_kb
from secscope.core.models import CodeLocation, Evidence, Finding, HttpLocation
from secscope.reporting.csv_export import to_csv
from secscope.reporting.diff import diff_reports
from secscope.reporting.html import FILTER_SCRIPT, render_html, script_hash
from secscope.reporting.json_export import REPORT_SCHEMA_VERSION
from secscope.reporting.plan import fix_plan
from secscope.reporting.sarif import to_sarif
from secscope.reporting.writer import ReportFormatError, write_outputs

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "golden" / "sarif-2.1.0.schema.json").read_text(
        encoding="utf-8"
    )
)
XSS = '<script>alert("pwn")</script><img src=x onerror=alert(1)>'


def code(rule: str, sev: str = "high", snippet: str = "x", line: int = 3) -> Finding:
    return default_kb().finding(
        rule, module="sast", location=CodeLocation(path="app.py", line=line), evidence=Evidence(snippet=snippet),
        severity=sev,  # type: ignore[arg-type]
    )  # fmt: skip


def http(rule: str, url: str, snippet: str) -> Finding:
    return default_kb().finding(
        rule, module="seo", location=HttpLocation(url=url), evidence=Evidence(snippet=snippet)
    )


def report(findings: list[Finding], **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "SecScope", "version": "0"},
        "scan_id": "s1",
        "generated_at": "2026-10-05T12:00:00+00:00",
        "language": "en",
        "target": {"kind": "folder", "value": "/p", "url": None},
        "stack": None,
        "profile": "standard",
        "scope_statement_accepted": True,
        "status": "completed",
        "duration_s": 1.0,
        "modules": {"sast": {"status": "ok", "duration_s": 1.0, "reason": None, "install_hint": None}},
        "notes": {},
        "tool_versions": {"semgrep": "1.179.0"},
        "scores": {"overall": 80.0, "grade": "B", "grade_capped": False, "security": 80.0, "seo": None,
                   "resilience": None, "quality": None, "dependencies": None, "effective_weights": {"security": 1.0}},
        "suppressed": 0,
        "fix_plan": [i.as_dict() for i in fix_plan(findings)],
        "seo": None,
        "sbom_path": None,
        "advisory_db": {},
        "findings": [f.model_dump(mode="json") for f in findings],
    }  # fmt: skip
    base.update(extra)
    return base


# ---------------------------------------------------------------------- HTML


def test_html_escapes_everything_from_the_target() -> None:
    hostile = http("SEO-TITLE-003", "http://127.0.0.1:8000/a?q=" + XSS, f"title is {XSS}")
    seo = {"score": {"score": 50.0, "subscores": {"on_page": 50.0}, "capped_by_index_blocker": False},
           "production_origin": None, "pages": [{"url": "http://127.0.0.1/", "status": 200, "title": XSS, "words": 3, "indexable": True, "depth": 0}],
           "generated": {"robots.txt": XSS}}  # fmt: skip
    html = render_html(
        report([hostile], seo=seo, target={"kind": "url", "value": XSS, "url": None})
    )
    assert "<script>alert" not in html
    assert "onerror=alert(1)>" not in html
    assert "&lt;script&gt;alert(&#34;pwn&#34;)&lt;/script&gt;" in html
    # The only <script> element is our own filter script.
    assert len(re.findall(r"<script\b", html)) == 1


def test_html_has_strict_csp_matching_the_inline_script() -> None:
    html = render_html(report([code("SAST-SQLI-001")]))
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', html)
    assert csp is not None
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert script_hash() in policy
    assert FILTER_SCRIPT in html
    assert "http" not in policy  # no remote origins at all


def test_html_is_offline_single_file() -> None:
    html = render_html(report([code("SAST-SQLI-001")]))
    assert not re.search(r'<(?:link|script|img)[^>]+(?:href|src)="https?://', html)


@pytest.mark.parametrize("lang", ["tr", "en"])
def test_html_languages(lang: str) -> None:
    html = render_html(report([code("SAST-SQLI-001")]), lang=lang)  # type: ignore[arg-type]
    assert f'<html lang="{lang}">' in html
    assert ("Yönetici özeti" in html) == (lang == "tr")


def test_html_renders_remediation_for_detected_stack_first() -> None:
    finding = default_kb().finding(
        "SAST-SQLI-001", module="sast", location=CodeLocation(path="a.php", line=1), stack="php"
    )
    html = render_html(report([finding]))
    assert "Code examples — php" in html


# --------------------------------------------------------------------- SARIF


def test_sarif_is_schema_valid() -> None:
    findings = [
        code("SAST-SQLI-001"),
        http("SEO-NOINDEX-001", "http://127.0.0.1/", "noindex"),
        code("QUAL-EXCEPT-001", "low"),
    ]
    sarif = to_sarif(findings)
    jsonschema.validate(sarif, SCHEMA)
    run = sarif["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "SAST-SQLI-001",
        "SEO-NOINDEX-001",
        "QUAL-EXCEPT-001",
    ]
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert run["results"][0]["partialFingerprints"]["secscopeFindingId/v1"] == findings[0].id


def test_sarif_empty_is_valid() -> None:
    jsonschema.validate(to_sarif([]), SCHEMA)


# ----------------------------------------------------------------------- CSV


def test_csv_neutralises_formulas() -> None:
    f = code("SAST-SQLI-001", snippet='=HYPERLINK("http://evil","x")')
    rows = list(csv.reader(io.StringIO(to_csv([f]))))
    assert rows[0][0] == "id"
    assert rows[1][-1].startswith("'=")


# --------------------------------------------------------------- plan & diff


def test_fix_plan_quick_wins_first() -> None:
    findings = [
        code("SAST-SQLI-001", "high"),
        *(code("SAST-COOKIE-001", "medium", str(i), i + 10) for i in range(5)),
        code("QUAL-EXCEPT-001", "low"),
    ]
    plan = fix_plan(findings)
    assert [p.rule_id for p in plan][:2] == ["SAST-SQLI-001", "SAST-COOKIE-001"]
    cookie = next(p for p in plan if p.rule_id == "SAST-COOKIE-001")
    assert cookie.count == 5


def test_diff_classification() -> None:
    a1, a2, a3 = (
        code("SAST-SQLI-001", "medium"),
        code("SAST-XSS-001", snippet="y"),
        code("SAST-EVAL-001", snippet="z"),
    )
    b1 = a1.model_copy(update={"severity": "critical"})
    b4 = code("SAST-CMDI-001", snippet="w")
    before = report([a1, a2, a3], scores={"overall": 80.0})
    after = report([b1, a2, b4], scores={"overall": 70.0})
    d = diff_reports(before, after)
    assert [f.rule_id for f in d.new] == ["SAST-CMDI-001"]
    assert [f.rule_id for f in d.fixed] == ["SAST-EVAL-001"]
    assert [f.rule_id for f in d.persistent] == ["SAST-XSS-001"]
    assert [(x.severity, y.severity) for x, y in d.regressed] == [("medium", "critical")]
    assert d.summary()["score_delta"]["overall"] == -10.0


# -------------------------------------------------------------------- writer


def test_write_outputs_all_formats(tmp_path: Path) -> None:
    seo: dict[str, Any] = {"score": {"score": 90.0, "subscores": {}, "capped_by_index_blocker": False}, "production_origin": None,
           "pages": [], "generated": {"robots.txt": "User-agent: *\n"}}  # fmt: skip
    written = write_outputs(
        report([code("SAST-SQLI-001")], seo=seo), tmp_path, ["html", "json", "sarif", "csv"]
    )
    assert set(written) == {"html", "json", "sarif", "csv", "patches"}
    assert (written["patches"] / "robots.txt").read_text() == "User-agent: *\n"
    assert json.loads(written["json"].read_text(encoding="utf-8"))["scan_id"] == "s1"


def test_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ReportFormatError):
        write_outputs(report([]), tmp_path, ["docx"])
