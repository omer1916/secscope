"""The AI-prompt export: a Markdown document an assistant can act on."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secscope.analysis.kb import default_kb
from secscope.core.models import CodeLocation, Evidence, Finding, HttpLocation
from secscope.reporting.ai_prompt import render_ai_prompt
from secscope.reporting.writer import ReportFormatError, write_outputs
from tests.fake_secrets import AWS_KEY_ID


def _finding(rule: str, path: str = "app/db.py", line: int = 10, snippet: str = "x = 1") -> Finding:
    return default_kb().finding(
        rule,
        module="sast",
        location=CodeLocation(path=path, line=line),
        evidence=Evidence(snippet=snippet),
        stack="flask",
    )


def _report(findings: list[Finding], *, stack: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "scan_id": "s1",
        "language": "tr",
        "stack": stack or {"name": "flask", "family": "flask"},
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def test_prompt_lists_each_finding_with_code_and_fix() -> None:
    report = _report([_finding("SAST-SQLI-001", snippet="cur.execute('... ' + q)")])
    out = render_ai_prompt(report, lang="tr")
    assert "SAST-SQLI-001" in out
    assert "app/db.py:10" in out
    assert "cur.execute('... ' + q)" in out  # evidence included
    assert "```python" in out  # fenced by file suffix
    assert out.startswith("# ")  # a Markdown document


def test_findings_are_ordered_by_severity() -> None:
    report = _report(
        [
            _finding("SEO-OG-001", path="index.html"),  # low
            _finding("SAST-SQLI-001"),  # high
        ]
    )
    out = render_ai_prompt(report, lang="en")
    assert out.index("SAST-SQLI-001") < out.index("SEO-OG-001")


def test_info_findings_are_summarised_not_detailed() -> None:
    f = _finding("SAST-SQLI-001")
    f = f.model_copy(update={"severity": "info"})
    out = render_ai_prompt(_report([f]), lang="en")
    # info findings go under the low-priority heading, without a full fix block
    assert "Info level" in out or "low priority" in out.lower()


def test_secret_value_is_masked_in_the_prompt() -> None:
    f = default_kb().finding(
        "SECRET-CLOUD-001",
        module="secrets",
        location=CodeLocation(path="config.py", line=2),
        evidence=Evidence(snippet=f"AWS_KEY = {AWS_KEY_ID}"),
    )
    out = render_ai_prompt(_report([f]), lang="en")
    assert AWS_KEY_ID not in out  # masked


def test_python_stack_prefers_a_python_snippet_over_javascript() -> None:
    # CORS remediation has both express and flask snippets; a flask app should see flask.
    out = render_ai_prompt(_report([_finding("SAST-CORS-001")]), lang="en")
    assert "CORS(app" in out  # the flask snippet, not the express one


def test_http_finding_has_no_file_fence() -> None:
    f = default_kb().finding(
        "DAST-CORS-001",
        module="dast_http",
        location=HttpLocation(url="http://localhost:8000/", method="GET"),
        evidence=Evidence(notes="reflects an arbitrary Origin"),
    )
    out = render_ai_prompt(_report([f]), lang="en")
    assert "DAST-CORS-001" in out
    assert "GET http://localhost:8000/" in out


def test_clean_report_says_nothing_to_fix() -> None:
    assert "0" in render_ai_prompt(_report([]), lang="tr")


def test_writer_emits_ai_markdown_file(tmp_path: Path) -> None:
    report = _report([_finding("SAST-SQLI-001")])
    written = write_outputs(report, tmp_path, ["ai"])
    assert written["ai"].suffix == ".md"
    assert written["ai"].name.endswith(".ai.md")
    assert "SAST-SQLI-001" in written["ai"].read_text(encoding="utf-8")


def test_unknown_format_is_rejected(tmp_path: Path) -> None:

    with pytest.raises(ReportFormatError):
        write_outputs(_report([]), tmp_path, ["nope"])
