"""Write a report in the requested formats + generated patch files (SPEC §10, §11.1)."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

from secscope.core.jsonutil import jdict
from secscope.core.models import Language
from secscope.reporting.csv_export import to_csv
from secscope.reporting.html import render_html
from secscope.reporting.json_export import report_findings, save_report
from secscope.reporting.sarif import to_sarif

FORMATS = ("html", "json", "sarif", "csv", "pdf")


class ReportFormatError(ValueError):
    pass


def html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    """Render the HTML report to PDF with Playwright's Chromium (optional dependency)."""
    try:
        # Optional dependency, imported dynamically so it stays optional for type checking too.
        sync_api: Any = importlib.import_module("playwright.sync_api")
    except ImportError as exc:
        raise ReportFormatError(
            "PDF needs Playwright: 'uv pip install playwright' and 'playwright install chromium'"
        ) from exc
    with sync_api.sync_playwright() as p:  # pragma: no cover - needs a browser
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())
        page.pdf(path=str(pdf_path), format="A4", print_background=True)
        browser.close()


def write_outputs(
    report: dict[str, Any], out_dir: Path, formats: list[str], *, lang: Language | None = None
) -> dict[str, Path]:
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise ReportFormatError(f"unknown format(s): {', '.join(sorted(unknown))}")
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"secscope-{report['scan_id']}"
    language: Language = lang or report.get("language") or "tr"  # type: ignore[assignment]
    written: dict[str, Path] = {}
    if "json" in formats:
        written["json"] = save_report(report, base.with_suffix(".json"))
    if "html" in formats or "pdf" in formats:
        html_path = base.with_suffix(".html")
        html_path.write_text(render_html(report, lang=language), encoding="utf-8")
        if "html" in formats:
            written["html"] = html_path
        if "pdf" in formats:
            pdf_path = base.with_suffix(".pdf")
            html_to_pdf(html_path, pdf_path)
            written["pdf"] = pdf_path
    findings = report_findings(report)
    if "sarif" in formats:
        path = base.with_suffix(".sarif")
        path.write_text(
            json.dumps(to_sarif(findings, lang=language), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        written["sarif"] = path
    if "csv" in formats:
        path = base.with_suffix(".csv")
        # utf-8-sig so Excel opens Turkish characters correctly.
        path.write_text(to_csv(findings, lang=language), encoding="utf-8-sig")
        written["csv"] = path
    generated = jdict(jdict(report.get("seo")).get("generated"))
    if generated:
        patches = out_dir / "patches" / str(report["scan_id"])
        patches.mkdir(parents=True, exist_ok=True)
        for name, content in generated.items():
            (patches / Path(name).name).write_text(str(content), encoding="utf-8", newline="\n")
        written["patches"] = patches
    return written
