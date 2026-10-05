"""CSV finding list (SPEC §11.1). Spreadsheet formula injection is neutralised."""

from __future__ import annotations

import csv
import io

from secscope.core.models import Finding, Language

COLUMNS = (
    "id",
    "severity",
    "confidence",
    "rule_id",
    "title",
    "category",
    "module",
    "location",
    "cwe",
    "owasp",
    "source_tools",
    "evidence",
)


def _cell(value: str) -> str:
    # Target-controlled text must not become a formula when opened in Excel/LibreOffice.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def to_csv(findings: list[Finding], *, lang: Language = "en") -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in findings:
        row = (
            f.id,
            f.severity,
            f.confidence,
            f.rule_id,
            f.title.get(lang),
            f.category.value,
            f.module,
            f.location.display(),
            ";".join(f"CWE-{c}" for c in f.cwe),
            ";".join(f.owasp),
            ";".join(f.source_tools),
            f.evidence.snippet or "",
        )
        writer.writerow([_cell(str(v)) for v in row])
    return buf.getvalue()
