"""Single-file, offline HTML report (SPEC §11.1).

Security: Jinja2 autoescaping is always on, so every value that came from the target (titles,
URLs, evidence, headers) is HTML-escaped; the page carries a strict CSP that only allows our own
inline script by hash and no network access at all (no CDN, fonts or images from outside).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import urlsplit

from jinja2 import Environment, PackageLoader, StrictUndefined

from secscope.core.models import SEVERITY_ORDER, Language
from secscope.core.scoring import DISPLAYED_SUBSCORES
from secscope.reporting.json_export import report_findings
from secscope.ui.i18n import Translator

# Filters the finding list; constant code (no data interpolation) so the CSP hash is stable.
FILTER_SCRIPT = """
(function () {
  var q = document.getElementById("q"), mod = document.getElementById("mod");
  if (!q) return;
  var boxes = Array.prototype.slice.call(document.querySelectorAll("input.sev"));
  var items = Array.prototype.slice.call(document.querySelectorAll("details.finding[data-sev]"));
  function apply() {
    var text = q.value.trim().toLowerCase(), m = mod.value;
    var sev = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
    items.forEach(function (el) {
      var ok = sev.indexOf(el.getAttribute("data-sev")) >= 0 &&
               (!m || el.getAttribute("data-mod") === m) &&
               (!text || el.getAttribute("data-q").indexOf(text) >= 0);
      el.hidden = !ok;
    });
  }
  q.addEventListener("input", apply);
  mod.addEventListener("change", apply);
  boxes.forEach(function (b) { b.addEventListener("change", apply); });
})();
""".strip()

GRADE_COLORS = {"A": "#2e7d32", "B": "#558b2f", "C": "#b7791f", "D": "#d1501f", "F": "#b3261e"}


def _urlpath(url: str) -> str:
    """Path and query of a target URL: its loopback origin is a throwaway port."""
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("secscope.reporting", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["urlpath"] = _urlpath
    return env


def script_hash(script: str = FILTER_SCRIPT) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()


def render_html(report: dict[str, Any], *, lang: Language | None = None) -> str:
    language: Language = lang or report.get("language") or "tr"  # type: ignore[assignment]
    t = Translator(language)
    findings = report_findings(report)
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in findings:
        counts[f.severity] += 1
    sev_counts = sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]])  # type: ignore[index]
    plan: list[dict[str, Any]] = report.get("fix_plan", [])
    seo_plan = [p for p in plan if str(p["rule_id"]).startswith("SEO-")]
    scores: dict[str, Any] = {
        "overall": None, "grade": "–", "grade_capped": False, "effective_weights": {},
        "security": None, "seo": None, "resilience": None, "quality": None, "dependencies": None,
        **(report.get("scores") or {}),
    }  # fmt: skip
    return (
        _env()
        .get_template("report.html.j2")
        .render(
            report=report,
            lang=language,
            t=t,
            findings=findings,
            total=len(findings),
            sev_counts=sev_counts,
            modules_with_findings=sorted({f.module for f in findings}),
            plan=plan,
            seo_plan=seo_plan,
            seo=report.get("seo"),
            scores=scores,
            subscores=DISPLAYED_SUBSCORES,
            grade_color=GRADE_COLORS.get(str(scores["grade"]), "#5d6670"),
            script=FILTER_SCRIPT,
            script_hash=script_hash(),
        )
    )
