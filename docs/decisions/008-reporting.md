# ADR-008: Report pipeline, report safety and stable ids across scans

- Status: accepted (M8)
- Date: 2026-10-06

## Decisions

1. **`report.json` is canonical.** Each scan saves it in `work/<scan>/report.json` (schema
   version 2). HTML, SARIF 2.1.0, CSV and PDF are rendered from it, so `secscope report <id>`
   re-renders without re-scanning and `secscope diff A B` compares two stored reports.
2. **Report XSS is designed out**: Jinja2 autoescape is always on; target-controlled text
   (titles, URLs, evidence, generated files) is never marked safe. The page has a CSP of
   `default-src 'none'` with our single constant inline script allowed by SHA-256 hash, no remote
   origins at all (single file, works offline). Tests inject `<script>`/`onerror` payloads into
   every text field and assert they come out escaped.
3. **CSV formula injection** is neutralised (cells starting with `= + - @ TAB CR` get a `'`);
   the file is UTF-8 with BOM so Excel shows Turkish characters.
4. **Stable ids across scans**: the target runs on a random loopback port per scan. HTTP
   finding fingerprints treat any loopback origin as `local`, and SEO evidence uses paths
   instead of absolute URLs. Without this every rescan showed all findings as fixed + new (found
   by the end-to-end diff test).
5. **Suppressions** (false positives) are stored with a mandatory reason, by finding id or by
   rule id, applied when the scan is finalised, excluded from scores and counted in the report.
6. **Fix plan** groups findings per rule and orders by impact ÷ effort (impact uses the score
   weights with the repeat discount; effort S=1, M=2, L=4) — quick wins first; the top five are
   the report's "top actions".
7. **PDF** is rendered from the HTML with Playwright's Chromium when installed; otherwise the
   PDF format fails with an install hint (no silent skip).
8. Generated SEO files are copied to `<out>/patches/<scan>/` — the user's source is never edited.
