# Detection benchmarks

Measured against `fixtures/*/expected.yaml` by `tests/integration/test_static_detection.py`
(SPEC §1 success criterion: ≥ 90 % of defined vulnerabilities, ≤ 5 % false positives on clean apps).

## Static analysis (M3) — 2026-10-05, Windows 10, all optional tools installed

Tools: Semgrep 1.179.0, Bandit 1.9.4, gitleaks 8.30.1, Trivy 0.75.0 (DB 2026-10-05),
osv-scanner 2.6.0 (offline DB 2026-10-05).

| Fixture | Must-find rules | Found | Unexpected findings |
|---|---|---|---|
| vuln-flask | 18 (incl. SCA) | 18 | 0 |
| vuln-express | 12 (incl. SCA) | 12 | 0 |
| vuln-php | 5 | 5 | 0 |
| slow-app | 1 | 1 | 0 |
| clean-flask | – | – | 0 |
| clean-express | – | – | 0 (SCA advisories in express's transitive deps are real) |
| static-seo-good | – | – | 0 |

**Static recall: 36 / 36 = 100 %** (97.2 % before fixing a missed NoSQL-injection pattern;
the clean-flask false positive found on the way led to sanitiser and DB-result handling in the
Python taint engine).

Without Semgrep/Bandit/gitleaks/Trivy/osv-scanner the native engines alone still find every
`must` rule except `SCA-VULN-001` (no offline advisory DB) — "reduced coverage" is reported.

## Dogfooding (M10)

Static scan of SecScope's own `src/` (2026-10-06). The first run produced false positives that
were fixed in the engines, each with a regression test:

| Finding | Cause | Fix |
|---|---|---|
| SSRF on `request.get(...)` | local variable named `request` treated as Flask's | taint only from unshadowed `request.<attr>` (AST); Semgrep sources limited to `flask.request.$ANY` |
| Generic secret on type annotations / module paths | `name: str = ...` and dotted identifiers matched | separator / value class tightened; plain identifiers without digits ignored |
| XSS on `|safe` in the report template | constant script pinned by the CSP hash | inline suppression with reason |

After the fixes: **0 findings ≥ medium** — enforced by `tests/integration/test_dogfood.py`.

## Optional external benchmark

OWASP Juice Shop / DVWA / WebGoat can be scanned statically from their source to track detection
beyond our fixtures. Dynamic testing is not part of this build (ADR-009).
