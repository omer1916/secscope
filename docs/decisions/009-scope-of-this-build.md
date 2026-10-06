# ADR-009: Scope of this build

- Status: accepted (M10)
- Date: 2026-10-06

## Decision

This build ships static analysis (SAST, secrets, dependencies, configuration), SEO / launch
readiness, reporting (HTML, SARIF, CSV, JSON, diff, suppressions), the desktop UI and packaging.

It intentionally does **not** include:

- **Weaponised dynamic testing (part of SPEC M4/M5)**: no attack payloads, ZAP or Nuclei
  scans, exploit chaining or PoC generation. Benign runtime checks and safe reflection
  verification were later added as the `dast_http` module (ADR-011); this exclusion is only
  about weaponised exploitation.
- **Load / stress / resilience testing (SPEC M7)**.
- The wizard's **authentication step** (only meaningful for authenticated dynamic testing),
  so the wizard has four steps.
- **Lab Core Web Vitals** (needs the browser module; ADR-007).

These were decided during development and are recorded here so that documentation, the
threat model and the UI do not promise them. Tools only those parts would need (Java for ZAP,
Nuclei) are not in the tool manifest, so the Tool Manager does not offer them.
