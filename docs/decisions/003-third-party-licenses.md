# ADR-003: Project license and third-party license constraints

- Status: accepted (M0); license facts below are to be re-verified when each tool is integrated
- Date: 2026-10-05

## Decision

SecScope is licensed **Apache-2.0** (user decision, 2026-10-05).

## Constraints recorded from SPEC §2 (verify against upstream at integration time)

| Component | License (per SPEC) | Constraint |
|---|---|---|
| PySide6 / Qt 6 | LGPL-3.0 | Link dynamically; PyInstaller one-folder build keeps Qt as replaceable shared libraries; ship license texts and a "how to replace Qt" note. |
| OWASP ZAP | Apache-2.0 | Downloaded by the Tool Manager, not bundled. |
| Trivy | Apache-2.0 | Downloaded, not bundled. |
| Nuclei + templates | MIT | Downloaded; templates updated only by explicit user action. |
| gitleaks | MIT | Downloaded, not bundled. |
| Locust | MIT | Python dependency. |
| Playwright | Apache-2.0 | Chromium downloaded at first run. |
| Semgrep engine | LGPL-2.1 | Invoked as an external CLI. **Semgrep Registry rules have a separate, more restrictive license** → we never redistribute registry rules; our own rules live in `rules/`; registry rules are fetched only on the user's machine when online. |

Each integration milestone re-checks the license at the pinned version and updates this table.
