# Changelog

## 0.1.0 — first public release

**Scanning**

- Static analysis: Python AST taint tracking, pattern rules for JavaScript/TypeScript, PHP and
  templates, optional Semgrep and Bandit; insecure defaults and world-writable permissions.
- Secrets: own scanner plus optional gitleaks (git history); values always masked; secrets in
  git-ignored files are shown as information.
- Dependencies: Trivy and osv-scanner with offline databases; npm, PyPI (requirements,
  Pipfile.lock, poetry.lock, uv.lock, pyproject.toml, versions from the project's `.venv`) and
  Composer; typosquatting, install scripts, copyleft licences, CycloneDX SBOM.
- Configuration: Docker, compose, nginx, Apache, GitHub Actions (outside-attacker model).
- Running-app checks on localhost: headers, cookies, CORS, exposed files, error leakage, and
  reflected XSS / template injection / open redirect verified with harmless markers.
- SEO and launch readiness: 33 checks, generated `robots.txt`, `sitemap.xml` and JSON-LD.

**Results**

- A–F score with a documented formula; unmeasured areas are shown as "–".
- HTML, JSON, SARIF, CSV, PDF and an AI-ready Markdown prompt ("Copy for AI").
- Scan history, diff, false-positive suppression, coverage section, attack-surface inventory,
  git revision stamp, `--changed-since` and `--fail-on` for CI.

**App**

- PySide6 desktop app (Turkish / English, light / dark) and CLI; Windows build with PyInstaller.
- Scope guard (loopback only, cannot be disabled), sandboxed target execution, no telemetry.
