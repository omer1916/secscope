# SecScope

> **Status: alpha.** Static analysis, secrets, dependency and configuration checks, SEO / launch
> readiness, reporting, the desktop UI and Windows packaging work. Active dynamic testing (DAST)
> and load testing are not part of this build ([ADR-009](docs/decisions/009-scope-of-this-build.md)).

SecScope is a desktop application that tests **your own** web site, web app or API
**on your own machine**: static analysis, secret and dependency scanning, configuration
checks and technical SEO readiness — merged into one explainable report with copy-paste fixes.

**Scope is loopback-only by design.** Every dynamic request goes through a scope
guard that only allows `localhost`, `127.0.0.0/8` and `::1`. There is no setting
that turns this off. Do not point SecScope at systems you do not own.

The full product and engineering specification lives in [SPEC.md](SPEC.md)
(Turkish).

User guides: [Türkçe](docs/user-guide.tr.md) · [English](docs/user-guide.en.md) ·
[threat model](docs/threat-model.md) · [packaging](packaging/README.md).

## Quick start (CLI)

```bash
uv sync
uv run secscope tools install gitleaks trivy osv-scanner   # optional, SHA-256 verified
uv run secscope tools update-db                              # offline advisory databases
uv run secscope scan --path ./my-project --accept-scope-statement --format html,json,sarif
uv run secscope diff <old-scan-id> <new-scan-id>
```

The HTML report works offline and contains scores, a quick-wins-first fix plan, every finding
with evidence (secrets masked), fixes with code for your stack, and a "Visibility in Google"
section with generated `robots.txt`, `sitemap.xml` and JSON-LD drafts.

## Development

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run secscope --version
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run pyright
```

Install the git hooks once with `uv run pre-commit install`.

Project layout and conventions: [docs/architecture.md](docs/architecture.md),
architecture decisions: [docs/decisions/](docs/decisions/).

## License

Apache-2.0 — see [LICENSE](LICENSE).
