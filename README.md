# SecScope

> **Status: pre-alpha (milestone M0 — foundations).** Not usable for scanning yet.

SecScope is a desktop application that tests **your own** web site, web app or API
**on your own machine**: static analysis, secret and dependency scanning, local
DAST, browser checks, technical SEO readiness and load/resilience testing — merged
into one explainable report with copy-paste fixes.

**Scope is loopback-only by design.** Every dynamic request goes through a scope
guard that only allows `localhost`, `127.0.0.0/8` and `::1`. There is no setting
that turns this off. Do not point SecScope at systems you do not own.

The full product and engineering specification lives in [SPEC.md](SPEC.md)
(Turkish).

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
