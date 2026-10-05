# SecScope — project rules for Claude Code

SPEC.md is the single source of truth. Read the relevant section before touching a module.

## Working rules (SPEC §0, condensed)
- Talk to the user in **Turkish**. Code, identifiers, comments and commit messages in **English**.
  UI strings only through i18n (`ui/i18n/tr.json` default, `en.json`); no hardcoded UI text.
- Milestone loop: summarise design (≤10 lines) → tests first or alongside → implement →
  run tests + linters → check the Definition of Done (SPEC §14) → small, meaningful commits.
  Do not start the next milestone until the user approves.
- Never assume external tool flags. Verify with `<tool> --help` + version + real output and
  record verified flags in `docs/tool-notes/<tool>.md`.
- Never skip silently: a missing tool makes its module `SKIPPED` with reason + install hint.
- **Scope Guard (SPEC §4) is non-negotiable.** All dynamic network traffic goes through
  `secscope.core.scope_guard` (`ScopedHttpClient`, `ScopeGuard.open_connection`). No other
  file may import `socket`, `urllib.request`, `http.client`, `httpcore`, or construct
  `httpx.Client/AsyncClient` — enforced by ruff TID251 and `tests/unit/test_network_ban.py`.
  Never add a setting that disables it. Every change there needs an attack test.
- Pin dependencies (`uv.lock`); pin external binaries by version + SHA-256 in `tools/manifest.toml`.
- Every finding is explainable: what, where, evidence (secrets masked), why, fix with code,
  references (CWE/OWASP). Every `rule_id` needs `remediation/<rule_id>.yaml`.
- On ambiguity: write a short ADR in `docs/decisions/NNN-title.md` and ask the user.
- New scanner = one file + one registry entry. No speculative abstractions.

## Git
- Never add `Co-Authored-By` trailers or "Generated with Claude Code" lines.
- Do not push or create a GitHub remote unless the user asks.

## Commands
```bash
uv sync                                   # install (locked)
uv run pytest                             # all tests
uv run ruff format . && uv run ruff check . && uv run pyright   # must be clean
uv run secscope --version
uv run secscope schema finding            # JSON schemas; docs/schemas/ must match (golden test)
```

## Layout
`src/secscope/core` (models, events, config, scope_guard, redact, logging) ·
`storage` (SQLite + SQL migrations, `PRAGMA user_version`) · `modules` · `worker` · `ui` ·
`reporting` · `tests/unit|integration|e2e|golden` · `docs/decisions` (ADRs).
