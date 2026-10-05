# Architecture

See SPEC.md §3 for the target architecture. This file tracks what exists.

## Process model

```
UI (PySide6)  ──commands (stdin, JSON-Lines)──▶  worker process  ──▶ modules
              ◀──events (stdout, JSON-Lines)───                   ──▶ Scope Guard ──▶ loopback only
```

The core (`secscope.core`) has no UI dependency, so the same code runs headless via the
`secscope` CLI (CI) and inside the worker process (desktop). A crashing scan cannot take
the UI down.

## Implemented (M0)

| Area | Module | Notes |
|---|---|---|
| Data models | `core/models.py` | `Finding`, locations, evidence (secrets masked on construction), remediation, refs. JSON schemas in `docs/schemas/` (golden-tested). See ADR-002. |
| Protocol | `core/events.py` | Versioned (`v: 1`) JSON-Lines events + commands, discriminated unions. |
| Settings | `core/config.py` | `Settings` (atomic save, platformdirs), `ScanConfig`, score weights (sum = 1). |
| Secret masking | `core/redact.py` | Known token formats, key/value pairs, auth headers, cookies, URL credentials, private keys. Idempotent. |
| Logging | `core/logging.py` | Rotating file; the formatter masks secrets in the final text, tracebacks included. |
| Storage | `storage/db.py`, `storage/repo.py` | SQLite, WAL, FK on; migrations are `storage/migrations/NNNN_name.sql`, applied atomically, tracked with `PRAGMA user_version`. |
| Scope Guard | `core/scope_guard.py` | URL decision, DNS pinning, redirect re-checks, `ScopedHttpClient`, scoped raw TCP. See ADR-001. |
| CLI | `cli.py` | `--version`, `schema <kind>`. |

## Network rule

Only `core/scope_guard.py` may use raw network primitives. Enforced by ruff `TID251`
(banned API) and `tests/unit/test_network_ban.py` (AST scan; cannot be silenced).
