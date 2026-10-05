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
| CLI | `cli.py` | `scan`, `tools list`, `modules`, `schema <kind>`, hidden `worker`. Exit codes 0/1/2/3 (`--fail-on`). |

## Implemented (M1)

| Area | Module | Notes |
|---|---|---|
| Module contract | `modules/base.py` | `BaseModule`, `Requirements`, `PreflightResult` (localized), `ScanContext` (`checkpoint()`, `http_client()`), `ModuleResult`. Guide: [adding-a-module.md](adding-a-module.md). |
| Registry | `modules/registry.py` | One `"pkg.mod:Class"` line per module; profiles per module. |
| Orchestrator | `core/orchestrator.py` | Dependency layers, bounded parallelism, exclusive modules, timeouts, pause/resume/cancel, kill_target, scope violations attributed to the module, persistence hooks. |
| Processes | `core/process.py` | `ManagedProcess`: Windows Job Objects / POSIX process groups + psutil sweep. ADR-004. |
| Archives | `core/archive.py` | Safe zip/tar extraction (slip, links, devices, bombs, lying headers). |
| Tools | `core/toolmgr.py`, `tools/manifest.toml` | Detection (managed copy, then PATH), min versions, localized install hints. |
| Session | `core/session.py` | Scan id, work dir, DB, guard (LAN policy), context. |
| Worker | `worker/main.py`, `worker/client.py` | JSON-Lines over stdio, journal `events.jsonl`, exits on stdin EOF. |
| UI | `ui/main_window.py`, `ui/worker_bridge.py`, `ui/i18n/` | Minimal window (QProcess), tr/en catalogs. Full UI in M9. |

## Network rule

Only `core/scope_guard.py` may use raw network primitives. Enforced by ruff `TID251`
(banned API) and `tests/unit/test_network_ban.py` (AST scan; cannot be silenced).
