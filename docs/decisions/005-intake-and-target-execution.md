# ADR-005: Project intake and running the user's app

- Status: accepted (M2)
- Date: 2026-10-05

## Decisions

1. **Two copies, original untouched.** `work/<scan>/src` is a read-only copy (static
   analysis); `work/<scan>/run` is a writable copy the app runs in, created only when a
   selected module needs a running target. The user's folder is only ever read.
   This is also the primary data-safety measure: active scanning can only damage the copy.
2. **SQLite snapshots** of the run copy (backup API, consistent while open) are taken before
   dynamic modules and restored in the cleanup phase.
3. **The user's code is executed only if** a selected module needs a running target **and**
   the scope statement was accepted. Without consent nothing is copied to `run/` and no
   process starts (tested).
4. **Dependency installation is opt-in** (`RunConfig.install`). It runs the project's own
   install scripts and talks to package registries — explicit user choice in the wizard
   (`--install` later on the CLI). Python projects get a per-scan virtualenv (via `uv` if
   available, else `python -m venv`); Node projects use `npm ci` when a lockfile exists.
5. **Environment whitelist**: only OS/runtime basics (PATH, SYSTEMROOT, HOME, TEMP, locale,
   Node/Java toolchain paths...) are passed; `HOST=127.0.0.1` and `PORT` are set. Cloud keys,
   tokens and other shell secrets of the user never reach the target.
6. **Readiness** = an HTTP status 200–399 on the ready path, polled *through the scope guard*;
   failure reports the last 50 log lines. If the app also listens beyond loopback (e.g.
   `0.0.0.0`) the scan warns that it is reachable from the network while running.
7. **Static sites** are served by our own server in a separate process: loopback only, no
   `Server` header, no directory listing, `404.html` support and Netlify-style `_redirects`
   (so redirect chains / soft 404s can be tested like on a real static host).
8. **Archives**: when everything sits in one top folder (`myapp-main/`), that folder is the
   project root. Symbolic links are never copied or served (they could point at `~/.ssh`).
9. **Fixtures are excluded from ruff/pyright**: an autofixer must never "repair" the
   deliberate vulnerabilities the detection tests rely on.
