# Threat model — SecScope itself

SecScope runs untrusted input on the user's machine: project archives, the project's own code,
and HTTP responses from the target. This document lists what can go wrong and how the design
answers it. Each control is backed by tests (named in brackets).

## Assets

The user's machine and files, the user's credentials and secrets (shell environment, SSH keys,
cloud configs), third parties on the network, and the integrity of SecScope's reports.

## Threats and controls

| # | Threat | Control | Tests |
|---|---|---|---|
| T1 | **SecScope traffic leaves the machine** (typo'd URL, crawled link, redirect, DNS rebinding, proxy env, parser tricks such as `localhost@evil.com`, `127.0.0.1\@evil.com`, `0x7f000001`) | Scope guard: loopback-only decisions, non-canonical hosts rejected, resolve-and-pin, every redirect hop re-checked, `trust_env=False`; no other module may open sockets (ruff TID251 + AST test). ADR-001. | `test_scope_guard*`, `test_network_ban` |
| T2 | **Malicious archive** (zip slip, absolute paths, symlinks, devices, reserved Windows names, zip bombs, lying headers) | Safe extractor validates every entry before writing, enforces size/count/ratio on written bytes, removes partial output. | `test_archive` (incl. hypothesis) |
| T3 | **The scanned project's code is hostile** (it runs when a dynamic module needs the target) | Runs only after the scope statement; in a *copy*; environment whitelist (no user secrets); loopback port; whole process tree killed on stop/cancel/crash (Job Objects / process groups); listening beyond loopback is reported. Not a sandbox against malware — the wizard says "only your own code". Docker isolation is future work. ADR-004/005. | `test_sandbox`, `test_process`, `test_worker` |
| T4 | **Report XSS** — target-controlled text (titles, URLs, evidence) executes in the report | Jinja2 autoescape always on; strict CSP (`default-src 'none'`, script by hash, no remote origins); UI detail panel escapes everything. | `test_reporting`, `test_ui_smoke::test_detail_panel_escapes_target_content` |
| T5 | **CSV formula injection** in exported findings | Cells starting with `= + - @ TAB CR` are prefixed with `'`. | `test_csv_neutralises_formulas` |
| T6 | **Secrets leak** into logs, events, the database or reports | Evidence models mask on construction; log formatter masks the final text including tracebacks; gitleaks runs with `--redact=100`. | `test_redact`, `test_models`, `test_logging_and_cli`, `test_tool_contracts` |
| T7 | **Supply chain of the tools we run** | Binaries pinned by version + SHA-256 from official checksum files; HTTPS to allow-listed hosts only (redirects included); safe extraction; downloads only on explicit user action. ADR-006. | `test_downloader` |
| T8 | **Third-party telemetry / phoning home** | Trivy `--disable-telemetry --skip-version-check`, Semgrep `--metrics=off`, offline advisory databases during scans. | tool notes, `test_tool_contracts` |
| T9 | **XML attacks** via sitemaps (entity expansion, external entities) | `defusedxml` refuses DTDs/entities. | `test_seo_analysis::test_sitemap_parsing` |
| T10 | **Worker crash / UI death** leaves orphan processes or open ports | Worker exits on stdin EOF; kill-on-close Job Object on Windows; tree sweep on POSIX (known gap: SIGKILL of the worker by the OS on POSIX, ADR-004). | `test_worker` |
| T11 | **False sense of security** | Every module reports SKIPPED / reduced coverage instead of silently passing; SEO report states its limits; lab vs field metrics are labelled. | `test_orchestrator`, report templates |
| T12 | **SecScope's own code** has the bugs it looks for | Dogfooding: the source must pass its own static analysis with no medium+ findings. | `test_dogfood` |

## Out of scope in this build

Active dynamic attack simulation (DAST, M4/M5) and load / resilience testing (M7) are not
implemented (ADR-009), so SecScope never sends attack payloads or load to any target.
