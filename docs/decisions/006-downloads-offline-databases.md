# ADR-006: Tool downloads, offline advisory databases and third-party telemetry

- Status: accepted (M3)
- Date: 2026-10-05

## Context

SPEC §13 allows network traffic only to (a) the loopback target, (b) user-initiated tool and
database updates, (c) consented external link checks. Several tools we wrap phone home by
default: **Trivy sends anonymous telemetry unless `--disable-telemetry`** (verified in
0.75.0 help text), Semgrep sends metrics when `--metrics` is `auto` and the registry is used.
Vulnerability matching needs advisory data that changes daily.

## Decisions

1. **Second sanctioned network path**: `secscope.core.downloader` (besides the scope guard).
   HTTPS only; every hop including redirects must be on `tools/manifest.toml`
   `[download_hosts]`; size cap; SHA-256 verified *before* unpacking; safe extraction. Allowed
   only behind explicit user actions (`secscope tools install|update-db`, UI buttons) — never
   during a scan. Enforced by ruff TID251 + the AST network-ban test.
2. **Pinned binaries**: gitleaks 8.30.1, Trivy 0.75.0, osv-scanner 2.6.0, Nuclei 3.11.1 for
   windows/linux (amd64, arm64) and darwin (amd64, arm64); hashes copied from each release's
   official checksum file (2026-10-05). Bumping = edit the manifest + re-record golden outputs.
3. **Advisory data is offline during scans**: Trivy runs with `--skip-db-update
   --skip-java-db-update --skip-check-update --offline-scan`; osv-scanner with `--offline
   --offline-vulnerabilities`. Databases (Trivy ≈1.4 GB, OSV PyPI+npm ≈240 MB) are refreshed by
   `secscope tools update-db`. The report shows the database date; without any database the SCA
   module still builds the inventory/SBOM and states "reduced coverage".
4. **Telemetry off everywhere**: Trivy `--disable-telemetry --skip-version-check`; Semgrep
   `--metrics=off --disable-version-check` (+ `SEMGREP_SEND_METRICS=off`); only our own
   Semgrep rules are used, so the registry is never contacted.
5. **Online-only checks are not run** (`npm audit`, `pip-audit` query public services with the
   full dependency list). They may be added later behind an explicit, default-off setting.
6. Running both Trivy and osv-scanner is deliberate: on the fixtures osv-scanner found
   advisories for `qs` and `path-to-regexp` that Trivy did not, and agreement between both
   raises a finding's confidence.
