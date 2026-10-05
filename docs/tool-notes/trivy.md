# Trivy — verified notes

- Verified: 2026-10-05, Trivy **0.75.0** (windows-amd64, SHA-256 from `trivy_0.75.0_checksums.txt`),
  `trivy fs --help`, `trivy config --help`, real offline runs on the fixtures.

## Privacy: telemetry is ON by default

`--disable-telemetry` ("disable sending anonymous usage data to Aqua") and
`--skip-version-check` are passed on **every** invocation.

## Database (explicit user action only)

```
trivy fs --download-db-only --cache-dir <data>/trivy-cache --disable-telemetry --skip-version-check --no-progress -q
```

~1.4 GB on disk. `<cache>/db/metadata.json` has `UpdatedAt` / `NextUpdate` → shown in the report
as the advisory data date. Default DB repos: `mirror.gcr.io/aquasec/trivy-db:2`,
`ghcr.io/aquasecurity/trivy-db:2` (add both hosts to the user-facing privacy notes).

## Scan (offline, no network)

```
trivy fs <dir> --scanners vuln --format json --list-all-pkgs=false --cache-dir <cache> \
  --skip-db-update --skip-java-db-update --skip-check-update --offline-scan \
  --disable-telemetry --skip-version-check -q
```

JSON: `Results[].Target` (manifest path, relative), `Type` (pip, npm, composer...),
`Vulnerabilities[]` with `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`
(comma separated), `Severity` (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN), `CVSS{source:{V3Score}}`,
`Title`, `PrimaryURL`.

`trivy config` (misconfig) works with the embedded check bundle when `--skip-check-update` is set.
