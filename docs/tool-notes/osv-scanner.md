# osv-scanner — verified notes

- Verified: 2026-10-05, osv-scanner **2.6.0** (single binary `osv-scanner_windows_amd64.exe`,
  SHA-256 from `osv-scanner_SHA256SUMS`), `osv-scanner scan source --help`, real runs.
- v2 uses the `scan source` subcommand (v1's flat CLI differs).

## Offline databases (explicit user action only)

Location is controlled by the env var `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`; files land in
`<dir>/osv-scalibr/<Ecosystem>/all.zip` (PyPI + npm ≈ 240 MB). Download happens only for the
ecosystems present in the scanned project, so our "update advisory data" action scans a small
template project containing lockfiles for PyPI, npm and Packagist with:

```
osv-scanner scan source --offline --offline-vulnerabilities --download-offline-databases -r <template>
```

## Scan (no network)

```
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<dir> osv-scanner scan source --offline \
  --offline-vulnerabilities -r <project> --format json --verbosity error
```

`--offline` disables every network feature (deps.dev resolution etc.).
Exit code **1 = vulnerabilities found** (not an error); 128/127 = no lockfile / usage errors.

JSON: `results[].source.path` (absolute), `packages[].package{name,version,ecosystem}`,
`packages[].vulnerabilities[]` (OSV records: `id`, `aliases`, `summary`, `affected`),
`packages[].groups[].max_severity` (CVSS base score as a string).
**Read the file as UTF-8** (advisory texts contain non-ASCII characters).
