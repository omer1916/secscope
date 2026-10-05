# gitleaks — verified notes

- Verified: 2026-10-05, gitleaks **8.30.1** (windows-amd64 release, SHA-256 from
  `gitleaks_8.30.1_checksums.txt`), `gitleaks --help`, `gitleaks git --help`, real runs.
- Since v8.19 the subcommands are `dir`, `git`, `stdin` (`detect`/`protect` are legacy).

## Invocations

```
gitleaks dir <path> --redact=100 --no-banner -f json -r - --exit-code 0 -l error
gitleaks git <repo> --redact=100 --no-banner -f json -r - --exit-code 0 -l error
```

| Flag | Behaviour |
|---|---|
| `--redact=100` | `Match` and `Secret` become the literal `"REDACTED"` — secrets never reach our process output. |
| `-f json -r -` | JSON array on stdout. |
| `--exit-code 0` | do not signal "leaks found" via exit status (we parse JSON instead). |
| `-l error` | keep stderr quiet. |
| `--max-target-megabytes` | optional size cap. |

## JSON fields used

`RuleID`, `File` (relative to the given path, OS separators), `StartLine`, `StartColumn`,
`Commit` (empty for `dir`), `Date`, `Entropy`, `Description`.

## Mapping

`aws-*`, `gcp-*`, `azure-*` → `SECRET-CLOUD-001`; `private-key` → `SECRET-PRIVKEY-001`;
`jwt` → `SECRET-JWT-001`; `generic-api-key` → `SECRET-GENERIC-001`; anything else →
`SECRET-TOKEN-001`. Git-history results whose (rule, file) is not present in the working
tree become `SECRET-HISTORY-001`.

`git` mode needs `git` on PATH and the project's `.git` folder (kept in the scan copy).
