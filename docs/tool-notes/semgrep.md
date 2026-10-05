# Semgrep — verified notes

- Verified: 2026-10-05, Semgrep **1.179.0** (OSS engine), Windows 10 native (`semgrep.exe` via
  `uv tool install semgrep`). `semgrep scan --help` and a real run were used.

## Invocation we use

```
semgrep scan --config <our rules dir> --json --metrics=off --disable-version-check \
  --no-rewrite-rule-ids --quiet --timeout 30 --jobs N <target dir>
```

| Flag | Verified behaviour |
|---|---|
| `--metrics=off` | "metrics are disabled altogether and not sent". Default is `auto` (sends when pulling from the registry or logged in) → we always pass `off`. |
| `--disable-version-check` | no update check (privacy, offline). |
| `--no-rewrite-rule-ids` | without it `check_id` becomes `C.Users.<path>.<rule-id>` (derived from the config path). |
| `--json` | results on stdout. |
| `--timeout=DOUBLE` | per-file per-rule timeout (default 5 s). |
| `--max-target-bytes` | default 1 000 000; larger files skipped. |
| `--exclude=PATTERN` / `--include` | glob filters. |
| `--use-git-ignore` / `--no-git-ignore` | we scan a copy; pass `--no-git-ignore` so ignored-but-present files (e.g. `.env`) are seen. |

## JSON shape (1.179.0)

```json
{"version":"1.179.0",
 "results":[{"check_id":"…","path":"…","start":{"line":2,"col":1,"offset":10},
             "end":{"line":2,"col":21,"offset":30},
             "extra":{"message":"…","metadata":{},"severity":"ERROR",
                      "fingerprint":"requires login","lines":"requires login",
                      "engine_kind":"OSS"}}],
 "errors":[], "paths":{"scanned":[…]}}
```

**Important:** without login, `extra.lines` is the literal string `"requires login"`. We read the
evidence line from the file ourselves using `start.line` / `end.line`.

## Exit codes

0 = ran (findings or not, without `--error`); 1 = findings with `--error`; ≥2 = errors.
We do not pass `--error` and treat ≥2 as module failure (stderr captured).

## Licensing

The engine is LGPL-2.1 and invoked as an external CLI. Semgrep Registry rules (`p/…`) have a
separate, more restrictive licence → we never ship them; our own rules live in `rules/semgrep/`.
