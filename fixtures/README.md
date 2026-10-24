# Test fixtures — DELIBERATELY VULNERABLE APPLICATIONS

> **WARNING:** `vuln-*` and `slow-app` contain intentional security bugs (SQL injection,
> command injection, XSS, path traversal, hardcoded fake secrets, ...). They exist only so
> SecScope's detection rate can be measured (SPEC §12).
>
> * They bind to **127.0.0.1 only**. Never expose them, never deploy them, never reuse code.
> * All credentials, keys and tokens in here are **fake** and grant access to nothing.
> * "Path traversal" targets read a local canary file (`canary.txt`), never system files.

| Fixture | Stack | Purpose | Expected results |
|---|---|---|---|
| `vuln-flask` | Python/Flask | SQLi, XSS, debug, secrets, weak JWT, open redirect, traversal, IDOR, cookies, CORS, rate limit, old deps, exposed files, stack traces | `expected.yaml` |
| `vuln-express` | Node/Express | NoSQL injection, command injection, eval, DOM XSS, CORS, source maps, `alg:none` JWT, old lodash | `expected.yaml` |
| `vuln-php` | PHP | SQLi, LFI, unserialize, phpinfo, directory listing (needs PHP to run) | `expected.yaml` |
| `static-seo-bad` | static | SEO problems of every kind | `expected.yaml` |
| `static-seo-good` | static | passes all SEO checks | no critical/high |
| `clean-flask`, `clean-express` | Python / Node | secure counterparts | false-positive budget ≤ 5% |
| `slow-app` | Python stdlib | CPU-bound endpoint, leaking endpoint, small thread pool, crash under load | knee ±20%, leak detected |

`expected.yaml` lists the rule ids a scan must report (`must`) and may report (`may`), per phase
(`static`, `dynamic`, `seo`, ...). Recall is measured against `must`.

Keys shaped like live AWS or Stripe credentials are stored as `__SECSCOPE_FAKE_*__` placeholders,
so that GitHub's push protection does not (rightly) reject them. The detection tests scan a copy
with the fake values filled in; to scan one by hand:

```bash
uv run python -m tests.fake_secrets vuln-flask ../vuln-flask-filled
```
