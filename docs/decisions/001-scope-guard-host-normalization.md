# ADR-001: Scope Guard host normalisation and pinning

- Status: accepted (M0)
- Date: 2026-10-05
- Context: SPEC §4, in particular §4.7 ("`http://0x7f000001` — decide and test")

## Context

SecScope must only ever talk to the user's own machine. URLs reach the guard from
user input, crawled pages, redirects, OpenAPI files and external tools (ZAP is Java,
Nuclei is Go, the browser is Chromium). These parsers disagree on edge cases. Verified
with httpx 0.28.1 on 2026-10-05:

| Input | `urllib.parse` host | httpx host | Browsers (WHATWG) |
|---|---|---|---|
| `http://localhost@evil.com/` | `evil.com` | `evil.com` | `evil.com` |
| `http://127.0.0.1\@evil.com/` | `evil.com` | `evil.com` | `127.0.0.1` (backslash = `/`) |
| `http://0x7f000001/` | `0x7f000001` | `0x7f000001` | `127.0.0.1` |
| `http://2130706433/`, `http://127.1/` | unchanged | unchanged | `127.0.0.1` |
| `http://0177.0.0.1/` | `0177.0.0.1` | `InvalidURL` | `127.0.0.1` |

Any accept/deny decision that depends on *which* parser later handles the URL can be
turned into a scope escape.

## Decision

1. **Reject ambiguity instead of interpreting it.** Denied before any resolution:
   non-ASCII, control characters, whitespace, backslashes, `%` in the host, userinfo
   (any `@` in the authority, even `user:pass@localhost`), trailing dots, empty labels,
   and **every non-canonical IPv4 spelling** — a host whose last label is numeric or
   `0x…` but which is not a strict dotted quad without leading zeros.
   So `0x7f000001` is **denied** even though it means 127.0.0.1: no legitimate user
   types it, and accepting it would require us to replicate four parsers exactly.
2. **IP literals:** `127.0.0.0/8`, `::1`, and IPv4-mapped loopback (`::ffff:127.x.x.x`).
   Everything else is denied (including `0.0.0.0`, `[::]`, NAT64 `64:ff9b::/96`,
   IPv4-compatible `::127.0.0.1`, link-local, zone ids). The advanced "my LAN" option
   (off by default, double confirmation in the UI) adds RFC 1918 / RFC 4193 ranges only,
   and only for IP literals — never names.
3. **Names:** only `localhost` and `*.localhost` (RFC 6761). They are resolved on every
   check; **all** returned addresses must be allowed (one external address poisons the
   answer), and the connection is **pinned** to a checked address. The URL on the wire
   carries the IP; the `Host` header and TLS SNI keep the name. Check and connect use the
   same resolution result, so DNS rebinding between them is impossible. If the OS cannot
   resolve a `*.localhost` sub-domain (Windows), we fall back to 127.0.0.1/::1 per RFC 6761.
4. **Redirects** are followed manually; every hop is checked. An out-of-scope `Location`
   is not followed, the 3xx response is returned with a `secscope_blocked_redirect`
   marker (a candidate open-redirect finding), and a `scope.violation` is reported.
5. **Environment proxies are ignored** (`trust_env=False`): `HTTP(S)_PROXY`/`ALL_PROXY`
   must never route traffic off the machine.
6. Violations raise `ScopeViolationError` (an `httpx.RequestError`), so modules handle
   them like a failed request and the scan continues; the guard's `on_violation`
   callback emits the `scope.violation` event centrally.

## Consequences

- A user typing `http://127.1:3000` gets a clear "non-canonical IP" error and must type
  `127.0.0.1`. Acceptable.
- External tools (ZAP/Nuclei, M5) must be configured with the *checked, canonical* URL
  and include/exclude regexes derived from it; their own traffic is verified from logs.
- Enforcement that modules cannot bypass the guard: ruff `TID251` banned-api plus an AST
  test (`tests/unit/test_network_ban.py`) that cannot be silenced with `noqa`.
