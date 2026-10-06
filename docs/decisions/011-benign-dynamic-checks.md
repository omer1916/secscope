# ADR-011: Benign dynamic checks (dast_http)

- Status: accepted
- Date: 2026-10-07

## Context

The goal users describe is "test my own app, find the holes, fix them". Static analysis
(strong for Python/JS/PHP) already finds code vulnerabilities with the exact line and a fix.
What it cannot see is runtime behaviour: the server's response headers, cookies, CORS, exposed
files, and whether a given input is actually reflected unsanitised at runtime. ADR-009 had
deferred all dynamic testing; this ADR adds back the part that is defensive and safe.

## Decision

Add a dynamic module, `dast_http`, that runs **only** against the user's own loopback target,
**only** after the scope statement is accepted (enforced by the orchestrator), at the configured
rate. It has two halves, both benign:

1. **Response inspection** — ordinary requests; the module reads what the app returns:
   missing/weak security headers (CSP, HSTS, X-Frame-Options, …), version disclosure, insecure
   cookies, permissive CORS (origin reflection), HTTP TRACE, directory listing, exposed
   `.git`/`.env`/backup files, and stack-trace/debug error pages.

2. **Safe reflection verification** — for each GET parameter discovered on the home page, a
   **harmless unique marker** is sent and the module observes how the app returns it:
   - angle brackets that come back unescaped → reflected XSS (`DAST-XSS-001`);
   - a `{{7*9}}` marker returning `63` → template injection (`DAST-SSTI-001`);
   - a parameter that sends the browser to an external address → open redirect
     (`DAST-REDIRECT-001`, detected through the scope guard's blocked-redirect signal).

   The marker is inert — no script executes, nothing is exploited. This is the standard
   low-false-positive verification technique (SPEC §6.3-C "güvenli kanıt"), not an attack.

## What is still excluded

- **Weaponised exploitation**: SQL-injection / command-injection payloads crafted to trigger
  database errors, time delays or command execution; ZAP/Nuclei active scans; exploit chaining
  or PoC generation. SQL and command injection are covered by static analysis instead, which
  points at the exact vulnerable line.
- **POST forms are never submitted**, so the module never changes application state.
- Load / stress testing (still out, ADR-009).

## Consequences

The `dast_http` module counts toward the security sub-score. Findings use `HttpLocation`
(loopback origin normalised), so ids stay stable across rescans. Discovery is limited to
home-page links and GET forms; deeper crawling is future work.
