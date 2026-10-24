# Security policy

SecScope runs untrusted input on your machine — project archives, the project's own code and
HTTP responses from the target — so its own security matters. The design and its controls are
described in the [threat model](docs/threat-model.md).

## Reporting a vulnerability

Please **do not open a public issue** for a security problem in SecScope itself. Use GitHub's
private reporting instead: **Security → Report a vulnerability** on this repository.

Especially interesting:

- any way to make SecScope send a request to a host other than `localhost` / `127.0.0.0/8` /
  `::1` (a scope-guard bypass);
- archives that escape the extraction directory or exhaust resources despite the limits;
- secrets that appear unmasked in reports, logs or the database;
- script execution in the HTML report through content of the scanned project or target.

You can expect an acknowledgement within a week. Fixes come with a regression test.

## Supported versions

SecScope is in alpha; only the latest release receives fixes.

## Test data

`fixtures/` and `tests/` deliberately contain **fake** secrets (Stripe-, AWS- and Slack-shaped
strings, private-key headers) and intentionally vulnerable demo applications, so that the
detectors can be tested. None of them is a real credential, and the demo apps must never be
deployed.
