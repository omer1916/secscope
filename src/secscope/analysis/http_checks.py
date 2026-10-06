"""Benign runtime checks on the responses of the user's own local app (SPEC §6.3-C, safe
subset). Pure functions: they take response data (status, headers, body) and yield issues, so
they are fully testable without a network. No attack payloads are sent; every check only
inspects what the app returns to ordinary requests, or requests well-known paths to see
whether they are exposed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from secscope.core.models import Confidence, Severity

# Well-known paths that should never be reachable in production. Requesting them is benign
# (a normal GET); finding one served is the finding.
EXPOSED_PATHS: tuple[tuple[str, str], ...] = (
    ("/.git/config", "[core]"),
    ("/.git/HEAD", "ref:"),
    ("/.env", "="),
    ("/.env.local", "="),
    ("/.DS_Store", "\x00\x00\x00"),
    ("/.svn/entries", ""),
    ("/.hg/requires", ""),
    ("/config.php.bak", "<?php"),
    ("/wp-config.php.bak", "<?php"),
    ("/backup.sql", ""),
    ("/db.sqlite3", "SQLite format"),
    ("/phpinfo.php", "phpinfo()"),
    ("/.aws/credentials", "aws_access_key_id"),
    ("/docker-compose.yml", "services:"),
)
# Framework debug / stack-trace signatures in an error response body.
ERROR_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("werkzeug debugger", "Werkzeug Debugger"),
    ("werkzeug traceback", "Traceback (most recent call last)"),
    ("django debug", "You're seeing this error because you have"),
    ("django traceback", "Request Method:</th>"),
    ("flask traceback", "flask.app"),
    ("php error", "<b>Fatal error</b>"),
    ("php warning", "<b>Warning</b>:"),
    ("php notice", "on line <b>"),
    ("rails error", "Action Controller: Exception caught"),
    ("express stack", "at Object.&lt;anonymous&gt;"),
    ("node stack", "at processTicksAndRejections"),
    ("dotnet stack", "ASP.NET"),
    ("sql error", "SQL syntax"),
    ("stack trace", "stack trace:"),
)
DIRECTORY_LISTING = re.compile(r"<title>Index of /|<h1>Index of /|Directory listing for ")
# A probe origin we present in the CORS check; a correctly configured app rejects it.
CORS_PROBE_ORIGIN = "https://secscope-cors-probe.example"


@dataclass(frozen=True, slots=True)
class HttpIssue:
    rule_id: str
    url: str
    detail: str
    confidence: Confidence = "high"
    severity: Severity | None = None
    method: str = "GET"
    extra: dict[str, str] = field(default_factory=dict[str, str])


def _lower(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def is_https(url: str) -> bool:
    return urlsplit(url).scheme == "https"


def check_security_headers(
    url: str, headers: Mapping[str, str], *, is_html: bool
) -> Iterator[HttpIssue]:
    h = _lower(headers)
    https = is_https(url)

    csp = h.get("content-security-policy")
    if is_html and not csp:
        yield HttpIssue("DAST-CSP-001", url, "no Content-Security-Policy header", severity="medium")
    elif csp:
        weak: list[str] = []
        if "unsafe-inline" in csp:
            weak.append("unsafe-inline")
        if "unsafe-eval" in csp:
            weak.append("unsafe-eval")
        if re.search(r"(?:default|script|style|img)-src[^;]*\*", csp):
            weak.append("wildcard source")
        if "frame-ancestors" not in csp:
            weak.append("no frame-ancestors")
        if "object-src" not in csp and "default-src" not in csp:
            weak.append("no object-src")
        if weak:
            yield HttpIssue(
                "DAST-CSP-001", url, "weak CSP: " + ", ".join(weak), "medium", "low",
                extra={"csp": csp[:200]},
            )  # fmt: skip

    missing: list[str] = []
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    frame_ok = "x-frame-options" in h or (csp is not None and "frame-ancestors" in csp)
    if is_html and not frame_ok:
        missing.append("X-Frame-Options (or CSP frame-ancestors)")
    if "referrer-policy" not in h:
        missing.append("Referrer-Policy")
    if is_html and "permissions-policy" not in h:
        missing.append("Permissions-Policy")
    if https and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if missing:
        yield HttpIssue("DAST-HEADERS-001", url, "missing: " + ", ".join(missing), severity="low")

    disclosed: list[str] = []
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        disclosed.append(f"Server: {server}")
    if "x-powered-by" in h:
        disclosed.append(f"X-Powered-By: {h['x-powered-by']}")
    for key in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if key in h:
            disclosed.append(f"{key}: {h[key]}")
    if disclosed:
        yield HttpIssue("DAST-SERVER-001", url, "; ".join(disclosed), severity="low")

    if not https:
        yield HttpIssue("DAST-HTTPS-001", url, "served over plain HTTP (local)", "medium", "info")


def check_cookies(url: str, set_cookie_headers: list[str]) -> Iterator[HttpIssue]:
    """Each raw ``Set-Cookie`` header value; a session cookie without HttpOnly+Secure is worse."""
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        missing = [
            flag
            for flag, present in (
                ("Secure", "secure" in attrs),
                ("HttpOnly", "httponly" in attrs),
                ("SameSite", "samesite=" in attrs),
            )
            if not present
        ]
        if not missing:
            continue
        session_like = bool(re.search(r"(?i)sess|sid|token|auth|jwt", name))
        severity: Severity = (
            "medium" if session_like and {"HttpOnly", "Secure"} & set(missing) else "low"
        )
        yield HttpIssue(
            "DAST-COOKIE-001", url, f"cookie '{name}' missing: {', '.join(missing)}",
            severity=severity, extra={"cookie": name},
        )  # fmt: skip


def check_cors(
    url: str, probe_origin: str, response_headers: Mapping[str, str]
) -> Iterator[HttpIssue]:
    """Given the response to a request that carried ``Origin: <probe_origin>``: does the app
    reflect that untrusted origin (optionally with credentials)? Benign — one normal request."""
    h = _lower(response_headers)
    acao = h.get("access-control-allow-origin", "")
    creds = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    if acao == probe_origin:
        detail = "reflects an arbitrary Origin" + (" with credentials" if creds else "")
        yield HttpIssue(
            "DAST-CORS-001", url, detail, severity="high" if creds else "medium",
            extra={"allow_origin": "reflected"},
        )  # fmt: skip
    elif acao == "*" and creds:
        yield HttpIssue("DAST-CORS-001", url, "Allow-Origin '*' with credentials", severity="high")


def check_methods(url: str, allow_header: str, trace_status: int | None) -> Iterator[HttpIssue]:
    allowed = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    if "TRACE" in allowed or trace_status == 200:
        yield HttpIssue("DAST-METHOD-001", url, "HTTP TRACE is enabled", severity="low")


def check_error_page(url: str, status: int, body: str) -> Iterator[HttpIssue]:
    if status < 400:
        return
    low = body.lower()
    for label, needle in ERROR_SIGNATURES:
        if needle.lower() in low:
            yield HttpIssue(
                "DAST-ERRLEAK-001", url, f"error response leaks a {label}", severity="medium",
                extra={"signature": label},
            )  # fmt: skip
            return


def check_directory_listing(url: str, status: int, body: str) -> Iterator[HttpIssue]:
    if status == 200 and DIRECTORY_LISTING.search(body):
        yield HttpIssue("DAST-DIRLIST-001", url, "directory listing is enabled", severity="medium")


def exposed_file_issue(path: str, status: int, body: str, signature: str) -> HttpIssue | None:
    """A well-known sensitive path that returned 200 with content that looks like the real
    file (the signature guards against a catch-all 200 page)."""
    if status != 200:
        return None
    if signature and signature not in body[:4096]:
        return None
    if not signature and len(body) < 8:
        return None
    severity: Severity = "high" if path.startswith(("/.git", "/.env", "/.aws")) else "medium"
    return HttpIssue("DAST-EXPOSED-001", path, f"{path} is reachable", severity=severity,
                     extra={"path": path})  # fmt: skip
