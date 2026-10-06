"""Pure-function runtime checks (no network)."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from secscope.analysis.http_checks import (
    CORS_PROBE_ORIGIN,
    HttpIssue,
    check_cookies,
    check_cors,
    check_directory_listing,
    check_error_page,
    check_methods,
    check_security_headers,
    exposed_file_issue,
)

HTTP = "http://127.0.0.1:8000/"
HTTPS = "https://127.0.0.1:8443/"
STRONG = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "Strict-Transport-Security": "max-age=63072000",
}


def ids(issues: Iterable[HttpIssue]) -> list[str]:
    return [i.rule_id for i in issues]


def test_missing_all_headers_on_html() -> None:
    found = ids(check_security_headers(HTTP, {}, is_html=True))
    assert "DAST-CSP-001" in found
    assert "DAST-HEADERS-001" in found
    assert "DAST-HTTPS-001" in found  # plain HTTP


def test_strong_headers_produce_no_header_findings() -> None:
    found = ids(check_security_headers(HTTPS, STRONG, is_html=True))
    assert found == []


def test_weak_csp_is_flagged() -> None:
    issues = list(
        check_security_headers(
            HTTPS,
            {**STRONG, "Content-Security-Policy": "default-src *; script-src 'unsafe-inline'"},
            is_html=True,
        )
    )
    csp = [i for i in issues if i.rule_id == "DAST-CSP-001"]
    assert csp
    assert "unsafe-inline" in csp[0].detail


def test_version_disclosure() -> None:
    found = ids(
        check_security_headers(
            HTTPS, {**STRONG, "Server": "nginx/1.25.3", "X-Powered-By": "Express"}, is_html=True
        )
    )
    assert found == ["DAST-SERVER-001"]


def test_non_html_skips_html_only_headers() -> None:
    # A JSON API response is not expected to carry CSP / frame-ancestors / permissions-policy,
    # but HSTS still applies to every HTTPS response.
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=63072000",
    }
    assert ids(check_security_headers(HTTPS, headers, is_html=False)) == []


@pytest.mark.parametrize(
    ("cookie", "expect"),
    [
        ("session_id=x; Path=/", True),
        ("sid=x; Secure; HttpOnly; SameSite=Lax", False),
        ("theme=dark", True),  # low severity, still reported
    ],
)
def test_cookies(cookie: str, expect: bool) -> None:
    assert bool(list(check_cookies(HTTP, [cookie]))) is expect


def test_session_cookie_missing_httponly_is_medium() -> None:
    issue = next(iter(check_cookies(HTTP, ["auth_token=x; Secure"])))
    assert issue.severity == "medium"


def test_cors_reflection_with_credentials_is_high() -> None:
    headers = {
        "Access-Control-Allow-Origin": CORS_PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    issue = next(iter(check_cors(HTTP, CORS_PROBE_ORIGIN, headers)))
    assert issue.rule_id == "DAST-CORS-001"
    assert issue.severity == "high"


def test_cors_same_origin_is_fine() -> None:
    assert (
        list(
            check_cors(
                HTTP, CORS_PROBE_ORIGIN, {"Access-Control-Allow-Origin": "https://app.example.com"}
            )
        )
        == []
    )


def test_trace_method() -> None:
    assert ids(check_methods(HTTP, "GET, POST, TRACE", None)) == ["DAST-METHOD-001"]
    assert ids(check_methods(HTTP, "GET, POST", 405)) == []


def test_error_page_stack_trace() -> None:
    body = "<pre>Traceback (most recent call last):\n  File x</pre>"
    assert ids(check_error_page(HTTP, 500, body)) == ["DAST-ERRLEAK-001"]
    assert list(check_error_page(HTTP, 404, "Not found")) == []
    assert list(check_error_page(HTTP, 500, "Something went wrong")) == []


def test_directory_listing() -> None:
    assert ids(check_directory_listing(HTTP, 200, "<h1>Index of /files/</h1>")) == [
        "DAST-DIRLIST-001"
    ]
    assert list(check_directory_listing(HTTP, 200, "<h1>Welcome</h1>")) == []


def test_exposed_file_needs_200_and_signature() -> None:
    assert exposed_file_issue("/.env", 200, "SECRET=1\n", "=") is not None
    assert exposed_file_issue("/.env", 404, "not found", "=") is None
    # a catch-all 200 page that does not contain the signature is not the real file
    assert exposed_file_issue("/.git/config", 200, "<html>home</html>", "[core]") is None


def test_exposed_git_is_high() -> None:
    issue = exposed_file_issue(
        "/.git/config", 200, "[core]\n\trepositoryformatversion = 0", "[core]"
    )
    assert issue is not None and issue.severity == "high"
