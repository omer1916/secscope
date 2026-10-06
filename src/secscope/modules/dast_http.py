"""Benign runtime security checks against the user's own running app (SPEC §6.3-C, safe subset).

This module never sends attack payloads. It makes ordinary requests to the target (which the
scope guard pins to loopback) and inspects the responses for misconfigurations, and it requests
a short list of well-known sensitive paths to see whether they are exposed. Everything runs only
after the scope statement is accepted and only against the local target.

What it reports: missing/weak security headers, insecure cookies, permissive CORS, HTTP TRACE,
directory listing, exposed `.git`/`.env`/backup files, and error pages that leak stack traces.
Finding ids are stable across rescans (the loopback origin is normalised in the location).
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import ClassVar, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from selectolax.lexbor import LexborHTMLParser

from secscope.analysis.http_checks import (
    CORS_PROBE_ORIGIN,
    EXPOSED_PATHS,
    REDIRECT_PARAM_NAMES,
    REDIRECT_PROBE_URL,
    HttpIssue,
    check_cookies,
    check_cors,
    check_directory_listing,
    check_error_page,
    check_methods,
    check_security_headers,
    exposed_file_issue,
    reflected_unescaped,
    ssti_probe_value,
    template_evaluated,
    xss_probe_value,
)
from secscope.analysis.kb import default_kb
from secscope.core.models import Category, Evidence, HttpLocation, LocalizedStr
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext

RANDOM_PROBE_PATH = "/secscope-not-a-real-path-7f3a9c"
MAX_BODY_BYTES = 512 * 1024
MAX_PROBE_TARGETS = 25


class ReqFn(Protocol):
    async def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> httpx.Response | None: ...


def _same_host(a: str, b: str) -> bool:
    return urlsplit(a).netloc.lower() == urlsplit(b).netloc.lower()


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def discover_get_params(base_url: str, html: str) -> list[tuple[str, str]]:
    """(url, parameter) pairs reachable by GET: query parameters on same-host links and the
    fields of GET forms. POST forms are skipped so nothing changes state."""
    tree = LexborHTMLParser(html)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, param: str) -> None:
        key = (urlsplit(url).path, param)
        if key not in seen and _same_host(base_url, url):
            seen.add(key)
            out.append((url, param))

    for link in tree.css("a[href]"):
        href = urljoin(base_url, link.attributes.get("href") or "")
        for name, _ in parse_qsl(urlsplit(href).query, keep_blank_values=True):
            add(href, name)
    for form in tree.css("form"):
        if (form.attributes.get("method") or "get").lower() != "get":
            continue  # never submit POST forms: they may change state
        action = urljoin(base_url, form.attributes.get("action") or base_url)
        for field in form.css("input[name], textarea[name], select[name]"):
            name = field.attributes.get("name")
            if name:
                add(_set_param(action, name, ""), name)
    return out[:MAX_PROBE_TARGETS]


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / rps
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)


def _is_html(response: httpx.Response) -> bool:
    return "html" in response.headers.get("content-type", "").lower()


class DastHttpModule(BaseModule):
    id: ClassVar[str] = "dast_http"
    title: ClassVar[LocalizedStr] = LocalizedStr(
        tr="Çalışan uygulama kontrolleri", en="Running-app checks"
    )
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(target_running=True)
    timeout_s: ClassVar[float] = 15 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        assert ctx.target_url is not None
        target = ctx.target_url
        limiter = RateLimiter(ctx.settings.rate_limits.dast_rps)
        result = ModuleResult()
        issues: list[HttpIssue] = []

        async with ctx.http_client(timeout=15) as client:

            async def req(
                method: str,
                url: str,
                *,
                headers: dict[str, str] | None = None,
                follow_redirects: bool = False,
            ) -> httpx.Response | None:
                await limiter.wait()
                try:
                    return await client.request(
                        method, url, headers=headers, follow_redirects=follow_redirects
                    )
                except httpx.HTTPError as exc:
                    emit.log(f"request failed: {method} {url}: {type(exc).__name__}", "debug")
                    return None

            emit.progress(10, "home page")
            home = await req("GET", target)
            if home is None:
                result.notes.append("dast_http: the target did not respond")
                emit.log("target did not respond; skipping runtime checks", "warning")
                return result
            body = home.text[:MAX_BODY_BYTES]
            is_html = _is_html(home)

            issues += check_security_headers(target, dict(home.headers), is_html=is_html)
            issues += check_cookies(target, home.headers.get_list("set-cookie"))
            issues += check_directory_listing(target, home.status_code, body)
            await ctx.checkpoint()

            emit.progress(35, "CORS")
            cors_resp = await req("GET", target, headers={"Origin": CORS_PROBE_ORIGIN})
            if cors_resp is not None:
                issues += check_cors(target, CORS_PROBE_ORIGIN, dict(cors_resp.headers))

            emit.progress(45, "methods")
            options = await req("OPTIONS", target)
            trace = await req("TRACE", target)
            issues += check_methods(
                target,
                options.headers.get("allow", "") if options is not None else "",
                trace.status_code if trace is not None else None,
            )
            await ctx.checkpoint()

            emit.progress(55, "error handling")
            missing = await req("GET", urljoin(target, RANDOM_PROBE_PATH))
            if missing is not None:
                issues += check_error_page(
                    urljoin(target, RANDOM_PROBE_PATH),
                    missing.status_code,
                    missing.text[:MAX_BODY_BYTES],
                )

            emit.progress(65, "exposed files")
            total = len(EXPOSED_PATHS)
            for i, (path, signature) in enumerate(EXPOSED_PATHS):
                await ctx.checkpoint()
                resp = await req("GET", urljoin(target, path))
                if resp is not None:
                    issue = exposed_file_issue(
                        path, resp.status_code, resp.text[:MAX_BODY_BYTES], signature
                    )
                    if issue is not None:
                        issues.append(issue)
                emit.progress(65 + int(20 * (i + 1) / total), "exposed files")

            # Safe reflection verification: send harmless markers through GET parameters and
            # observe how the app returns them (no payload executes). See http_checks.
            emit.progress(88, "input reflection")
            issues += await self._verify_reflection(req, ctx, target, body, is_html)

        kb = default_kb()
        stack = ctx.fingerprint.stack_family if ctx.fingerprint else None
        seen: set[tuple[str, str, str, str]] = set()
        for issue in issues:
            key = (issue.rule_id, issue.url, issue.parameter or "", issue.detail)
            if key in seen:
                continue
            seen.add(key)
            emit.finding(
                kb.finding(
                    issue.rule_id,
                    module=self.id,
                    location=HttpLocation(
                        url=issue.url, method=issue.method, parameter=issue.parameter
                    ),
                    evidence=Evidence(notes=issue.detail, extra=issue.extra),
                    severity=issue.severity,
                    confidence=issue.confidence,
                    stack=stack,
                )
            )
        result.data["checks"] = len(seen)
        emit.progress(100, f"{len(seen)} finding(s)")
        return result

    async def _verify_reflection(
        self,
        req: ReqFn,
        ctx: ScanContext,
        target: str,
        home_body: str,
        is_html: bool,
    ) -> list[HttpIssue]:
        if not is_html:
            return []
        issues: list[HttpIssue] = []
        canary = "sc" + secrets.token_hex(4)
        for url, param in discover_get_params(target, home_body):
            await ctx.checkpoint()
            reflect = await req("GET", _set_param(url, param, xss_probe_value(canary)))
            if reflect is not None and reflected_unescaped(canary, reflect.text[:MAX_BODY_BYTES]):
                issues.append(
                    HttpIssue(
                        "DAST-XSS-001",
                        url,
                        f"parameter '{param}' is reflected without HTML-escaping",
                        parameter=param,
                        severity="high",
                    )
                )
            tmpl = await req("GET", _set_param(url, param, ssti_probe_value(canary)))
            if tmpl is not None and template_evaluated(canary, tmpl.text[:MAX_BODY_BYTES]):
                issues.append(
                    HttpIssue(
                        "DAST-SSTI-001",
                        url,
                        f"parameter '{param}' is evaluated by a template engine",
                        parameter=param,
                        severity="critical",
                    )
                )
            if param.lower() in REDIRECT_PARAM_NAMES:
                red = await req(
                    "GET", _set_param(url, param, REDIRECT_PROBE_URL), follow_redirects=True
                )
                blocked = (
                    red.extensions.get("secscope_blocked_redirect") if red is not None else None
                )
                location = str(getattr(blocked, "location", ""))
                if location.startswith("https://secscope-redirect-probe.example"):
                    issues.append(
                        HttpIssue(
                            "DAST-REDIRECT-001",
                            url,
                            f"parameter '{param}' redirects to an external URL",
                            parameter=param,
                            severity="medium",
                        )
                    )
        return issues
