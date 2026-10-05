"""Scope Guard: the only gate between SecScope and the network (SPEC §4).

Every dynamic module talks to the target exclusively through
:class:`ScopedHttpClient` (HTTP) or :meth:`ScopeGuard.open_connection` (raw TCP).
This module is the single place in the code base allowed to import raw network
primitives; ``tests/unit/test_network_ban.py`` enforces that.

Decision procedure for a URL (see docs/decisions/001-scope-guard-host-normalization.md):

1. Reject anything a URL parser could read differently from another parser:
   control characters, whitespace, backslashes, percent-encoded or non-ASCII
   hosts, userinfo (``user@host``), trailing dots, and every non-canonical
   IPv4 spelling (``0x7f000001``, ``2130706433``, ``0177.0.0.1``, ``127.1``).
   Python, Java (ZAP), Go (Nuclei) and Chromium disagree on these forms.
2. IP literals must be loopback (``127.0.0.0/8``, ``::1``, IPv4-mapped
   loopback) or inside an explicitly allowed private LAN range.
3. Host names must be ``localhost`` or ``*.localhost`` (RFC 6761). They are
   resolved, *every* resolved address must pass step 2, and the connection is
   pinned to the checked address, so DNS rebinding between check and connect
   is impossible.
4. Redirects are re-checked hop by hop; an out-of-scope ``Location`` is not
   followed and is reported as a violation (it may be an open redirect).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Self
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

LOOPBACK_V4 = ipaddress.IPv4Network("127.0.0.0/8")
LOOPBACK_V6 = ipaddress.IPv6Address("::1")
ALLOWED_SCHEMES = frozenset({"http", "https", "ws", "wss"})
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
MAX_REDIRECTS = 10

# Strict dotted-quad: four decimal octets, no leading zeros.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
_CANONICAL_V4 = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")
# WHATWG treats a host whose last label is numeric (decimal or 0x-hex) as IPv4.
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|\d+)$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_IPV6_ALLOWED = re.compile(r"^[0-9a-f:.]+$")


class Reason(StrEnum):
    OK = "ok"
    INVALID_URL = "invalid_url"
    BAD_SCHEME = "bad_scheme"
    ILLEGAL_CHARS = "illegal_chars"
    USERINFO = "userinfo"
    BAD_PORT = "bad_port"
    NON_CANONICAL_HOST = "non_canonical_host"
    NON_CANONICAL_IP = "non_canonical_ip"
    IP_NOT_ALLOWED = "ip_not_allowed"
    NAME_NOT_ALLOWED = "name_not_allowed"
    UNRESOLVABLE = "unresolvable"
    RESOLVES_OUTSIDE_SCOPE = "resolves_outside_scope"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    url: str
    allowed: bool
    reason: Reason
    host: str | None = None
    port: int | None = None
    # Addresses the connection must be pinned to (in resolver order).
    addresses: tuple[IPAddress, ...] = ()

    @classmethod
    def deny(cls, url: str, reason: Reason, host: str | None = None) -> Self:
        return cls(url=url, allowed=False, reason=reason, host=host)


class ScopeViolationError(httpx.RequestError):
    """Raised when a request would leave the allowed scope.

    Subclasses :class:`httpx.RequestError` so modules handle it like any other
    failed request and the scan continues (SPEC §4.6); the violation itself is
    reported centrally through the guard's ``on_violation`` callback.
    """

    def __init__(self, decision: ScopeDecision, *, request: httpx.Request | None = None) -> None:
        super().__init__(
            f"blocked by scope guard ({decision.reason}): {decision.url}", request=request
        )
        self.decision = decision


Resolver = Callable[[str, int], Sequence[IPAddress]]
ViolationCallback = Callable[[ScopeDecision, bool], None]
"""Called with (decision, via_redirect) for every blocked request."""


def system_resolver(host: str, port: int) -> list[IPAddress]:
    """Resolve with the OS resolver, preserving its address order and de-duplicating."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: list[IPAddress] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        if addr not in out:
            out.append(addr)
    return out


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """What counts as "local". Loopback is always allowed; nothing else by default."""

    extra_networks: tuple[IPNetwork, ...] = ()

    @classmethod
    def from_strings(cls, networks: Iterable[str]) -> Self:
        # Settings.allowed_lan_networks has already validated these as private ranges.
        return cls(extra_networks=tuple(ipaddress.ip_network(n, strict=True) for n in networks))

    def ip_allowed(self, ip: IPAddress) -> bool:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv4Address):
            if ip in LOOPBACK_V4:
                return True
        elif ip == LOOPBACK_V6:
            return True
        return any(ip.version == net.version and ip in net for net in self.extra_networks)


@dataclass
class ScopeGuard:
    policy: ScopePolicy = field(default_factory=ScopePolicy)
    resolver: Resolver = system_resolver
    on_violation: ViolationCallback | None = None

    # ------------------------------------------------------------- decisions

    def check(self, url: str | httpx.URL) -> ScopeDecision:
        """Decide whether ``url`` may be requested. Never raises."""
        raw = str(url)
        decision = self._check_syntax(raw)
        if decision.allowed and not decision.addresses:
            decision = self._resolve(decision)
        return decision

    async def acheck(self, url: str | httpx.URL) -> ScopeDecision:
        raw = str(url)
        decision = self._check_syntax(raw)
        if decision.allowed and not decision.addresses:
            decision = await asyncio.to_thread(self._resolve, decision)
        return decision

    def require(self, url: str | httpx.URL, *, via_redirect: bool = False) -> ScopeDecision:
        """Like :meth:`check` but reports and raises on violation."""
        decision = self.check(url)
        if not decision.allowed:
            self.report(decision, via_redirect=via_redirect)
            raise ScopeViolationError(decision)
        return decision

    def report(self, decision: ScopeDecision, *, via_redirect: bool = False) -> None:
        log.warning(
            "scope violation blocked: url=%s reason=%s via_redirect=%s",
            decision.url,
            decision.reason,
            via_redirect,
        )
        if self.on_violation is not None:
            self.on_violation(decision, via_redirect)

    def _check_syntax(self, raw: str) -> ScopeDecision:
        if _FORBIDDEN_URL_CHARS.search(raw) or not raw.isascii():
            return ScopeDecision.deny(raw, Reason.ILLEGAL_CHARS)
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError:
            return ScopeDecision.deny(raw, Reason.INVALID_URL)
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return ScopeDecision.deny(raw, Reason.BAD_SCHEME)
        netloc = parts.netloc
        if not netloc:
            return ScopeDecision.deny(raw, Reason.INVALID_URL)
        if "@" in netloc:
            return ScopeDecision.deny(raw, Reason.USERINFO)
        if port == 0:
            return ScopeDecision.deny(raw, Reason.BAD_PORT)
        effective_port = port if port is not None else DEFAULT_PORTS[scheme]

        host_part = (
            netloc.rsplit(":", 1)[0] if not netloc.endswith("]") and ":" in netloc else netloc
        )
        if host_part.startswith("["):
            return self._check_ipv6_literal(raw, host_part, effective_port)

        host = host_part.lower()
        if not host or "%" in host or "[" in host or "]" in host:
            return ScopeDecision.deny(raw, Reason.ILLEGAL_CHARS, host)
        if host.endswith(".") or ".." in host:
            return ScopeDecision.deny(raw, Reason.NON_CANONICAL_HOST, host)

        if _CANONICAL_V4.match(host):
            ip = ipaddress.IPv4Address(host)
            if not self.policy.ip_allowed(ip):
                return ScopeDecision.deny(raw, Reason.IP_NOT_ALLOWED, host)
            return ScopeDecision(raw, True, Reason.OK, host, effective_port, (ip,))

        labels = host.split(".")
        if _NUMERIC_LABEL.match(labels[-1]):
            return ScopeDecision.deny(raw, Reason.NON_CANONICAL_IP, host)
        if not all(_DNS_LABEL.match(label) for label in labels):
            return ScopeDecision.deny(raw, Reason.NON_CANONICAL_HOST, host)
        if labels[-1] != "localhost":
            return ScopeDecision.deny(raw, Reason.NAME_NOT_ALLOWED, host)
        # Allowed name; addresses are filled in by _resolve.
        return ScopeDecision(raw, True, Reason.OK, host, effective_port)

    def _check_ipv6_literal(self, raw: str, host_part: str, port: int) -> ScopeDecision:
        inner = host_part[1:-1].lower() if host_part.endswith("]") else ""
        if not inner or not _IPV6_ALLOWED.match(inner):
            # Rejects zone ids ("%25eth0"), IPvFuture and malformed brackets.
            return ScopeDecision.deny(raw, Reason.NON_CANONICAL_IP, host_part)
        try:
            ip = ipaddress.IPv6Address(inner)
        except ValueError:
            return ScopeDecision.deny(raw, Reason.INVALID_URL, host_part)
        if not self.policy.ip_allowed(ip):
            return ScopeDecision.deny(raw, Reason.IP_NOT_ALLOWED, host_part)
        return ScopeDecision(raw, True, Reason.OK, inner, port, (ip,))

    def _resolve(self, decision: ScopeDecision) -> ScopeDecision:
        assert decision.host is not None
        assert decision.port is not None
        try:
            addresses = tuple(self.resolver(decision.host, decision.port))
        except OSError:
            addresses = ()
        if not addresses:
            if decision.host == "localhost" or decision.host.endswith(".localhost"):
                # RFC 6761: *.localhost always means loopback, even when the OS
                # resolver (e.g. on Windows) does not know the sub-domain.
                addresses = (ipaddress.IPv4Address("127.0.0.1"), LOOPBACK_V6)
            else:  # pragma: no cover - only localhost names reach this point
                return ScopeDecision.deny(decision.url, Reason.UNRESOLVABLE, decision.host)
        if not all(self.policy.ip_allowed(ip) for ip in addresses):
            # One bad address poisons the whole answer: a rebinding resolver
            # could otherwise make the connect step pick the external one.
            return ScopeDecision.deny(decision.url, Reason.RESOLVES_OUTSIDE_SCOPE, decision.host)
        return ScopeDecision(decision.url, True, Reason.OK, decision.host, decision.port, addresses)

    # ------------------------------------------------------------ raw sockets

    async def open_connection(
        self, host: str, port: int, *, scheme: str = "http", **kwargs: Any
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a TCP connection to an in-scope host (for resilience tests, SPEC §8.4).

        Pass ``ssl=...``/``server_hostname=...`` through ``kwargs`` for TLS.
        """
        authority = f"[{host}]" if ":" in host else host
        decision = await self.acheck(f"{scheme}://{authority}:{port}/")
        if not decision.allowed:
            self.report(decision)
            raise ScopeViolationError(decision)
        last_exc: OSError | None = None
        for ip in decision.addresses:
            try:
                return await asyncio.open_connection(str(ip), port, **kwargs)
            except OSError as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc


def allocate_loopback_port(host: str = "127.0.0.1") -> int:
    """Ask the OS for a free TCP port on a loopback address (for the target app)."""
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("only loopback addresses can be allocated")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def loopback_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """True when nothing listens on ``host:port`` (checked by binding it)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return False
        return True


# ------------------------------------------------------------------- HTTP


class ScopedTransport(httpx.AsyncBaseTransport):
    """httpx transport that checks every request and pins it to a checked IP.

    The URL sent on the wire uses the IP literal; the ``Host`` header (set by
    httpx from the original URL) and TLS SNI keep the original host name.
    """

    def __init__(self, guard: ScopeGuard, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self._guard = guard
        # trust_env=False: an HTTP(S)_PROXY variable must never route traffic elsewhere.
        self._inner = inner or httpx.AsyncHTTPTransport(trust_env=False, retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        decision = await self._guard.acheck(request.url)
        if not decision.allowed:
            self._guard.report(
                decision, via_redirect=bool(request.extensions.get("secscope_redirect"))
            )
            raise ScopeViolationError(decision, request=request)

        last_exc: httpx.ConnectError | None = None
        for ip in decision.addresses:
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=str(ip)),
                headers=request.headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": request.url.host},
            )
            try:
                response = await self._inner.handle_async_request(pinned)
            except httpx.ConnectError as exc:
                last_exc = exc
                continue
            response.extensions = {**response.extensions, "secscope_peer_ip": str(ip)}
            return response
        assert last_exc is not None
        raise last_exc

    async def aclose(self) -> None:
        await self._inner.aclose()


@dataclass(frozen=True, slots=True)
class BlockedRedirect:
    """An in-scope response whose ``Location`` pointed out of scope (not followed)."""

    location: str
    decision: ScopeDecision


class ScopedHttpClient:
    """The only HTTP client dynamic modules may use.

    Redirects are followed manually so an out-of-scope hop is *reported and
    returned*, not raised: the 3xx response is handed back with
    ``response.extensions["secscope_blocked_redirect"]`` set to a
    :class:`BlockedRedirect`, which modules can turn into an open-redirect
    finding.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        timeout: float = 15.0,
        headers: Mapping[str, str] | None = None,
        cookies: httpx.Cookies | None = None,
        verify: bool = False,
        max_redirects: int = MAX_REDIRECTS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        # verify=False: local dev servers typically use self-signed certificates;
        # certificate quality is assessed separately by the TLS checks.
        inner = transport or httpx.AsyncHTTPTransport(trust_env=False, retries=0, verify=verify)
        self.guard = guard
        self.max_redirects = max_redirects
        self._client = httpx.AsyncClient(
            transport=ScopedTransport(guard, inner),
            timeout=timeout,
            headers=headers,
            cookies=cookies,
            follow_redirects=False,
            trust_env=False,
        )

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    async def request(
        self, method: str, url: str | httpx.URL, *, follow_redirects: bool = True, **kwargs: Any
    ) -> httpx.Response:
        request = self._client.build_request(method, url, **kwargs)
        history: list[httpx.Response] = []
        while True:
            response = await self._client.send(request, follow_redirects=False)
            next_request = response.next_request
            if not follow_redirects or next_request is None:
                break
            decision = await self.guard.acheck(next_request.url)
            if not decision.allowed:
                self.guard.report(decision, via_redirect=True)
                response.extensions = {
                    **response.extensions,
                    "secscope_blocked_redirect": BlockedRedirect(str(next_request.url), decision),
                }
                break
            if len(history) >= self.max_redirects:
                raise httpx.TooManyRedirects("exceeded maximum allowed redirects", request=request)
            await response.aread()
            history.append(response)
            next_request.extensions = {**next_request.extensions, "secscope_redirect": True}
            request = next_request
        response.history = history
        return response

    async def get(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def post(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
