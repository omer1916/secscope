"""Scope Guard attack list (SPEC §4.7) and behavioural tests. Must pass 100%."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscope.core.scope_guard import (
    IPAddress,
    Reason,
    ScopeDecision,
    ScopedHttpClient,
    ScopeGuard,
    ScopePolicy,
    ScopeViolationError,
)

V4 = ipaddress.IPv4Address
V6 = ipaddress.IPv6Address


def fixed_resolver(*ips: str) -> Callable[[str, int], Sequence[IPAddress]]:
    addrs = [ipaddress.ip_address(ip) for ip in ips]
    return lambda _host, _port: addrs


def failing_resolver(_host: str, _port: int) -> Sequence[IPAddress]:
    raise OSError("no such host")


@pytest.fixture
def guard() -> ScopeGuard:
    # Deterministic: never depend on the machine's hosts file.
    return ScopeGuard(resolver=fixed_resolver("127.0.0.1", "::1"))


# --------------------------------------------------------------- attack list

DENIED: list[tuple[str, Reason]] = [
    # SPEC §4.7 explicit list
    ("http://example.com", Reason.NAME_NOT_ALLOWED),
    ("http://127.0.0.1.evil.com", Reason.NAME_NOT_ALLOWED),
    ("http://[::ffff:8.8.8.8]", Reason.IP_NOT_ALLOWED),
    ("http://0x7f000001", Reason.NON_CANONICAL_IP),  # decision: ADR-001, rejected
    ("http://localhost@evil.com", Reason.USERINFO),
    # non-canonical IPv4 spellings (parser differentials)
    ("http://2130706433/", Reason.NON_CANONICAL_IP),
    ("http://0177.0.0.1/", Reason.NON_CANONICAL_IP),
    ("http://127.1/", Reason.NON_CANONICAL_IP),
    ("http://127.0.0.01/", Reason.NON_CANONICAL_IP),
    ("http://0x7f.0.0.1/", Reason.NON_CANONICAL_IP),
    ("http://127.0.0.0x1/", Reason.NON_CANONICAL_IP),
    ("http://evil.com.0x7f/", Reason.NON_CANONICAL_IP),
    # non-loopback IP literals
    ("http://0.0.0.0/", Reason.IP_NOT_ALLOWED),
    ("http://8.8.8.8/", Reason.IP_NOT_ALLOWED),
    ("http://10.0.0.1/", Reason.IP_NOT_ALLOWED),
    ("http://192.168.1.10:8080/", Reason.IP_NOT_ALLOWED),
    ("http://169.254.169.254/latest/meta-data/", Reason.IP_NOT_ALLOWED),
    ("http://[::]/", Reason.IP_NOT_ALLOWED),
    ("http://[::127.0.0.1]/", Reason.IP_NOT_ALLOWED),  # deprecated IPv4-compatible
    ("http://[64:ff9b::7f00:1]/", Reason.IP_NOT_ALLOWED),  # NAT64 of 127.0.0.1
    ("http://[fe80::1]/", Reason.IP_NOT_ALLOWED),
    ("http://[2001:4860:4860::8888]/", Reason.IP_NOT_ALLOWED),
    # userinfo in every shape
    ("http://user:pass@localhost/", Reason.USERINFO),
    ("http://localhost:80@evil.com/", Reason.USERINFO),
    ("http://evil.com@localhost/", Reason.USERINFO),
    ("http://localhost%40evil.com/", Reason.ILLEGAL_CHARS),
    # characters that split parsers apart
    ("http://127.0.0.1\\@evil.com/", Reason.ILLEGAL_CHARS),
    ("http://localhost\t.evil.com/", Reason.ILLEGAL_CHARS),
    ("http://local host/", Reason.ILLEGAL_CHARS),
    ("http://localhost\x00.evil.com/", Reason.ILLEGAL_CHARS),
    ("http://%31%32%37.0.0.1/", Reason.ILLEGAL_CHARS),
    ("http://\uff11\uff12\uff17.0.0.1/", Reason.ILLEGAL_CHARS),  # fullwidth digits
    ("http://l\u043ecalhost/", Reason.ILLEGAL_CHARS),  # Cyrillic o
    ("http://[::1%25eth0]/", Reason.NON_CANONICAL_IP),
    # host name shapes
    ("http://localhost./", Reason.NON_CANONICAL_HOST),
    ("http://localhost.evil.com/", Reason.NAME_NOT_ALLOWED),
    ("http://evil-localhost/", Reason.NAME_NOT_ALLOWED),
    ("http://xn--localhost/", Reason.NAME_NOT_ALLOWED),
    ("http://a..localhost/", Reason.NON_CANONICAL_HOST),
    ("http://_x.localhost/", Reason.NON_CANONICAL_HOST),
    ("http://evil.com#@localhost/", Reason.NAME_NOT_ALLOWED),
    ("http://evil.com?@localhost/", Reason.NAME_NOT_ALLOWED),
    # schemes and malformed URLs
    ("ftp://localhost/", Reason.BAD_SCHEME),
    ("file:///etc/passwd", Reason.BAD_SCHEME),
    ("javascript:alert(1)", Reason.BAD_SCHEME),
    ("gopher://localhost:6379/_", Reason.BAD_SCHEME),
    ("//localhost/", Reason.BAD_SCHEME),
    ("http:/localhost/", Reason.INVALID_URL),
    ("http://[::1/", Reason.INVALID_URL),
    ("http://localhost:0/", Reason.BAD_PORT),
    ("http://localhost:99999/", Reason.INVALID_URL),
    ("http://localhost:-1/", Reason.INVALID_URL),
    ("", Reason.BAD_SCHEME),
]

ALLOWED: list[str] = [
    "http://localhost",
    "http://localhost:3000/path?q=1#frag",
    "HTTP://LOCALHOST:8000/",
    "https://localhost/",
    "ws://localhost:5173/socket",
    "http://127.0.0.1/",
    "http://127.0.0.1:65535/",
    "http://127.255.255.254/",
    "http://127.5.6.7:8080/",
    "http://[::1]:8000/",
    "http://[::ffff:127.0.0.1]/",
    "http://app.localhost:3000/",
    "http://a.b.localhost/",
]


@pytest.mark.parametrize(("url", "reason"), DENIED)
def test_attack_list_denied(guard: ScopeGuard, url: str, reason: Reason) -> None:
    decision = guard.check(url)
    assert not decision.allowed
    assert decision.reason == reason
    assert decision.addresses == ()


@pytest.mark.parametrize("url", ALLOWED)
def test_loopback_allowed(guard: ScopeGuard, url: str) -> None:
    decision = guard.check(url)
    assert decision.allowed, decision
    assert decision.addresses
    assert all(ScopePolicy().ip_allowed(ip) for ip in decision.addresses)


def test_check_accepts_httpx_url(guard: ScopeGuard) -> None:
    assert guard.check(httpx.URL("http://localhost:1234/")).allowed
    assert not guard.check(httpx.URL("http://example.com/")).allowed


def test_default_ports(guard: ScopeGuard) -> None:
    assert guard.check("http://localhost/").port == 80
    assert guard.check("https://localhost/").port == 443
    assert guard.check("http://localhost:8443/").port == 8443


# ------------------------------------------------------- resolution / rebinding


def test_hosts_file_poisoning_denied() -> None:
    guard = ScopeGuard(resolver=fixed_resolver("93.184.216.34"))
    decision = guard.check("http://localhost/")
    assert not decision.allowed
    assert decision.reason == Reason.RESOLVES_OUTSIDE_SCOPE


def test_mixed_answer_denied() -> None:
    guard = ScopeGuard(resolver=fixed_resolver("127.0.0.1", "8.8.8.8"))
    assert guard.check("http://localhost/").reason == Reason.RESOLVES_OUTSIDE_SCOPE


def test_mapped_external_answer_denied() -> None:
    guard = ScopeGuard(resolver=fixed_resolver("::ffff:8.8.8.8"))
    assert guard.check("http://localhost/").reason == Reason.RESOLVES_OUTSIDE_SCOPE


def test_unresolvable_localhost_subdomain_falls_back_to_loopback() -> None:
    guard = ScopeGuard(resolver=failing_resolver)
    decision = guard.check("http://app.localhost/")
    assert decision.allowed
    assert set(decision.addresses) == {V4("127.0.0.1"), V6("::1")}


def test_ip_literals_skip_resolver() -> None:
    def boom(_h: str, _p: int) -> Sequence[IPAddress]:
        raise AssertionError("resolver must not be called for IP literals")

    guard = ScopeGuard(resolver=boom)
    assert guard.check("http://127.0.0.1/").addresses == (V4("127.0.0.1"),)
    assert guard.check("http://[::1]/").addresses == (V6("::1"),)


class RebindingResolver:
    """First answer loopback, then an external address (classic DNS rebinding)."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _host: str, _port: int) -> Sequence[IPAddress]:
        self.calls += 1
        return [V4("127.0.0.1")] if self.calls == 1 else [V4("203.0.113.7")]


def test_dns_rebinding_is_rechecked_per_request() -> None:
    guard = ScopeGuard(resolver=RebindingResolver())
    assert guard.check("http://localhost:8000/").allowed
    second = guard.check("http://localhost:8000/")
    assert not second.allowed
    assert second.reason == Reason.RESOLVES_OUTSIDE_SCOPE


async def test_dns_rebinding_cannot_reach_external_ip() -> None:
    """End to end: the transport connects only to the address it checked."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    resolver = RebindingResolver()
    guard = ScopeGuard(resolver=resolver)
    async with ScopedHttpClient(guard, transport=httpx.MockTransport(handler)) as client:
        first = await client.get("http://localhost:8000/a")
        assert first.status_code == 200
        with pytest.raises(ScopeViolationError):
            await client.get("http://localhost:8000/b")
    assert len(seen) == 1
    assert seen[0].url.host == "127.0.0.1"


# --------------------------------------------------------------- LAN policy


def test_lan_policy_allows_only_listed_network() -> None:
    guard = ScopeGuard(policy=ScopePolicy.from_strings(["192.168.1.0/24"]))
    assert guard.check("http://192.168.1.20/").allowed
    assert not guard.check("http://192.168.2.20/").allowed
    assert not guard.check("http://8.8.8.8/").allowed
    # LAN option admits IP literals only, never arbitrary names.
    assert not guard.check("http://nas.lan/").allowed


# -------------------------------------------------------------- HTTP client


class Recorder:
    def __init__(self, routes: dict[str, httpx.Response]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.routes.get(request.url.path, httpx.Response(404))


def make_client(
    routes: dict[str, httpx.Response],
    violations: list[tuple[ScopeDecision, bool]] | None = None,
) -> tuple[ScopedHttpClient, Recorder]:
    rec = Recorder(routes)
    guard = ScopeGuard(
        resolver=fixed_resolver("127.0.0.1"),
        on_violation=(lambda d, r: violations.append((d, r))) if violations is not None else None,
    )
    return ScopedHttpClient(guard, transport=httpx.MockTransport(rec)), rec


async def test_request_is_pinned_and_keeps_host_header() -> None:
    client, rec = make_client({"/": httpx.Response(200)})
    async with client:
        response = await client.get("http://localhost:8000/")
    assert response.status_code == 200
    sent = rec.requests[0]
    assert sent.url.host == "127.0.0.1"
    assert sent.url.port == 8000
    assert sent.headers["host"] == "localhost:8000"
    assert sent.extensions["sni_hostname"] == "localhost"
    assert response.extensions["secscope_peer_ip"] == "127.0.0.1"


async def test_out_of_scope_request_never_reaches_transport() -> None:
    violations: list[tuple[ScopeDecision, bool]] = []
    client, rec = make_client({}, violations)
    async with client:
        with pytest.raises(ScopeViolationError) as exc_info:
            await client.get("http://example.com/")
    assert rec.requests == []
    assert exc_info.value.decision.reason == Reason.NAME_NOT_ALLOWED
    assert len(violations) == 1
    assert violations[0][1] is False


async def test_scope_violation_is_an_httpx_request_error() -> None:
    client, _ = make_client({})
    async with client:
        with pytest.raises(httpx.RequestError):
            await client.get("http://8.8.8.8/")


@pytest.mark.parametrize(
    "location",
    [
        "http://evil.com/",
        "//evil.com/",
        "https://127.0.0.1.evil.com/",
        "http://0x7f000001/",
        "http://localhost@evil.com/",
        "http://[::ffff:8.8.8.8]/",
    ],
)
async def test_redirect_out_of_scope_not_followed(location: str) -> None:
    violations: list[tuple[ScopeDecision, bool]] = []
    client, rec = make_client(
        {"/go": httpx.Response(302, headers={"Location": location})}, violations
    )
    async with client:
        response = await client.get("http://localhost:8000/go")
    assert response.status_code == 302
    blocked = response.extensions["secscope_blocked_redirect"]
    assert not blocked.decision.allowed
    assert [r.url.path for r in rec.requests] == ["/go"]
    assert len(violations) == 1
    assert violations[0][1] is True  # via_redirect


async def test_redirect_in_scope_followed() -> None:
    client, rec = make_client(
        {
            "/a": httpx.Response(301, headers={"Location": "/b"}),
            "/b": httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/c"}),
            "/c": httpx.Response(200, text="done"),
        }
    )
    async with client:
        response = await client.get("http://localhost:8000/a")
    assert response.status_code == 200
    assert response.text == "done"
    assert [r.status_code for r in response.history] == [301, 302]
    assert [r.url.path for r in rec.requests] == ["/a", "/b", "/c"]


async def test_redirect_not_followed_when_disabled() -> None:
    client, rec = make_client({"/a": httpx.Response(302, headers={"Location": "/b"})})
    async with client:
        response = await client.get("http://localhost:8000/a", follow_redirects=False)
    assert response.status_code == 302
    assert len(rec.requests) == 1


async def test_redirect_loop_bounded() -> None:
    client, _ = make_client({"/loop": httpx.Response(302, headers={"Location": "/loop"})})
    async with client:
        with pytest.raises(httpx.TooManyRedirects):
            await client.get("http://localhost:8000/loop")


async def test_proxy_environment_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://evil.com:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.com:3128")
    client, rec = make_client({"/": httpx.Response(200)})
    async with client:
        await client.get("http://localhost:8000/")
    assert rec.requests[0].url.host == "127.0.0.1"


# ----------------------------------------------------------------- property


@given(st.ip_addresses(v=4))
def test_property_ipv4_literal(ip: V4) -> None:
    guard = ScopeGuard()
    decision = guard.check(f"http://{ip}/")
    assert decision.allowed == (ip in ipaddress.IPv4Network("127.0.0.0/8"))


@given(st.ip_addresses(v=6))
def test_property_ipv6_literal(ip: V6) -> None:
    guard = ScopeGuard()
    decision = guard.check(f"http://[{ip}]/")
    mapped = ip.ipv4_mapped
    expected = ip == V6("::1") or (
        mapped is not None and mapped in ipaddress.IPv4Network("127.0.0.0/8")
    )
    assert decision.allowed == expected


@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_property_integer_hosts_denied(n: int) -> None:
    guard = ScopeGuard()
    assert not guard.check(f"http://{n}/").allowed
    assert not guard.check(f"http://{n:#x}/").allowed
    assert not guard.check(f"http://{n:#o}/".replace("0o", "0")).allowed


@given(st.text(max_size=80))
def test_property_never_raises_and_never_allows_external(text: str) -> None:
    guard = ScopeGuard(resolver=fixed_resolver("127.0.0.1"))
    for candidate in (
        text,
        f"http://{text}/",
        f"http://{text}.localhost/",
        f"http://localhost{text}",
    ):
        decision = guard.check(candidate)
        if decision.allowed:
            assert decision.addresses
            assert all(ScopePolicy().ip_allowed(ip) for ip in decision.addresses)
            host = decision.host or ""
            assert host == "localhost" or host.endswith(".localhost") or ipaddress.ip_address(host)


def test_require_reports_and_raises() -> None:
    violations: list[tuple[ScopeDecision, bool]] = []
    guard = ScopeGuard(
        resolver=fixed_resolver("127.0.0.1"), on_violation=lambda d, r: violations.append((d, r))
    )
    assert guard.require("http://localhost:3000/").allowed
    assert violations == []
    with pytest.raises(ScopeViolationError):
        guard.require("http://evil.com/", via_redirect=True)
    assert [(d.reason, r) for d, r in violations] == [(Reason.NAME_NOT_ALLOWED, True)]
