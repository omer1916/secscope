"""Scope Guard against real loopback sockets (no mocks): pinning must work on the wire."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from secscope.core.scope_guard import ScopedHttpClient, ScopeGuard, ScopeViolationError


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
            return
        body = f"host={self.headers['Host']}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server_port() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


async def test_real_request_ip_literal(server_port: int) -> None:
    async with ScopedHttpClient(ScopeGuard()) as client:
        response = await client.get(f"http://127.0.0.1:{server_port}/")
    assert response.status_code == 200
    assert response.text == f"host=127.0.0.1:{server_port}"


async def test_real_request_localhost_name(server_port: int) -> None:
    # The OS may resolve localhost to ::1 first; the transport must fall back to 127.0.0.1.
    async with ScopedHttpClient(ScopeGuard()) as client:
        response = await client.get(f"http://localhost:{server_port}/")
    assert response.status_code == 200
    assert response.text == f"host=localhost:{server_port}"
    assert response.extensions["secscope_peer_ip"] == "127.0.0.1"


async def test_real_redirect_out_blocked(server_port: int) -> None:
    async with ScopedHttpClient(ScopeGuard()) as client:
        response = await client.get(f"http://127.0.0.1:{server_port}/redirect-out")
    assert response.status_code == 302
    assert "secscope_blocked_redirect" in response.extensions


async def test_open_connection_in_scope(server_port: int) -> None:
    reader, writer = await ScopeGuard().open_connection("127.0.0.1", server_port)
    writer.write(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()
    assert data.startswith(b"HTTP/1.0 200")


@pytest.mark.parametrize("host", ["8.8.8.8", "example.com", "0x7f000001", "::ffff:1.1.1.1"])
async def test_open_connection_out_of_scope(host: str) -> None:
    with pytest.raises(ScopeViolationError):
        await ScopeGuard().open_connection(host, 80)
