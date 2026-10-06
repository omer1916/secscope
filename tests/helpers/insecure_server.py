"""A deliberately misconfigured HTTP target for dast_http tests. Stdlib only, loopback only.

Exhibits: missing security headers, a version-disclosing Server header, an insecure session
cookie, CORS origin reflection with credentials, TRACE enabled, directory listing, an exposed
/.env, and a stack-trace error page. DO NOT DEPLOY.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from urllib.parse import parse_qsl

HOME = (
    b"<html><head><title>demo</title></head><body><h1>hi</h1>"
    b'<a href="/hello?name=guest">hello</a> '
    b'<a href="/tmpl?q=hi">tmpl</a> '
    b'<a href="/go?next=/home">go</a></body></html>'
)


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.2.3"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def _send(
        self,
        status: int,
        body: bytes,
        ctype: str = "text/html",
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin:  # CORS origin reflection with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        split = self.path.split("?", 1)
        path = split[0]
        query = dict(parse_qsl(split[1], keep_blank_values=True)) if len(split) > 1 else {}
        if path == "/":
            self._send(200, HOME, extra={"Set-Cookie": "session_id=abc123; Path=/"})
        elif path == "/.env":
            self._send(200, b"SECRET_KEY=prod-value\nDB_PASSWORD=hunter2\n", "text/plain")
        elif path == "/files/":
            self._send(200, b"<html><body><h1>Index of /files/</h1><ul></ul></body></html>")
        elif path == "/hello":
            # reflected input WITHOUT escaping (reflected XSS)
            name = query.get("name", "world")
            self._send(200, f"<html><body><h1>Hello {name}</h1></body></html>".encode())
        elif path == "/tmpl":
            # a naive template engine that evaluates {{7*9}} (SSTI)
            q = query.get("q", "").replace("{{7*9}}", "63").replace("${7*9}", "63")
            self._send(200, f"<html><body>{q}</body></html>".encode())
        elif path == "/go":
            # open redirect: sends the browser wherever ?next points
            self._send(302, b"", extra={"Location": query.get("next", "/")})
        else:
            body = b"<html><body><h1>500</h1><pre>Traceback (most recent call last):\n  File app.py</pre></body></html>"
            self._send(500, body)

    def do_OPTIONS(self) -> None:
        self._send(204, b"", extra={"Allow": "GET, POST, OPTIONS, TRACE"})

    def do_TRACE(self) -> None:
        self._send(200, b"TRACE", "message/http")

    def log_message(self, format: str, *args: object) -> None:
        pass


class insecure_server:  # noqa: N801 - used as a context manager, reads like one
    """``with insecure_server() as url:`` — a misconfigured server on a random loopback port."""

    def __enter__(self) -> str:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self._server.server_address[1]}/"

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
