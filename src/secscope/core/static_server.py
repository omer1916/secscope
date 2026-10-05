"""Built-in static file server for static sites (SPEC §6.1), run as its own process.

Behaves like a typical static host (Netlify / GitHub Pages) so SEO checks are meaningful:

* binds to a loopback address only;
* no directory listings; ``404.html`` (if present) is served with status 404;
* a Netlify-style ``_redirects`` file is honoured for exact paths:
  ``/from /to 301|302|307|308`` redirects, ``/from /to 200`` rewrites, ``... 404`` serves
  the target with status 404;
* no ``Server`` header, so header findings describe the site, not this server;
* symbolic links are never served, nor files outside the root.
"""

from __future__ import annotations

import argparse
import ipaddress
import mimetypes
import sys
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_TEXTUAL = ("application/javascript", "application/json", "image/svg+xml", "application/xml")


@dataclass(frozen=True, slots=True)
class Rule:
    target: str
    status: int


def parse_redirects(text: str) -> dict[str, Rule]:
    rules: dict[str, Rule] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        status = 301
        if len(parts) > 2 and parts[2].rstrip("!").isdigit():
            status = int(parts[2].rstrip("!"))
        rules.setdefault(parts[0], Rule(parts[1], status))
    return rules


class StaticHandler(BaseHTTPRequestHandler):
    root: Path
    redirects: dict[str, Rule]
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return ""

    def send_header(self, keyword: str, value: str) -> None:
        if keyword.lower() == "server":
            return
        super().send_header(keyword, value)

    def do_GET(self) -> None:
        self._handle(head=False)

    def do_HEAD(self) -> None:
        self._handle(head=True)

    def _resolve(self, url_path: str) -> Path | None:
        rel = urllib.parse.unquote(url_path).lstrip("/")
        candidate = self.root / rel
        try:
            resolved = candidate.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(self.root) or _has_link(candidate, self.root):
            return None
        if resolved.is_dir():
            index = resolved / "index.html"
            return index if index.is_file() else None
        return resolved if resolved.is_file() else None

    def _is_dir(self, url_path: str) -> bool:
        # pathlib ignores trailing slashes, so "/file.html/" would look like a file: check directly.
        candidate = self.root / urllib.parse.unquote(url_path).lstrip("/")
        try:
            resolved = candidate.resolve()
        except OSError:
            return False
        return resolved.is_relative_to(self.root) and resolved.is_dir()

    def _redirect(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle(self, *, head: bool) -> None:
        split = urllib.parse.urlsplit(self.path)
        path = split.path or "/"
        rule = self.redirects.get(path)
        if rule is not None and rule.status in REDIRECT_CODES:
            self._redirect(rule.status, rule.target + (f"?{split.query}" if split.query else ""))
            return
        status = HTTPStatus.OK
        if rule is not None:
            path, status = rule.target, HTTPStatus(rule.status)
        elif not path.endswith("/") and self._is_dir(path):
            self._redirect(HTTPStatus.MOVED_PERMANENTLY, path + "/")
            return
        file = self._resolve(path)
        if file is None:
            self._not_found(head)
            return
        self._send_file(file, status, head)

    def _send_file(self, file: Path, status: int, head: bool) -> None:
        body = file.read_bytes()
        ctype = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in _TEXTUAL:
            ctype += "; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _not_found(self, head: bool) -> None:
        page = self.root / "404.html"
        if page.is_file():
            self._send_file(page, HTTPStatus.NOT_FOUND, head)
            return
        body = b"<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>"
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        sys.stdout.write((format % args) + "\n")
        sys.stdout.flush()


def _has_link(path: Path, root: Path) -> bool:
    current = path
    while current not in (root, current.parent):
        if current.is_symlink():
            return True
        current = current.parent
    return False


def make_server(root: Path, host: str, port: int) -> ThreadingHTTPServer:
    if not ipaddress.ip_address(host).is_loopback:
        raise SystemExit("static server binds to loopback only")
    root = root.resolve()
    redirects_file = root / "_redirects"
    rules = (
        parse_redirects(redirects_file.read_text(encoding="utf-8"))
        if redirects_file.is_file()
        else {}
    )
    handler = type("Handler", (StaticHandler,), {"root": root, "redirects": rules})
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecScope built-in static server")
    parser.add_argument("root", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    server = make_server(args.root, args.host, args.port)
    print(f"serving {args.root} on http://{args.host}:{server.server_address[1]}/", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
