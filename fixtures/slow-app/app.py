"""Load-test fixture (SPEC §12): known bottlenecks, stdlib only. Loopback only.

* /         cheap page
* /cpu      CPU-bound work (~15 ms of hashing per request)
* /leak     keeps 200 KB per request forever (memory leak)
* /health   cheap health check
* A fixed pool of 4 worker threads; requests queue up behind it.
* When more than CRASH_INFLIGHT requests are in flight, the process exits (crash under load).
"""

import hashlib
import os
import queue
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
WORKERS = int(os.environ.get("SLOW_APP_WORKERS", "4"))
CRASH_INFLIGHT = int(os.environ.get("SLOW_APP_CRASH_INFLIGHT", "200"))

_leak: list[bytes] = []
_inflight = 0
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(
                200,
                b"<html><head><title>slow-app</title></head><body>ok</body></html>",
                "text/html",
            )
        elif path == "/health":
            self._send(200, b"ok")
        elif path == "/cpu":
            digest = b"seed"
            for _ in range(20_000):
                digest = hashlib.sha256(digest).digest()
            self._send(200, digest.hex().encode())
        elif path == "/leak":
            _leak.append(os.urandom(200 * 1024))
            self._send(200, f"kept {len(_leak)} blocks".encode())
        else:
            self._send(404, b"not found")

    def log_message(self, format: str, *args: object) -> None:
        pass


class PooledServer(HTTPServer):
    """HTTPServer that hands connections to a fixed-size worker pool."""

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, Handler)
        self.jobs: queue.Queue[tuple[socket.socket, tuple[str, int]]] = queue.Queue()
        for _ in range(WORKERS):
            threading.Thread(target=self._worker, daemon=True).start()

    def process_request(self, request, client_address) -> None:  # type: ignore[override]
        global _inflight
        with _lock:
            _inflight += 1
            if _inflight > CRASH_INFLIGHT:
                sys.stderr.write(f"slow-app: {_inflight} requests in flight, crashing\n")
                os._exit(3)
        self.jobs.put((request, client_address))

    def _worker(self) -> None:
        global _inflight
        while True:
            request, client_address = self.jobs.get()
            try:
                self.finish_request(request, client_address)
            except Exception:
                pass
            finally:
                self.shutdown_request(request)
                with _lock:
                    _inflight -= 1


if __name__ == "__main__":
    server = PooledServer((HOST, PORT))
    print(f"slow-app on http://{HOST}:{PORT} with {WORKERS} workers", flush=True)
    server.serve_forever()
