"""SPEC §4.1: only secscope.core.scope_guard may touch raw network primitives.

Ruff's banned-api rule (TID251) gives editor feedback; this AST scan is the
enforcement that cannot be silenced with ``# noqa``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "secscope"
ALLOWED_FILES = {SRC / "core" / "scope_guard.py"}

BANNED_MODULES = {
    "socket",
    "ssl",
    "urllib.request",
    "urllib3",
    "http.client",
    "httpcore",
    "requests",
    "aiohttp",
    "websockets",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncssh",
}
BANNED_ATTRS = {
    ("httpx", "Client"),
    ("httpx", "AsyncClient"),
    ("httpx", "HTTPTransport"),
    ("httpx", "AsyncHTTPTransport"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("httpx", "patch"),
    ("httpx", "delete"),
    ("httpx", "head"),
    ("httpx", "options"),
    ("httpx", "request"),
    ("httpx", "stream"),
    ("asyncio", "open_connection"),
    ("asyncio", "open_unix_connection"),
}
# Method names that open outbound connections no matter which object they hang off.
BANNED_METHODS = {"create_connection", "sock_connect", "create_datagram_endpoint"}


def violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _banned_module(alias.name):
                    found.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            if _banned_module(node.module):
                found.append(f"from {node.module} import ...")
            for alias in node.names:
                if (node.module, alias.name) in BANNED_ATTRS or _banned_module(
                    f"{node.module}.{alias.name}"
                ):
                    found.append(f"from {node.module} import {alias.name}")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and (node.value.id, node.attr) in BANNED_ATTRS:
                found.append(f"{node.value.id}.{node.attr}")
            if node.attr in BANNED_METHODS:
                found.append(f".{node.attr}")
        elif isinstance(node, ast.Call):
            # __import__("socket") / importlib.import_module("socket")
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name in {"__import__", "import_module"} and node.args:
                arg = node.args[0]
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and (_banned_module(arg.value) or arg.value == "httpx")
                ):
                    found.append(f"{name}({arg.value!r})")
    return found


def _banned_module(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in BANNED_MODULES)


def test_source_tree_has_no_raw_network_access() -> None:
    offenders: dict[str, list[str]] = {}
    for path in SRC.rglob("*.py"):
        if path in ALLOWED_FILES:
            continue
        hits = violations(path.read_text(encoding="utf-8"))
        if hits:
            offenders[str(path.relative_to(SRC))] = hits
    assert offenders == {}, f"raw network access outside scope_guard: {offenders}"


@pytest.mark.parametrize(
    "snippet",
    [
        "import socket",
        "import socket as s",
        "from socket import create_connection",
        "import urllib.request",
        "from urllib import request",
        "import http.client",
        "import requests",
        "import httpcore",
        "from httpx import AsyncClient",
        "import httpx\nhttpx.AsyncClient()",
        "import httpx\nhttpx.get('http://x')",
        "import asyncio\nasyncio.open_connection('x', 1)",
        "loop.create_connection(f, 'x', 1)",
        "__import__('socket')",
        "importlib.import_module('httpx')",
    ],
)
def test_detector_catches(snippet: str) -> None:
    assert violations(snippet)


@pytest.mark.parametrize(
    "snippet",
    [
        "import httpx\nx: httpx.Response",
        "from secscope.core.scope_guard import ScopedHttpClient",
        "import asyncio\nasyncio.sleep(1)",
        "import urllib.parse",
    ],
)
def test_detector_allows(snippet: str) -> None:
    assert violations(snippet) == []
