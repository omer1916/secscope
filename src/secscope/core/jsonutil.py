"""Typed accessors for untrusted JSON from external tools (keeps pyright strict happy and
makes malformed tool output degrade to "nothing" instead of crashing)."""

from __future__ import annotations

from typing import Any, cast


def jdict(value: Any) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def jlist(value: Any) -> list[Any]:
    return cast(list[Any], value) if isinstance(value, list) else []


def jstr(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def jint(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return default
