"""Secret masking for evidence, logs and reports.

Every string that may contain target- or user-supplied data passes through
:func:`redact` before it is persisted or displayed. Masking is idempotent:
``redact(redact(x)) == redact(x)``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

MASK = "****…"

# Characters a masked value may consist of; used so already-masked values are
# recognised as such and not masked a second time with a shorter prefix.
_MASKED_TAIL = re.escape(MASK)

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

SENSITIVE_PARAM_NAMES = re.compile(
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"session[_-]?(?:id|key|secret|token)|sessid|jwt|private[_-]?key|credentials?)",
    re.IGNORECASE,
)


def mask(value: str, keep: int = 4) -> str:
    """Mask a secret value, keeping a short prefix for recognisability.

    Values shorter than 12 characters keep no prefix at all: a 4-character
    prefix of a short password would leak a large fraction of it.
    """
    if value.endswith(MASK):
        return value
    if len(value) < 12:
        return MASK
    return value[:keep] + MASK


def _sub_group(pattern: re.Pattern[str], group: str) -> Callable[[str], str]:
    """Build a substitution that masks only the named group of each match."""

    def apply(text: str) -> str:
        def repl(m: re.Match[str]) -> str:
            start, end = m.span(group)
            whole_start = m.start()
            s = m.group(0)
            return s[: start - whole_start] + mask(m.group(group)) + s[end - whole_start :]

        return pattern.sub(repl, text)

    return apply


def _sub_whole(pattern: re.Pattern[str]) -> Callable[[str], str]:
    return lambda text: pattern.sub(lambda m: mask(m.group(0)), text)


_PRIVATE_KEY = re.compile(
    r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----.*?(?:-----END \1-----|\Z)",
    re.DOTALL,
)


def _mask_private_keys(text: str) -> str:
    return _PRIVATE_KEY.sub(
        lambda m: f"-----BEGIN {m.group(1)}-----{MASK}-----END {m.group(1)}-----", text
    )


# Well-known token formats. The value group must not be able to swallow the mask.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),  # AWS key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # GitHub
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),  # GitLab
    re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"),  # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),  # Google API key
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),  # Stripe
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"),  # Anthropic / OpenAI style
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),  # SendGrid
    # JWT: three base64url segments, header starts with {"
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
)

# "Authorization: Bearer xyz", "Basic xyz" and similar schemes.
_AUTH_SCHEME = re.compile(
    r"(?i)\b(?:bearer|basic|token|digest)\s+(?P<v>[A-Za-z0-9._~+/=\-]{8,}(?:"
    + _MASKED_TAIL
    + r")?)"
)

# scheme://user:password@host -> mask the password.
_URL_CREDS = re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:)(?P<v>[^@\s/]+)(?=@)")

# key = value / key: value / "key": "value" / key=value in query strings.
_KEY_VALUE = re.compile(
    r"(?P<k>[\"']?[A-Za-z0-9_.\-]{0,40}?"
    + SENSITIVE_PARAM_NAMES.pattern
    + r"[A-Za-z0-9_.\-]{0,40}[\"']?)"
    r"(?P<sep>\s*[:=]\s*|=)"
    r"(?P<q>[\"']?)(?P<v>[^\"'\s&;,}<>]+)",
    re.IGNORECASE,
)

# "Cookie: a=b; c=d" and "Set-Cookie: a=b; Path=/" header lines.
_COOKIE_LINE = re.compile(r"(?im)^(?P<h>(?:set-)?cookie\s*:\s*)(?P<v>.*)$")
_COOKIE_ATTRS = frozenset(
    {
        "path",
        "domain",
        "expires",
        "max-age",
        "samesite",
        "secure",
        "httponly",
        "priority",
        "partitioned",
    }
)


def _mask_cookie_pairs(value: str) -> str:
    out: list[str] = []
    for part in value.split(";"):
        name, sep, val = part.partition("=")
        if sep and name.strip().lower() not in _COOKIE_ATTRS:
            out.append(f"{name}={mask(val.strip())}" if val.strip() else part)
        else:
            out.append(part)
    return ";".join(out)


def _mask_cookie_lines(text: str) -> str:
    return _COOKIE_LINE.sub(lambda m: m.group("h") + _mask_cookie_pairs(m.group("v")), text)


def _mask_key_values(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        return m.group("k") + m.group("sep") + m.group("q") + mask(m.group("v"))

    return _KEY_VALUE.sub(repl, text)


_STEPS: tuple[Callable[[str], str], ...] = (
    _mask_private_keys,
    *(_sub_whole(p) for p in _TOKEN_PATTERNS),
    _sub_group(_AUTH_SCHEME, "v"),
    _sub_group(_URL_CREDS, "v"),
    _mask_cookie_lines,
    _mask_key_values,
)


def redact(text: str) -> str:
    """Mask every secret-looking substring of ``text``."""
    for step in _STEPS:
        text = step(text)
    return text


def redact_header(name: str, value: str) -> str:
    """Mask a single HTTP header value based on its name and content."""
    lowered = name.strip().lower()
    if lowered in {"cookie", "set-cookie"}:
        return _mask_cookie_pairs(value)
    if lowered in SENSITIVE_HEADERS:
        scheme, sep, rest = value.partition(" ")
        if sep and scheme.isalpha() and rest:
            return f"{scheme} {mask(rest)}"
        return mask(value)
    return redact(value)


def redact_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, redact_header(k, v)) for k, v in headers]
