from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscope.core.redact import MASK, mask, redact, redact_header

# Fake but format-correct secrets; never real credentials.
SECRETS = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "slack": "xoxb-1234567890-abcdefghijkl",
    "google": "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
    "stripe": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "anthropic": "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz012345",
    "jwt": (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ),
}


@pytest.mark.parametrize(("kind", "secret"), sorted(SECRETS.items()))
def test_known_token_formats_masked(kind: str, secret: str) -> None:
    out = redact(f"config {kind} = {secret} end")
    assert secret not in out
    assert MASK in out


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('DB_PASSWORD="hunter2hunter2"', "hunter2hunter2"),
        ("password: s3cr3t!", "s3cr3t!"),
        ('{"api_key": "abcd1234efgh5678"}', "abcd1234efgh5678"),
        ("SECRET_KEY=django-insecure-xyz123456", "django-insecure-xyz123456"),
        ("https://x.local/cb?token=abc123def456ghi&x=1", "abc123def456ghi"),
        ("postgres://app:SuperSecret99@localhost:5432/db", "SuperSecret99"),
        ("Authorization: Bearer abcdefghijklmnop.qrstuv", "abcdefghijklmnop.qrstuv"),
        ("Cookie: sessionid=9f8e7d6c5b4a39281706; theme=dark", "9f8e7d6c5b4a39281706"),
        ("Set-Cookie: sid=AbCdEf0123456789; Path=/; HttpOnly", "AbCdEf0123456789"),
        ("client_secret=xyzzyxyzzyxyzzy", "xyzzyxyzzyxyzzy"),
    ],
)
def test_contextual_secrets_masked(text: str, secret: str) -> None:
    assert secret not in redact(text)


def test_private_key_block_masked() -> None:
    key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq\nabcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact(f"x\n{key}\ny")
    assert "MIIEowIBAAKCAQEA7bq" not in out
    assert "-----BEGIN RSA PRIVATE KEY-----" in out


def test_truncated_private_key_masked() -> None:
    out = redact("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA")
    assert "b3BlbnNzaC1rZXktdjEAAAAA" not in out


def test_benign_text_untouched() -> None:
    text = "author = 'Jane'; session_timeout = 30; inside = True; GET /index.html 200"
    assert redact(text) == text


def test_mask_keeps_short_prefix_only_for_long_values() -> None:
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA" + MASK
    assert mask("short") == MASK
    assert mask(mask("AKIAIOSFODNN7EXAMPLE")) == "AKIA" + MASK


def test_header_redaction() -> None:
    assert redact_header("Authorization", "Bearer abcdefghijklmnopqrst") == "Bearer abcd" + MASK
    assert redact_header("X-Api-Key", "zyxwvutsrqponmlk") == "zyxw" + MASK
    assert redact_header("Set-Cookie", "a=0123456789abcdef; Path=/; Secure").endswith(
        "; Path=/; Secure"
    )
    assert redact_header("Content-Type", "text/html") == "text/html"


@given(st.text(max_size=300))
def test_redact_idempotent(text: str) -> None:
    once = redact(text)
    assert redact(once) == once


@given(st.sampled_from(sorted(SECRETS.values())), st.text(max_size=40), st.text(max_size=40))
def test_secret_never_survives_any_context(secret: str, before: str, after: str) -> None:
    assert secret not in redact(f"{before} {secret} {after}")
