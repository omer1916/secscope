from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from secscope.core.models import (
    Category,
    CodeLocation,
    Evidence,
    Finding,
    HttpLocation,
    HttpMessage,
    LocalizedStr,
    Ref,
)


def make_finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "rule_id": "SEC-HDR-001",
        "module": "dast_native",
        "category": Category.SECURITY,
        "title": LocalizedStr(tr="CSP yok", en="Missing CSP"),
        "severity": "medium",
        "confidence": "high",
        "location": HttpLocation(url="http://localhost:3000/"),
        "source_tools": ["native"],
    }
    data.update(overrides)
    return Finding.model_validate(data)


def test_id_is_stable_sha256() -> None:
    a, b = make_finding(), make_finding()
    assert a.id == b.id
    assert len(a.id) == 64


def test_id_depends_on_rule_location_and_evidence() -> None:
    base = make_finding()
    assert make_finding(rule_id="SEC-HDR-002").id != base.id
    assert make_finding(location=HttpLocation(url="http://localhost:3000/x")).id != base.id
    assert make_finding(evidence=Evidence(snippet="a")).id != base.id


def test_id_ignores_query_values_and_whitespace() -> None:
    a = make_finding(
        location=HttpLocation(url="http://localhost/s?q=1&p=2"),
        evidence=Evidence(snippet="x  y"),
    )
    b = make_finding(
        location=HttpLocation(url="http://localhost/s?p=9&q=3"),
        evidence=Evidence(snippet="x y\n"),
    )
    assert a.id == b.id


def test_code_location_id_ignores_line_drift() -> None:
    ev = Evidence(snippet="eval(user_input)")
    a = make_finding(location=CodeLocation(path="app.py", line=10), evidence=ev)
    b = make_finding(location=CodeLocation(path="app.py", line=42), evidence=ev)
    assert a.id == b.id


def test_stored_id_is_preserved() -> None:
    assert make_finding(id="abc").id == "abc"


@pytest.mark.parametrize("path", ["/etc/passwd", "C:\\x\\y.py", "../outside.py", "a/../../b"])
def test_code_location_must_be_relative(path: str) -> None:
    with pytest.raises(ValidationError):
        CodeLocation(path=path)


def test_code_location_normalises_backslashes() -> None:
    assert CodeLocation(path="src\\app.py", line=3, column=7).display() == "src/app.py:3:7"


@pytest.mark.parametrize("rule_id", ["sec-hdr-001", "SEC", "SEC_HDR", "-SEC-1"])
def test_rule_id_format(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(rule_id=rule_id)


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        make_finding(severityy="high")


def test_source_tools_required() -> None:
    with pytest.raises(ValidationError):
        make_finding(source_tools=[])


def test_evidence_masks_secrets() -> None:
    ev = Evidence(
        snippet='API_KEY = "sk_l\x69ve_4eC39HqLyjWDarjtT1zdp7dc"',
        request=HttpMessage(
            method="GET",
            url="http://localhost/?token=abcdef1234567890",
            headers=[("Authorization", "Bearer abcdefghijklmnopqrstu")],
        ),
        response=HttpMessage(status=200, body="password=hunter2hunter2"),
    )
    dumped = ev.model_dump_json()
    for secret in (
        "4eC39HqLyjWDarjtT1zdp7dc",
        "abcdef1234567890",
        "abcdefghijklmnopqrstu",
        "hunter2hunter2",
    ):
        assert secret not in dumped


def test_http_body_truncated() -> None:
    msg = HttpMessage(body="x" * 50_000)
    assert msg.body is not None
    assert len(msg.body) == 16_000
    assert msg.body_truncated


def test_json_roundtrip() -> None:
    finding = make_finding(
        location=CodeLocation(path="app.py", line=1),
        references=[
            Ref.model_validate({"type": "cwe", "id": 79}),  # YAML KB gives ints
            Ref(type="url", href="https://owasp.org"),
        ],
        cwe=[79],
    )
    again = Finding.model_validate_json(finding.model_dump_json())
    assert again == finding
    assert again.references[0].id == "79"


def test_ref_needs_id_or_href() -> None:
    with pytest.raises(ValidationError):
        Ref(type="url")


def test_findings_are_immutable() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.severity = "high"  # pyright: ignore[reportAttributeAccessIssue]


def test_json_schema_generated() -> None:
    schema = Finding.model_json_schema()
    assert schema["title"] == "Finding"
    assert {"rule_id", "severity", "location"} <= set(schema["properties"])
    json.dumps(schema)


def test_localized_get() -> None:
    text = LocalizedStr(tr="merhaba", en="hello")
    assert text.get("tr") == "merhaba"
    assert text.get("en") == "hello"


def test_http_id_ignores_random_loopback_port() -> None:
    a = make_finding(location=HttpLocation(url="http://127.0.0.1:55705/about"))
    b = make_finding(location=HttpLocation(url="http://127.0.0.1:61234/about"))
    c = make_finding(location=HttpLocation(url="http://localhost:3000/about"))
    assert a.id == b.id == c.id
    assert make_finding(location=HttpLocation(url="https://a.example/about")).id != a.id
