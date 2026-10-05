"""Tool contract tests: our parsers against *recorded real outputs* (tests/golden/).

Re-record with ``uv run python scripts/record_golden.py`` after a tool version bump.
"""

from __future__ import annotations

import json
from pathlib import Path

from secscope.analysis.kb import default_kb
from secscope.modules.common import ToolMap
from secscope.modules.sast import parse_bandit, parse_semgrep
from secscope.modules.sca import VulnerablePackage, parse_osv, parse_trivy
from secscope.modules.secrets import gitleaks_rule, parse_gitleaks

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "golden"


def golden(tool: str, fixture: str) -> tuple[str, Path]:
    root = REPO / "fixtures" / fixture
    text = (GOLDEN / tool / f"{fixture}.json").read_text(encoding="utf-8")
    # Paths were recorded as {ROOT}; JSON escapes backslashes, so substitute the escaped form.
    return text.replace("{ROOT}", json.dumps(str(root))[1:-1]), root


def test_semgrep_contract() -> None:
    text, root = golden("semgrep", "vuln-express")
    findings = parse_semgrep(text, root, default_kb(), "express")
    rules = {f.rule_id for f in findings}
    assert {
        "SAST-CMDI-001",
        "SAST-EVAL-001",
        "SAST-CORS-001",
        "SAST-PROTO-001",
        "SAST-XSS-001",
    } <= rules
    assert all(f.source_tools == ["semgrep"] for f in findings)
    # "requires login" placeholder never becomes evidence; the real line is read from disk.
    assert all("requires login" not in (f.evidence.snippet or "") for f in findings)
    assert any("eval(" in (f.evidence.snippet or "") for f in findings)


def test_bandit_contract() -> None:
    text, root = golden("bandit", "vuln-flask")
    findings, unmapped = parse_bandit(text, root, default_kb(), ToolMap.load(), "flask")
    rules = {f.rule_id for f in findings}
    assert {"SAST-SQLI-001", "SAST-DEBUG-001", "SAST-HARDCODED-001"} <= rules
    assert unmapped == set()
    assert all(f.location.display().startswith(("app.py", "config.py")) for f in findings)


def test_bandit_output_never_leaks_secret_into_evidence() -> None:
    text, root = golden("bandit", "vuln-flask")
    findings, _ = parse_bandit(text, root, default_kb(), ToolMap.load(), None)
    dumped = "".join(f.model_dump_json() for f in findings)
    assert "supersecretkey123" not in dumped


def test_gitleaks_contract() -> None:
    text, root = golden("gitleaks", "vuln-flask")
    assert "REDACTED" in text
    findings = parse_gitleaks(text, root, default_kb(), None, history=False)
    assert {f.rule_id for f in findings} >= {"SECRET-CLOUD-001", "SECRET-TOKEN-001"}
    history = parse_gitleaks(text, root, default_kb(), None, history=True)
    assert {f.rule_id for f in history} == {"SECRET-HISTORY-001"}


def test_gitleaks_rule_mapping() -> None:
    assert gitleaks_rule("aws-access-token") == "SECRET-CLOUD-001"
    assert gitleaks_rule("private-key") == "SECRET-PRIVKEY-001"
    assert gitleaks_rule("jwt") == "SECRET-JWT-001"
    assert gitleaks_rule("generic-api-key") == "SECRET-GENERIC-001"
    assert gitleaks_rule("slack-bot-token") == "SECRET-TOKEN-001"


def test_trivy_contract() -> None:
    text, root = golden("trivy", "vuln-express")
    rows = parse_trivy(text, root)
    assert any(name == "lodash" and version == "4.17.15" for _eco, name, version, _m, _a in rows)
    assert {eco for eco, *_ in rows} == {"npm"}
    assert all(a.severity in {"critical", "high", "medium", "low"} for *_, a in rows)


def test_osv_contract_and_merge_with_trivy() -> None:
    osv_text, root = golden("osv-scanner", "vuln-flask")
    trivy_text, _ = golden("trivy", "vuln-flask")
    osv_rows = parse_osv(osv_text, root)
    trivy_rows = parse_trivy(trivy_text, root)
    assert any(name == "flask" for _e, name, *_ in osv_rows)
    assert {m for *_, m, _a in osv_rows} == {"requirements.txt"}

    pkg = VulnerablePackage("PyPI", "flask", "2.2.2", "requirements.txt")
    for eco, name, version, _m, adv in [*trivy_rows, *osv_rows]:
        if (eco, name.lower(), version) == ("PyPI", "flask", "2.2.2"):
            pkg.add(adv, "trivy" if adv.id.startswith("CVE") else "osv-scanner")
    # CVE ids from Trivy and PYSEC/GHSA ids from OSV describing the same issue are merged.
    assert pkg.tools == {"trivy", "osv-scanner"}
    assert len(pkg.advisories) < len(
        [r for r in [*trivy_rows, *osv_rows] if r[1].lower() == "flask"]
    )
