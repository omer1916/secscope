"""Static detection rate on the fixtures (SPEC M3 acceptance).

* recall over all `must` rules of the vulnerable fixtures >= 90 %
* clean fixtures: findings outside `allowed` <= 5 % of the rule catalogue
* `needs_db` rules are only checked when an offline vulnerability DB is installed
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscope.analysis.kb import default_kb
from tests.detection import expected, found_rules, run_static, vulnerability_db_present

VULNERABLE = ["vuln-flask", "vuln-express", "vuln-php", "slow-app"]
CLEAN = ["clean-flask", "clean-express", "static-seo-good"]

_results: dict[str, tuple[set[str], set[str]]] = {}


@pytest.mark.parametrize("fixture", VULNERABLE)
def test_vulnerable_fixture_recall(fixture: str, tmp_path: Path) -> None:
    spec = expected(fixture)["static"]
    must = set(spec.get("must", []))
    if vulnerability_db_present():
        must |= set(spec.get("needs_db", []))
    run = run_static(fixture, tmp_path)
    found = found_rules(run.findings)
    _results[fixture] = (must, found)
    missing = must - found
    # Per fixture we allow at most one miss; the overall bar is checked below.
    assert len(missing) <= max(1, len(must) // 10), f"{fixture} missed {sorted(missing)}"


def test_overall_recall_at_least_90_percent() -> None:
    if len(_results) < len(VULNERABLE):
        pytest.skip("run together with test_vulnerable_fixture_recall")
    total = sum(len(m) for m, _ in _results.values())
    hit = sum(len(m & f) for m, f in _results.values())
    assert hit / total >= 0.90, f"recall {hit}/{total}"


@pytest.mark.parametrize("fixture", CLEAN)
def test_clean_fixture_false_positive_budget(fixture: str, tmp_path: Path) -> None:
    spec = expected(fixture)["static"]
    allowed = set(spec.get("allowed", []))
    run = run_static(fixture, tmp_path)
    false_positives = [f for f in run.findings if f.rule_id not in allowed and f.severity != "info"]
    budget = int(len(default_kb().entries) * 0.05)
    assert len(false_positives) <= budget, [
        (f.rule_id, f.location.display(), f.evidence.snippet) for f in false_positives
    ]
