"""SEO module against the static fixtures (SPEC M6 acceptance)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import defusedxml.ElementTree as SafeET
import pytest

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.orchestrator import Orchestrator, ScanOutcome
from secscope.core.scan import run_scan
from secscope.core.session import open_session
from secscope.modules.base import ScanContext
from secscope.modules.registry import load_builtin
from tests.detection import FIXTURES, expected


def seo_scan(fixture: str, tmp_path: Path) -> tuple[ScanOutcome, ScanContext]:
    config = ScanConfig(
        target=Target(kind=TargetKind.FOLDER, value=str(FIXTURES / fixture)),
        scope_statement_accepted=True,
    )
    session = open_session(config, Settings(data_dir=tmp_path))
    try:
        outcome = asyncio.run(
            run_scan(Orchestrator(load_builtin(), lambda _e: None), session.ctx, ["seo"])
        )
    finally:
        session.close()
    return outcome, session.ctx


@pytest.fixture(scope="module")
def bad(tmp_path_factory: pytest.TempPathFactory) -> tuple[ScanOutcome, ScanContext]:
    return seo_scan("static-seo-bad", tmp_path_factory.mktemp("bad"))


@pytest.fixture(scope="module")
def good(tmp_path_factory: pytest.TempPathFactory) -> tuple[ScanOutcome, ScanContext]:
    return seo_scan("static-seo-good", tmp_path_factory.mktemp("good"))


def test_bad_site_finds_every_expected_problem(bad: tuple[ScanOutcome, ScanContext]) -> None:
    outcome, _ = bad
    must = set(expected("static-seo-bad")["seo"]["must"])
    found = {f.rule_id for f in outcome.findings}
    assert must - found == set()
    assert outcome.module_status["seo"] == "ok"


def test_bad_site_score_capped_by_index_blocker(bad: tuple[ScanOutcome, ScanContext]) -> None:
    _, ctx = bad
    score = ctx.results["seo"].data["seo_score"]
    assert score["capped_by_index_blocker"] is True
    assert score["score"] <= 40


def test_good_site_has_no_critical_or_high(good: tuple[ScanOutcome, ScanContext]) -> None:
    outcome, ctx = good
    severe = [
        (f.rule_id, f.evidence.snippet)
        for f in outcome.findings
        if f.severity in {"critical", "high"}
    ]
    assert severe == []
    assert ctx.results["seo"].data["seo_score"]["score"] >= 90
    assert ctx.results["seo"].data["production_origin"] == "https://www.example.com"


def test_generated_sitemap_is_valid_and_uses_public_urls(
    good: tuple[ScanOutcome, ScanContext],
) -> None:
    _, ctx = good
    generated = ctx.results["seo"].data["generated"]
    root = SafeET.fromstring(Path(generated["sitemap.xml"]).read_bytes())
    locs = sorted(n.text or "" for n in root.iter() if n.tag.endswith("loc"))
    assert locs == [
        "https://www.example.com/",
        "https://www.example.com/about.html",
        "https://www.example.com/blog/sourdough-starter-guide.html",
    ]
    robots = Path(generated["robots.txt"]).read_text(encoding="utf-8")
    assert "Sitemap: https://www.example.com/sitemap.xml" in robots


def test_every_request_stayed_in_scope(bad: tuple[ScanOutcome, ScanContext]) -> None:
    # The bad site links to https://example.com/; the crawler must not follow it.
    _, ctx = bad
    pages = ctx.results["seo"].data["pages"]
    assert all(p["url"].startswith("http://127.0.0.1:") for p in pages)
