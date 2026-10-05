from __future__ import annotations

import pytest

from secscope.analysis.seo import (
    Page,
    SeoIssue,
    SiteFacts,
    Sitemap,
    map_to_target,
    page_checks,
    parse_page,
    parse_sitemap,
    seo_score,
    site_checks,
    valid_lastmod,
)
from secscope.analysis.seo_generators import (
    jsonld_templates,
    robots_txt,
    sitemap_xml,
    title_suggestions,
)

GOOD_HTML = (
    """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>A good page title about sourdough bread baking</title>
<meta name="description" content="A friendly and complete guide to baking sourdough bread at home, step by step, for beginners.">
<link rel="canonical" href="https://www.example.com/x"><link rel="icon" href="/f.svg">
<meta property="og:title" content="t"><script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"n","url":"u"}</script>
</head><body><h1>Sourdough</h1><h2>Steps</h2><img src="/a.webp" alt="bread" width="10" height="10">
<p>"""
    + "word " * 150
    + """</p><a href="/about">About our bakery</a></body></html>"""
)


def page(html: str, url: str = "http://127.0.0.1:8000/x", status: int = 200) -> Page:
    return parse_page(
        Page(url=url, requested=url, status=status, content_type="text/html", html=html)
    )


def rules(issues: list[SeoIssue]) -> set[str]:
    return {i.rule_id for i in issues}


def test_good_page_is_clean() -> None:
    assert rules(page_checks(page(GOOD_HTML))) == set()


MUTATIONS: list[tuple[str, str, str]] = [
    ("<title>A good page title about sourdough bread baking</title>", "", "SEO-TITLE-001"),
    ("A good page title about sourdough bread baking", "Hi", "SEO-TITLE-003"),
    ('<meta name="description"', '<meta name="x"', "SEO-DESC-001"),
    ("<h1>Sourdough</h1>", "", "SEO-H1-001"),
    ("<h2>Steps</h2>", "<h4>Steps</h4>", "SEO-H1-001"),
    ('<meta name="viewport" content="width=device-width, initial-scale=1">', "", "SEO-VIEWPORT-001"),
    (' lang="en"', "", "SEO-LANG-001"),
    (' alt="bread"', "", "SEO-IMG-001"),
    (' width="10" height="10"', "", "SEO-IMG-002"),
    ("<h1>Sourdough</h1>", '<img src="/hero.png" alt="h" width="1" height="1" loading="lazy"><h1>Sourdough</h1>', "SEO-IMG-003"),
    ("About our bakery", "click here", "SEO-LINK-001"),
    ("word " * 150, "short", "SEO-THIN-001"),
    ("</head>", '<script src="/x.js"></script></head>', "SEO-RENDERBLOCK-001"),
    ('<meta property="og:title" content="t">', "", "SEO-OG-001"),
    ('"@type":"WebSite","name":"n","url":"u"}', '"@type":"WebSite"}', "SEO-JSONLD-002"),
    ('{"@context"', '{bad json "@context"', "SEO-JSONLD-001"),
]  # fmt: skip


@pytest.mark.parametrize(("old", "new", "rule"), MUTATIONS)
def test_page_rule_triggers(old: str, new: str, rule: str) -> None:
    assert old in GOOD_HTML
    assert rule in rules(page_checks(page(GOOD_HTML.replace(old, new))))


def test_decorative_empty_alt_is_fine() -> None:
    p = page(GOOD_HTML.replace('alt="bread"', 'alt=""'))
    assert "SEO-IMG-001" not in rules(page_checks(p))


def test_noindex_detection_from_header() -> None:
    p = page(GOOD_HTML)
    p.headers["x-robots-tag"] = "noindex, nofollow"
    assert p.noindex


def site(pages: list[Page], **kw: object) -> SiteFacts:
    defaults: dict[str, object] = {
        "target_origin": "http://127.0.0.1:8000", "home": "http://127.0.0.1:8000/", "pages": pages,
        "robots_status": 200, "robots_text": "", "robots_disallow_all": False,
        "sitemaps": [Sitemap("u", 200, [("https://www.example.com/x", "2026-01-01")])],
        "sitemap_declared": True, "not_found_status": 404, "production_origin": "https://www.example.com",
    }  # fmt: skip
    defaults.update(kw)
    return SiteFacts(**defaults)  # type: ignore[arg-type]


def test_site_level_rules() -> None:
    home = page(GOOD_HTML, "http://127.0.0.1:8000/")
    assert "SEO-ROBOTS-002" in rules(site_checks(site([home], robots_disallow_all=True)))
    assert "SEO-ROBOTS-001" in rules(site_checks(site([home], robots_status=404)))
    assert "SEO-404PAGE-001" in rules(site_checks(site([home], not_found_status=200)))
    assert "SEO-SITEMAP-001" in rules(site_checks(site([home], sitemaps=[])))
    assert "SEO-SITEMAP-001" in rules(site_checks(site([home], sitemap_declared=False)))
    dup = page(GOOD_HTML, "http://127.0.0.1:8000/y")
    assert "SEO-TITLE-002" in rules(site_checks(site([home, dup])))
    noindex_home = page(
        GOOD_HTML.replace("</head>", '<meta name="robots" content="noindex"></head>'),
        "http://127.0.0.1:8000/",
    )
    crit = [i for i in site_checks(site([noindex_home])) if i.rule_id == "SEO-NOINDEX-001"]
    assert crit
    assert crit[0].severity is None  # KB default (critical) for important pages


def test_redirect_and_soft404() -> None:
    p = page(
        GOOD_HTML.replace("A good page title about sourdough bread baking", "Page not found"),
        "http://127.0.0.1:8000/gone",
    )
    p.redirects = [(302, "/a"), (301, "/b")]
    found = rules(site_checks(site([p])))
    assert {"SEO-REDIRECT-001", "SEO-SOFT404-001"} <= found


def test_sitemap_parsing() -> None:
    body = b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://a.example/</loc><lastmod>2026-01-02</lastmod></url><url><loc>/rel</loc></url></urlset>'
    sm = parse_sitemap("u", 200, body)
    assert sm.urls == [("https://a.example/", "2026-01-02"), ("/rel", None)]
    assert parse_sitemap("u", 200, b"<urlset>").error is not None
    assert parse_sitemap("u", 404, b"").error == "HTTP 404"
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><urlset>&a;</urlset>'
    assert parse_sitemap("u", 200, bomb).error is not None  # entities refused (defusedxml)


@pytest.mark.parametrize(
    ("value", "ok"),
    [("2026-03-10", True), ("2026-03-10T12:00:00+00:00", True), ("not-a-date", False)],
)
def test_lastmod(value: str, ok: bool) -> None:
    assert valid_lastmod(value) is ok


def test_map_to_target() -> None:
    assert (
        map_to_target("https://www.example.com/a/b?x=1", "http://127.0.0.1:9000")
        == "http://127.0.0.1:9000/a/b?x=1"
    )


def test_seo_score_weights_and_cap() -> None:
    defaults = {"SEO-ROBOTS-002": "critical", "SEO-TITLE-001": "high"}
    assert seo_score({}, defaults)["score"] == 100.0
    capped = seo_score({"SEO-ROBOTS-002": "critical"}, defaults)
    assert capped["capped_by_index_blocker"] is True
    assert capped["score"] <= 40
    assert seo_score({"SEO-TITLE-001": "high"}, defaults)["subscores"]["on_page"] < 100


def test_generators() -> None:
    home = page(GOOD_HTML, "http://127.0.0.1:8000/")
    hidden = page(
        GOOD_HTML.replace("</head>", '<meta name="robots" content="noindex"></head>'),
        "http://127.0.0.1:8000/private",
    )
    xml = sitemap_xml([home, hidden], "https://www.example.com")
    assert "https://www.example.com/x" in xml  # canonical used
    assert "/private" not in xml
    assert "Disallow: /" in robots_txt("https://a.example", ai_crawlers={"GPTBot": False})
    assert '"@type": "Organization"' in jsonld_templates(home, "https://a.example")
    no_title = page(
        GOOD_HTML.replace("<title>A good page title about sourdough bread baking</title>", "")
    )
    suggestion = title_suggestions([no_title], "Example Bakery")
    assert suggestion[0]["proposal"] == "Sourdough – Example Bakery"
