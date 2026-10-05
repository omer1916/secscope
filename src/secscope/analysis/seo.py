"""Technical SEO analysis over crawled pages (SPEC §7). Pure functions — no network.

The crawler (``modules/seo.py``) produces :class:`Page` objects; :func:`site_checks`
turns them into :class:`SeoIssue` items mapped to KB rule ids. Thresholds are hints, not
Google rules (Google publishes no hard title/description limits).
"""

from __future__ import annotations

import itertools
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from selectolax.lexbor import LexborHTMLParser

TITLE_MIN, TITLE_MAX = 30, 60
DESC_MIN, DESC_MAX = 70, 160
THIN_WORDS = 100
# The first image counts as the likely LCP element only if it sits in the top part of the HTML.
LCP_REGION = 0.4
BIG_IMAGE_BYTES = 300 * 1024
MAX_CLICK_DEPTH = 4
SITEMAP_MAX_URLS = 50_000
SITEMAP_MAX_BYTES = 50 * 1024 * 1024
SOFT_404 = re.compile(r"(?i)\b(?:page not found|not found|404|sayfa bulunamad[ıi]|bulunamad[ıi])\b")
WEAK_ANCHOR = re.compile(
    r"(?i)^(?:click here|here|read more|more|link|this|buraya t[ıi]klay[ıi]n|t[ıi]klay[ıi]n|devam[ıi]|burada)$"
)
MODERN_IMAGE = (".webp", ".avif", ".svg")
# Required/recommended properties per schema.org type for Google rich results (subset).
JSONLD_REQUIRED: dict[str, tuple[str, ...]] = {
    "Organization": ("name", "url"),
    "WebSite": ("name", "url"),
    "Article": ("headline", "datePublished", "author"),
    "BlogPosting": ("headline", "datePublished", "author"),
    "NewsArticle": ("headline", "datePublished", "author"),
    "Product": ("name", "offers"),
    "BreadcrumbList": ("itemListElement",),
    "LocalBusiness": ("name", "address"),
    "Event": ("name", "startDate", "location"),
}


@dataclass
class Image:
    src: str
    alt: str | None
    has_dimensions: bool
    lazy: bool
    size: int | None = None
    # Position of the tag in the HTML (0..1); LCP candidates sit near the top.
    position: float = 0.0


@dataclass
class Page:
    url: str  # final URL on the target (after redirects)
    requested: str
    status: int
    content_type: str = ""
    redirects: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])
    headers: dict[str, str] = field(default_factory=dict[str, str])
    depth: int = 0
    html: str = ""
    # parsed
    title: str | None = None
    titles: int = 0
    description: str | None = None
    robots_meta: str = ""
    canonicals: list[str] = field(default_factory=list[str])
    lang: str | None = None
    charset: bool = False
    viewport: str | None = None
    h: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])
    images: list[Image] = field(default_factory=list[Image])
    links: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])  # (href, text)
    words: int = 0
    og: dict[str, str] = field(default_factory=dict[str, str])
    jsonld: list[Any] = field(default_factory=list[Any])
    jsonld_errors: int = 0
    blocking_scripts: int = 0
    favicon: bool = False
    robots_blocked: bool = False

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or (
            not self.content_type and "<html" in self.html[:500].lower()
        )

    @property
    def noindex(self) -> bool:
        directives = f"{self.robots_meta},{self.headers.get('x-robots-tag', '')}".lower()
        return "noindex" in directives or "none" in [d.strip() for d in directives.split(",")]

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"


def parse_page(page: Page) -> Page:
    tree = LexborHTMLParser(page.html)
    titles = tree.css("head title") or tree.css("title")
    page.titles = len(titles)
    page.title = titles[0].text(strip=True) if titles else None
    html_node = tree.css_first("html")
    page.lang = (html_node.attributes.get("lang") or None) if html_node else None
    for meta in tree.css("meta"):
        a = meta.attributes
        name = (a.get("name") or "").lower()
        prop = (a.get("property") or "").lower()
        if "charset" in a or (a.get("http-equiv") or "").lower() == "content-type":
            page.charset = True
        if name == "description":
            page.description = (a.get("content") or "").strip()
        elif name in {"robots", "googlebot"}:
            page.robots_meta += "," + (a.get("content") or "")
        elif name == "viewport":
            page.viewport = a.get("content") or ""
        if prop.startswith("og:") or name.startswith("twitter:"):
            page.og[prop or name] = a.get("content") or ""
    for link in tree.css("link"):
        rel = (link.attributes.get("rel") or "").lower().split()
        if "canonical" in rel:
            page.canonicals.append(link.attributes.get("href") or "")
        if "icon" in rel:
            page.favicon = True
    for level in range(1, 7):
        for node in tree.css(f"h{level}"):
            page.h.append((level, node.text(strip=True)))
    page.h.sort(key=lambda x: page.html.find(x[1]) if x[1] else 0)
    length = max(len(page.html), 1)
    for img in tree.css("img"):
        a = img.attributes
        raw_src = a.get("src") or ""
        page.images.append(
            Image(
                src=urljoin(page.url, a.get("src") or ""),
                # alt="" (decorative) is valid; only a missing attribute is a problem.
                alt=(a.get("alt") or "") if "alt" in a else None,
                has_dimensions="width" in a and "height" in a,
                lazy=(a.get("loading") or "").lower() == "lazy",
                position=(page.html.find(raw_src) / length) if raw_src else 1.0,
            )
        )
    for anchor in tree.css("a"):
        page.links.append((anchor.attributes.get("href") or "", anchor.text(strip=True)))
    for script in tree.css('script[type="application/ld+json"]'):
        try:
            page.jsonld.append(json.loads(script.text() or ""))
        except ValueError:
            page.jsonld_errors += 1
    head = tree.css_first("head")
    if head is not None:
        for script in head.css("script[src]"):
            a = script.attributes
            if "async" not in a and "defer" not in a and (a.get("type") or "") != "module":
                page.blocking_scripts += 1
    body = tree.body
    for node in tree.css("script, style, noscript"):
        node.decompose()
    text = body.text(separator=" ", strip=True) if body is not None else ""
    page.words = len(re.findall(r"\w+", text))
    return page


@dataclass(frozen=True, slots=True)
class SeoIssue:
    rule_id: str
    url: str
    detail: str
    severity: str | None = None  # override of the KB default
    count: int = 1


@dataclass
class Sitemap:
    url: str
    status: int
    urls: list[tuple[str, str | None]] = field(
        default_factory=list[tuple[str, str | None]]
    )  # (loc, lastmod)
    error: str | None = None
    size: int = 0


def parse_sitemap(url: str, status: int, body: bytes) -> Sitemap:
    sm = Sitemap(url=url, status=status, size=len(body))
    if status != 200:
        sm.error = f"HTTP {status}"
        return sm
    try:
        root: Element = SafeET.fromstring(body)
    except Exception as exc:  # defusedxml raises several types (DTD, entities, syntax)
        sm.error = f"invalid XML: {type(exc).__name__}"
        return sm
    for node in root.iter():
        if node.tag.endswith("}url") or node.tag == "url" or node.tag.endswith("}sitemap"):
            loc = next((c.text or "" for c in node if c.tag.endswith("loc")), "").strip()
            lastmod = next((c.text for c in node if c.tag.endswith("lastmod")), None)
            if loc:
                sm.urls.append((loc, lastmod.strip() if lastmod else None))
    return sm


def valid_lastmod(value: str) -> bool:
    try:
        date.fromisoformat(value[:10])
    except ValueError:
        return False
    return True


def map_to_target(url: str, target_origin: str) -> str:
    """Map a production URL (https://www.example.com/a) onto the local target (http://127.0.0.1:p/a)."""
    parts = urlsplit(url)
    t = urlsplit(target_origin)
    return urlunsplit((t.scheme, t.netloc, parts.path or "/", parts.query, ""))


def jsonld_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [i for d in data for i in jsonld_items(d)]  # pyright: ignore[reportUnknownVariableType]
    if isinstance(data, dict):
        graph = data.get("@graph")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
        return jsonld_items(graph) if graph else [data]  # pyright: ignore[reportUnknownArgumentType]
    return []


def page_checks(page: Page, *, first_image_is_hero: bool = True) -> list[SeoIssue]:
    """Checks that look at one page in isolation."""
    out: list[SeoIssue] = []
    u = page.url
    if not page.title:
        out.append(SeoIssue("SEO-TITLE-001", u, "missing or empty <title>"))
    elif not TITLE_MIN <= len(page.title) <= TITLE_MAX:
        out.append(
            SeoIssue(
                "SEO-TITLE-003",
                u,
                f"title is {len(page.title)} characters (hint: ~{TITLE_MIN}–{TITLE_MAX})",
            )
        )
    if page.titles > 1:
        out.append(SeoIssue("SEO-TITLE-001", u, f"{page.titles} <title> elements"))
    if page.description is None or not page.description:
        out.append(SeoIssue("SEO-DESC-001", u, "missing meta description"))
    elif not DESC_MIN <= len(page.description) <= DESC_MAX:
        out.append(
            SeoIssue(
                "SEO-DESC-001",
                u,
                f"description is {len(page.description)} characters (hint: ~{DESC_MIN}–{DESC_MAX})",
                "low",
            )
        )
    h1 = [t for lvl, t in page.h if lvl == 1]
    if len(h1) != 1 or not h1[0]:
        out.append(
            SeoIssue(
                "SEO-H1-001",
                u,
                f"{len(h1)} <h1> element(s)" + (" (empty)" if h1 and not all(h1) else ""),
            )
        )
    levels = [lvl for lvl, _ in page.h]
    if any(b - a > 1 for a, b in itertools.pairwise(levels)):
        out.append(SeoIssue("SEO-H1-001", u, "heading levels skip (e.g. h2 → h4)", "low"))
    if not page.viewport or "width=device-width" not in page.viewport.replace(" ", ""):
        out.append(SeoIssue("SEO-VIEWPORT-001", u, "no responsive viewport meta tag"))
    if not page.lang or not page.charset:
        missing = [n for n, ok in (("<html lang>", page.lang), ("charset", page.charset)) if not ok]
        out.append(SeoIssue("SEO-LANG-001", u, "missing " + ", ".join(missing)))
    no_alt = [i for i in page.images if i.alt is None]
    if no_alt:
        out.append(
            SeoIssue(
                "SEO-IMG-001",
                u,
                f"{len(no_alt)} image(s) without alt: {no_alt[0].src}",
                count=len(no_alt),
            )
        )
    no_dims = [i for i in page.images if not i.has_dimensions]
    if no_dims:
        out.append(
            SeoIssue(
                "SEO-IMG-002",
                u,
                f"{len(no_dims)} image(s) without width/height (layout shift)",
                count=len(no_dims),
            )
        )
    if (
        first_image_is_hero
        and page.images
        and page.images[0].lazy
        and page.images[0].position <= LCP_REGION
    ):
        out.append(
            SeoIssue(
                "SEO-IMG-003", u, f"first (likely LCP) image is lazy-loaded: {page.images[0].src}"
            )
        )
    big = [i for i in page.images if i.size is not None and i.size > BIG_IMAGE_BYTES]
    if big:
        kb = big[0].size // 1024 if big[0].size else 0
        out.append(
            SeoIssue(
                "SEO-IMG-004",
                u,
                f"{len(big)} image(s) over {BIG_IMAGE_BYTES // 1024} KB, e.g. {big[0].src} ({kb} KB)",
                count=len(big),
            )
        )
    elif any(
        i.size and not i.src.lower().split("?")[0].endswith(MODERN_IMAGE) and i.size > 100 * 1024
        for i in page.images
    ):
        out.append(
            SeoIssue("SEO-IMG-004", u, "large images not in a modern format (WebP/AVIF)", "info")
        )
    weak = [
        (h, t)
        for h, t in page.links
        if not h.strip()
        or h.strip() == "#"
        or h.strip().lower().startswith("javascript:")
        or WEAK_ANCHOR.match(t or "")
        or not (t or "").strip()
    ]
    if weak:
        out.append(
            SeoIssue(
                "SEO-LINK-001",
                u,
                f"{len(weak)} link(s) with empty/'#'/javascript: targets or weak anchor text, e.g. {weak[0][1] or weak[0][0]!r}",
                count=len(weak),
            )
        )
    if page.words < THIN_WORDS and not page.noindex:
        out.append(SeoIssue("SEO-THIN-001", u, f"only {page.words} words of text"))
    if page.blocking_scripts:
        out.append(
            SeoIssue(
                "SEO-RENDERBLOCK-001",
                u,
                f"{page.blocking_scripts} render-blocking <script> in <head> (no async/defer)",
            )
        )
    if not any(k.startswith("og:") for k in page.og):
        out.append(
            SeoIssue("SEO-OG-001", u, "no Open Graph tags (og:title, og:description, og:image)")
        )
    if page.jsonld_errors:
        out.append(
            SeoIssue(
                "SEO-JSONLD-001", u, f"{page.jsonld_errors} JSON-LD block(s) are not valid JSON"
            )
        )
    for item in (i for d in page.jsonld for i in jsonld_items(d)):
        types = item.get("@type")
        for t in [types] if isinstance(types, str) else (types or []):
            missing = [p for p in JSONLD_REQUIRED.get(str(t), ()) if p not in item]
            if missing:
                out.append(SeoIssue("SEO-JSONLD-002", u, f"{t} is missing {', '.join(missing)}"))
    return out


@dataclass
class SiteFacts:
    target_origin: str
    home: str
    pages: list[Page]
    robots_status: int | None
    robots_text: str
    robots_disallow_all: bool
    sitemaps: list[Sitemap]
    sitemap_declared: bool
    not_found_status: int | None  # status of a random non-existent URL
    production_origin: str | None = None
    sitemap_pages: dict[str, Page] = field(default_factory=dict[str, Page])


def site_checks(site: SiteFacts) -> list[SeoIssue]:
    out: list[SeoIssue] = []
    home = site.home
    html_pages = [p for p in site.pages if p.status == 200 and p.is_html]
    # robots.txt
    if site.robots_status != 200:
        out.append(
            SeoIssue(
                "SEO-ROBOTS-001",
                urljoin(home, "/robots.txt"),
                f"robots.txt returned {site.robots_status}",
            )
        )
    if site.robots_disallow_all:
        out.append(
            SeoIssue(
                "SEO-ROBOTS-002",
                urljoin(home, "/robots.txt"),
                "robots.txt blocks the whole site for Googlebot (Disallow: /)",
            )
        )
    blocked = [p for p in html_pages if p.robots_blocked]
    if blocked and not site.robots_disallow_all:
        out.append(
            SeoIssue(
                "SEO-BLOCKED-001",
                blocked[0].url,
                f"{len(blocked)} page(s) blocked by robots.txt; Google cannot read their content or noindex",
                count=len(blocked),
            )
        )
    # sitemap
    sitemap_urls = {
        map_to_target(loc, site.target_origin) for sm in site.sitemaps for loc, _ in sm.urls
    }
    if not site.sitemaps or all(sm.error for sm in site.sitemaps):
        out.append(
            SeoIssue("SEO-SITEMAP-001", urljoin(home, "/sitemap.xml"), "no readable sitemap.xml")
        )
    elif not site.sitemap_declared:
        out.append(
            SeoIssue(
                "SEO-SITEMAP-001",
                urljoin(home, "/robots.txt"),
                "sitemap is not declared in robots.txt (Sitemap: line)",
                "medium",
            )
        )
    for sm in site.sitemaps:
        if sm.error and sm.status == 200:
            out.append(SeoIssue("SEO-SITEMAP-002", sm.url, sm.error))
            continue
        relative = [loc for loc, _ in sm.urls if not urlsplit(loc).scheme]
        if relative:
            out.append(
                SeoIssue(
                    "SEO-SITEMAP-002",
                    sm.url,
                    f"{len(relative)} <loc> value(s) are not absolute URLs, e.g. {relative[0]}",
                )
            )
        bad_dates = [m for _, m in sm.urls if m and not valid_lastmod(m)]
        if bad_dates:
            out.append(
                SeoIssue(
                    "SEO-SITEMAP-002",
                    sm.url,
                    f"invalid <lastmod> value(s), e.g. {bad_dates[0]!r}",
                    "low",
                )
            )
        if len(sm.urls) > SITEMAP_MAX_URLS or sm.size > SITEMAP_MAX_BYTES:
            out.append(
                SeoIssue(
                    "SEO-SITEMAP-002",
                    sm.url,
                    "sitemap exceeds 50,000 URLs or 50 MB; split it with a sitemap index",
                )
            )
    bad_entries: list[str] = []
    for url, page in site.sitemap_pages.items():
        if page.status != 200 or page.redirects or page.noindex:
            reason = (
                f"{page.status}"
                if page.status != 200
                else ("redirect" if page.redirects else "noindex")
            )
            bad_entries.append(f"{urlsplit(url).path} ({reason})")
    if bad_entries:
        out.append(
            SeoIssue(
                "SEO-SITEMAP-003",
                urljoin(home, "/sitemap.xml"),
                "sitemap lists URLs that are not indexable 200 pages: "
                + ", ".join(bad_entries[:10]),
                count=len(bad_entries),
            )
        )
    # status codes, redirects, soft 404
    crawled = {id(x) for x in site.pages}
    every_page = site.pages + [x for x in site.sitemap_pages.values() if id(x) not in crawled]
    for p in every_page:
        if p.status >= 400 and urlsplit(p.requested).path not in {
            urlsplit(u).path for u in sitemap_urls
        }:
            out.append(
                SeoIssue("SEO-STATUS-001", p.requested, f"internal link returns HTTP {p.status}")
            )
        if len(p.redirects) > 1 or any(code in (302, 303, 307) for code, _ in p.redirects):
            chain = " → ".join(f"{loc} ({code})" for code, loc in p.redirects)
            out.append(
                SeoIssue(
                    "SEO-REDIRECT-001", p.requested, f"{len(p.redirects)} redirect hop(s): {chain}"
                )
            )
        if (
            p.status == 200
            and p.is_html
            and (
                SOFT_404.search(p.title or "")
                or any(SOFT_404.search(t) for lvl, t in p.h if lvl == 1)
            )
        ):
            out.append(
                SeoIssue(
                    "SEO-SOFT404-001",
                    p.requested,
                    f"returns 200 but reads like an error page: {p.title!r}",
                )
            )
    if site.not_found_status is not None and site.not_found_status != 404:
        out.append(
            SeoIssue(
                "SEO-404PAGE-001",
                home,
                f"a non-existent URL returns {site.not_found_status} instead of 404",
            )
        )
    # noindex on important pages
    important = {home, *sitemap_urls} | {p.url for p in html_pages if p.depth <= 1}
    for p in html_pages:
        if p.noindex:
            crit = p.url in important or p.requested in important
            out.append(
                SeoIssue(
                    "SEO-NOINDEX-001",
                    p.url,
                    "page is marked noindex (meta robots / X-Robots-Tag)",
                    None if crit else "medium",
                )
            )
    # canonical
    for p in html_pages:
        if p.noindex:
            continue
        if not p.canonicals:
            out.append(SeoIssue("SEO-CANONICAL-001", p.url, "no rel=canonical", "medium"))
            continue
        if len(set(p.canonicals)) > 1:
            out.append(
                SeoIssue(
                    "SEO-CANONICAL-001", p.url, f"{len(p.canonicals)} different canonical tags"
                )
            )
            continue
        canon = p.canonicals[0]
        if not urlsplit(canon).scheme:
            out.append(
                SeoIssue(
                    "SEO-CANONICAL-001",
                    p.url,
                    f"canonical is not an absolute URL: {canon}",
                    "medium",
                )
            )
        elif site.production_origin and urlsplit(canon).netloc not in {
            urlsplit(site.production_origin).netloc,
            urlsplit(site.target_origin).netloc,
        }:
            out.append(
                SeoIssue("SEO-CANONICAL-001", p.url, f"canonical points to another site: {canon}")
            )
    # duplicates across pages
    indexable = [p for p in html_pages if not p.noindex]
    for rule, values in (
        ("SEO-TITLE-002", [p.title for p in indexable]),
        ("SEO-DESC-001", [p.description for p in indexable]),
    ):
        counts = Counter(v for v in values if v)
        for value, n in counts.items():
            if n > 1:
                dupes = [
                    p.url
                    for p in indexable
                    if (p.title if rule == "SEO-TITLE-002" else p.description) == value
                ]
                out.append(
                    SeoIssue(
                        rule,
                        dupes[0],
                        f"{n} pages share the same {'title' if rule == 'SEO-TITLE-002' else 'description'}: {value!r}",
                        None if rule == "SEO-TITLE-002" else "low",
                        count=n,
                    )
                )
    # click depth / orphans
    deep = [p for p in html_pages if p.depth > MAX_CLICK_DEPTH]
    if deep:
        out.append(
            SeoIssue(
                "SEO-DEPTH-001",
                deep[0].url,
                f"{len(deep)} page(s) more than {MAX_CLICK_DEPTH} clicks from the home page",
                count=len(deep),
            )
        )
    linked = {p.url for p in site.pages}
    orphans = [
        u
        for u in sitemap_urls
        if u not in linked
        and site.sitemap_pages.get(u) is not None
        and site.sitemap_pages[u].status == 200
        and site.sitemap_pages[u].depth < 0
    ]
    if orphans:
        out.append(
            SeoIssue(
                "SEO-DEPTH-001",
                orphans[0],
                f"{len(orphans)} sitemap page(s) receive no internal links (orphans)",
                count=len(orphans),
            )
        )
    # URL hygiene
    ugly = [
        p.url
        for p in html_pages
        if re.search(
            r"[A-Z_]|;jsessionid|[?&](?:sid|sessionid|phpsessid)=",
            urlsplit(p.url).path + "?" + urlsplit(p.url).query,
        )
        or len(p.url) > 115
    ]
    if ugly:
        out.append(
            SeoIssue(
                "SEO-URL-001",
                ugly[0],
                f"{len(ugly)} URL(s) with upper case, underscores, session ids or excessive length",
                count=len(ugly),
            )
        )
    # site-wide structured data / favicon
    if html_pages and not any(p.jsonld for p in html_pages):
        out.append(SeoIssue("SEO-JSONLD-003", home, "no structured data (JSON-LD) on any page"))
    home_page = next((p for p in html_pages if p.url == home or p.path == "/"), None)
    if home_page is not None and not home_page.favicon:
        out.append(SeoIssue("SEO-FAVICON-001", home, "no <link rel=icon> on the home page"))
    for p in html_pages:
        out.extend(page_checks(p))
    return out


# --------------------------------------------------------------------- score

# Sub-categories and weights (SPEC §9 / §7.3). Performance here is a *heuristic* (static
# signals) until lab Core Web Vitals are measured; it is labelled as such in the report.
SEO_CATEGORIES: dict[str, tuple[float, tuple[str, ...]]] = {
    "crawl_index": (30, ("SEO-ROBOTS-001", "SEO-ROBOTS-002", "SEO-BLOCKED-001", "SEO-NOINDEX-001", "SEO-SITEMAP-001", "SEO-SITEMAP-002", "SEO-SITEMAP-003", "SEO-STATUS-001", "SEO-SOFT404-001", "SEO-REDIRECT-001", "SEO-CANONICAL-001", "SEO-404PAGE-001", "SEO-DEPTH-001", "SEO-URL-001")),
    "on_page": (25, ("SEO-TITLE-001", "SEO-TITLE-002", "SEO-TITLE-003", "SEO-DESC-001", "SEO-H1-001", "SEO-LANG-001", "SEO-IMG-001", "SEO-LINK-001", "SEO-THIN-001", "SEO-FAVICON-001")),
    "structured_data": (10, ("SEO-OG-001", "SEO-JSONLD-001", "SEO-JSONLD-002", "SEO-JSONLD-003")),
    "performance": (25, ("SEO-IMG-002", "SEO-IMG-003", "SEO-IMG-004", "SEO-RENDERBLOCK-001")),
    "mobile": (10, ("SEO-VIEWPORT-001",)),
}  # fmt: skip
CHECK_WEIGHT = {"critical": 25.0, "high": 10.0, "medium": 4.0, "low": 1.0, "info": 0.5}
INDEX_BLOCKERS = ("SEO-ROBOTS-002", "SEO-NOINDEX-001")


def seo_score(failed: dict[str, str], default_severity: dict[str, str]) -> dict[str, Any]:
    """failed: rule_id -> worst severity seen. Returns sub-scores, total and cap info."""
    subs: dict[str, float] = {}
    total = 0.0
    for name, (weight, rules) in SEO_CATEGORIES.items():
        weights = {r: CHECK_WEIGHT[default_severity.get(r, "medium")] for r in rules}
        lost = sum(CHECK_WEIGHT[failed[r]] if r in failed else 0 for r in rules)
        possible = sum(weights.values()) + sum(
            max(0.0, CHECK_WEIGHT[failed[r]] - weights[r]) for r in rules if r in failed
        )
        subs[name] = round(100 * (1 - lost / possible), 1) if possible else 100.0
        total += subs[name] * weight
    score = round(total / sum(w for w, _ in SEO_CATEGORIES.values()), 1)
    capped = any(failed.get(r) == "critical" for r in INDEX_BLOCKERS)
    if capped:
        score = min(score, 40.0)
    return {
        "score": score,
        "subscores": subs,
        "capped_by_index_blocker": capped,
        "performance_basis": "heuristic",
    }
