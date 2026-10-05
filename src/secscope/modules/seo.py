"""SEO and Google visibility module (SPEC §7): crawl the local target like Googlebot and
check launch readiness. Google cannot crawl localhost — this measures *technical readiness*,
not rankings; the report says so.

All requests go through the scope guard (``ctx.http_client``) at the configured rate.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import ClassVar
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from protego import Protego

from secscope.analysis.kb import default_kb
from secscope.analysis.seo import (
    Page,
    SeoIssue,
    SiteFacts,
    Sitemap,
    map_to_target,
    parse_page,
    parse_sitemap,
    seo_score,
    site_checks,
)
from secscope.analysis.seo_generators import (
    jsonld_templates,
    robots_txt,
    sitemap_xml,
    title_suggestions,
)
from secscope.core.models import Category, Evidence, Finding, HttpLocation, LocalizedStr
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext

GOOGLEBOT_SMARTPHONE = (
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.6478.126 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
MAX_PAGES = 500
MAX_DEPTH = 10
MAX_HTML_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PROBES = 200
CONCURRENCY = 4
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / rps
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _normalise(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def _is_local(url: str) -> bool:
    return (urlsplit(url).hostname or "") in LOCAL_HOSTS or (urlsplit(url).hostname or "").endswith(
        ".localhost"
    )


class SeoModule(BaseModule):
    id: ClassVar[str] = "seo"
    title: ClassVar[LocalizedStr] = LocalizedStr(
        tr="SEO ve Google görünürlüğü", en="SEO and Google visibility"
    )
    category: ClassVar[Category] = Category.SEO
    requires: ClassVar[Requirements] = Requirements(target_running=True)
    timeout_s: ClassVar[float] = 30 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        assert ctx.target_url is not None
        target = _origin(ctx.target_url)
        home = _normalise(urljoin(target, "/"))
        limiter = RateLimiter(ctx.settings.rate_limits.dast_rps)
        result = ModuleResult()
        async with ctx.http_client(
            headers={"User-Agent": GOOGLEBOT_SMARTPHONE}, timeout=20
        ) as client:

            async def get(url: str, *, method: str = "GET") -> httpx.Response | None:
                await limiter.wait()
                try:
                    return await client.request(method, url)
                except httpx.HTTPError as exc:
                    emit.log(f"fetch failed: {url}: {type(exc).__name__}", "debug")
                    return None

            # robots.txt
            robots = await get(urljoin(target, "/robots.txt"))
            robots_status = robots.status_code if robots is not None else None
            robots_text = robots.text if robots is not None and robots.status_code == 200 else ""
            parser = Protego.parse(robots_text) if robots_text else None
            disallow_all = parser is not None and not parser.can_fetch(
                urljoin(target, "/"), "Googlebot"
            )
            declared = list(parser.sitemaps) if parser is not None else []
            production = ctx.config.public_url or next(
                (u for u in declared if not _is_local(u)), None
            )
            production_origin = _origin(production) if production else None

            # sitemaps (and sitemap indexes, one level)
            sitemaps: list[Sitemap] = []
            queue = [map_to_target(u, target) for u in declared] or [
                urljoin(target, "/sitemap.xml")
            ]
            for sm_url in queue[:20]:
                r = await get(sm_url)
                sm = parse_sitemap(
                    sm_url,
                    r.status_code if r is not None else 0,
                    r.content if r is not None else b"",
                )
                if r is not None and r.status_code == 404 and not declared:
                    break
                sitemaps.append(sm)
                if r is not None and b"<sitemapindex" in r.content[:2000]:
                    queue.extend(
                        map_to_target(loc, target) for loc, _ in sm.urls if loc.endswith(".xml")
                    )
                    sm.urls = []
            if production_origin is None:
                remote = next(
                    (
                        loc
                        for sm in sitemaps
                        for loc, _ in sm.urls
                        if urlsplit(loc).scheme and not _is_local(loc)
                    ),
                    None,
                )
                production_origin = _origin(remote) if remote else None
            emit.progress(10, "crawling")

            # breadth-first crawl
            pages: dict[str, Page] = {}
            frontier: list[tuple[str, int]] = [(home, 0)]
            seen = {home}
            sem = asyncio.Semaphore(CONCURRENCY)

            async def fetch_page(url: str, depth: int) -> Page | None:
                async with sem:
                    r = await get(url)
                if r is None:
                    return None
                page = Page(
                    url=_normalise(str(r.url)),
                    requested=url,
                    status=r.status_code,
                    content_type=r.headers.get("content-type", ""),
                    redirects=[(h.status_code, h.headers.get("location", "")) for h in r.history],
                    headers={k.lower(): v for k, v in r.headers.items()},
                    depth=depth,
                )
                blocked = r.extensions.get("secscope_blocked_redirect")
                if blocked is not None:
                    page.redirects.append((r.status_code, str(getattr(blocked, "location", ""))))
                if page.is_html and len(r.content) <= MAX_HTML_BYTES:
                    page.html = r.text
                    parse_page(page)
                if parser is not None:
                    page.robots_blocked = not parser.can_fetch(page.url, "Googlebot")
                return page

            while frontier and len(pages) < MAX_PAGES:
                await ctx.checkpoint()
                batch = frontier[: MAX_PAGES - len(pages)]
                frontier = []
                results = await asyncio.gather(*(fetch_page(u, d) for u, d in batch))
                for (url, depth), page in zip(batch, results, strict=True):
                    if page is None:
                        continue
                    pages[url] = page
                    if depth >= MAX_DEPTH or page.status != 200:
                        continue
                    for href, _text in page.links:
                        link = self._internal(href, page.url, target, production_origin)
                        if link and link not in seen:
                            seen.add(link)
                            frontier.append((link, depth + 1))
                emit.progress(min(80, 10 + len(pages) * 70 // MAX_PAGES), f"{len(pages)} pages")

            # sitemap URLs that were not reached by links (orphans or broken entries)
            sitemap_pages: dict[str, Page] = {}
            for sm in sitemaps:
                for loc, _ in sm.urls:
                    url = _normalise(map_to_target(urljoin(home, loc), target))
                    if url in pages:
                        sitemap_pages[url] = pages[url]
                    elif url not in sitemap_pages and len(sitemap_pages) < MAX_PAGES:
                        page = await fetch_page(url, -1)
                        if page is not None:
                            sitemap_pages[url] = page

            # image weights (HEAD, internal images only)
            images = {i.src for p in pages.values() for i in p.images if i.src.startswith(target)}
            sizes: dict[str, int] = {}
            for src in list(images)[:MAX_IMAGE_PROBES]:
                r = await get(src, method="HEAD")
                if r is not None and r.headers.get("content-length", "").isdigit():
                    sizes[src] = int(r.headers["content-length"])
            for p in pages.values():
                for img in p.images:
                    img.size = sizes.get(img.src)

            probe = await get(urljoin(target, f"/secscope-not-found-{secrets.token_hex(4)}"))

        facts = SiteFacts(
            target_origin=target,
            home=home,
            pages=list(pages.values()),
            robots_status=robots_status,
            robots_text=robots_text,
            robots_disallow_all=disallow_all,
            sitemaps=sitemaps,
            sitemap_declared=bool(declared),
            not_found_status=probe.status_code if probe is not None else None,
            production_origin=production_origin,
            sitemap_pages=sitemap_pages,
        )
        issues = site_checks(facts)
        findings = self._findings(issues, target)
        for f in findings:
            emit.finding(f)
        kb = default_kb()
        failed: dict[str, str] = {}
        for f in findings:
            if f.severity != "info":
                prev = failed.get(f.rule_id)
                failed[f.rule_id] = (
                    f.severity
                    if prev is None or CHECK_ORDER[f.severity] > CHECK_ORDER[prev]
                    else prev
                )
        defaults = {r: e.severity for r, e in kb.entries.items() if r.startswith("SEO-")}
        result.data["seo_score"] = seo_score(failed, defaults)
        result.data["production_origin"] = production_origin
        result.data["pages"] = [
            {
                "url": p.url,
                "status": p.status,
                "title": p.title,
                "words": p.words,
                "indexable": p.status == 200 and not p.noindex and not p.robots_blocked,
                "depth": p.depth,
            }
            for p in sorted(pages.values(), key=lambda x: (x.depth, x.url))
        ][:MAX_PAGES]
        result.data["generated"] = self._generate(ctx, facts)
        result.notes.append(
            "core-web-vitals: lab measurement needs the browser module; performance sub-score is heuristic"
        )
        emit.progress(100, f"{len(pages)} pages, {len(findings)} findings")
        return result

    @staticmethod
    def _internal(href: str, base: str, target: str, production_origin: str | None) -> str | None:
        href = href.strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            return None
        absolute = urljoin(base, href)
        if production_origin and absolute.startswith(production_origin):
            absolute = map_to_target(absolute, target)
        if _origin(absolute) != target:
            return None
        return _normalise(absolute)

    @staticmethod
    def _findings(issues: list[SeoIssue], target: str) -> list[Finding]:
        kb = default_kb()
        out: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for issue in issues:
            key = (issue.rule_id, issue.url, issue.detail)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                kb.finding(
                    issue.rule_id,
                    module="seo",
                    location=HttpLocation(url=issue.url),
                    # Evidence uses paths, not the random port, so ids stay stable.
                    evidence=Evidence(
                        snippet=issue.detail.replace(target, ""), extra={"count": str(issue.count)}
                    ),
                    severity=issue.severity,  # type: ignore[arg-type]
                    source_tool="native",
                )
            )
        return out

    @staticmethod
    def _generate(ctx: ScanContext, site: SiteFacts) -> dict[str, str]:
        out_dir = ctx.work_dir / "seo"
        out_dir.mkdir(parents=True, exist_ok=True)
        home = next((p for p in site.pages if p.path == "/" and p.status == 200), None)
        name = home.title.split(" – ")[0].split(" | ")[0] if home and home.title else None
        files: dict[str, str] = {
            "robots.txt": robots_txt(site.production_origin),
            "sitemap.xml": sitemap_xml(site.pages, site.production_origin),
            "structured-data.html": jsonld_templates(home, site.production_origin),
            "title-suggestions.json": json.dumps(
                title_suggestions(site.pages, name), indent=2, ensure_ascii=False
            ),
        }
        paths: dict[str, str] = {}
        for filename, content in files.items():
            path = out_dir / filename
            path.write_text(content, encoding="utf-8", newline="\n")
            paths[filename] = str(path)
        return paths


CHECK_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
