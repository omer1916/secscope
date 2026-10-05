# ADR-007: SEO module ships before the browser module; Core Web Vitals deferred

- Status: accepted (M6)
- Date: 2026-10-05

## Context

SPEC §7 asks for lab Core Web Vitals (Playwright + web-vitals, optionally Lighthouse) and a
raw-HTML vs rendered-DOM comparison. Both need a headless Chromium, which belongs to the
browser module (SPEC §6.4) that has not been built yet. The user asked to prioritise M6 and M8.

## Decisions

1. The SEO module crawls with HTTP only (Googlebot Smartphone user agent, through the scope
   guard, rate-limited) and analyses the **server-delivered HTML**. JavaScript-only content is
   therefore not seen yet; the report notes it.
2. The **performance** sub-score is *heuristic* (`performance_basis: heuristic`): images
   without dimensions (CLS risk), lazy-loaded LCP candidates, oversized images, render-blocking
   scripts. Lab LCP/INP/CLS will replace it when the browser module lands; the report must never
   present the heuristic as Core Web Vitals.
3. The production origin (`--public-url`, else inferred from robots/sitemap/canonical hosts) is
   only used to map URLs onto the local target and to fill generated files — it is never
   contacted.
4. Thresholds (title ~30–60, description ~70–160, thin content < 100 words, image > 300 KB,
   click depth > 4) are hints, not Google rules; Google publishes no hard limits for titles and
   descriptions. FAQ/HowTo rich-result markup is not recommended by the generators.
5. Built-in static server honours Netlify `_redirects`, so redirect chains and soft 404s are
   testable on static sites.
