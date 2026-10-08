"""Performance rules. Only values that were actually measured are reported.

Response times are measured from the audit server (time until response headers, including redirects);
they are not browser rendering metrics such as LCP.
"""

from __future__ import annotations

import re

from .base import NotApplicable, Undetermined, page_rule, site_rule

SLOW_MS, VERY_SLOW_MS = 1200, 3000
HTML_LARGE = 500 * 1024
IMAGE_LARGE = 300 * 1024
JS_TOTAL_LARGE = 1024 * 1024
MANY_REQUESTS = 80
COMPRESSIBLE = ("text/", "application/javascript", "application/json", "application/xml", "image/svg+xml")
_MAX_AGE = re.compile(r"max-age=(\d+)")


def _cacheable(cache_control: str) -> bool:
    cc = cache_control.lower()
    if "no-store" in cc or "no-cache" in cc:
        return False
    m = _MAX_AGE.search(cc)
    return bool(m and int(m.group(1)) >= 3600) or "immutable" in cc


@page_rule("performance.response_very_slow", "performance", "high")
def response_very_slow(page, doc, snap):
    if page.elapsed_ms is not None and page.elapsed_ms >= VERY_SLOW_MS:
        yield {"ms": page.elapsed_ms, "threshold": VERY_SLOW_MS}


@page_rule("performance.response_slow", "performance", "medium")
def response_slow(page, doc, snap):
    if page.elapsed_ms is not None and SLOW_MS <= page.elapsed_ms < VERY_SLOW_MS:
        yield {"ms": page.elapsed_ms, "threshold": SLOW_MS}


@page_rule("performance.html_large", "performance", "medium")
def html_large(page, doc, snap):
    if page.html_bytes > HTML_LARGE:
        yield {"kb": round(page.html_bytes / 1024), "threshold_kb": HTML_LARGE // 1024}


@page_rule("performance.html_uncompressed", "performance", "medium")
def html_uncompressed(page, doc, snap):
    if page.html_bytes < 2048:
        raise NotApplicable
    encoding = page.headers.get("content-encoding", "").lower()
    if not any(e in encoding for e in ("gzip", "br", "zstd", "deflate")):
        yield {"kb": round(page.html_bytes / 1024)}


@page_rule("performance.render_blocking_scripts", "performance", "medium")
def render_blocking_scripts(page, doc, snap):
    blocking = [s.src for s in doc.scripts if s.in_head and not (s.is_async or s.is_defer or s.is_module)]
    if blocking:
        yield {"count": len(blocking), "scripts": blocking[:8]}


@page_rule("performance.many_stylesheets", "performance", "low")
def many_stylesheets(page, doc, snap):
    blocking = [s.href for s in doc.stylesheets if s.in_head and s.media in ("", "all", "screen")]
    if len(blocking) > 5:
        yield {"count": len(blocking)}


@page_rule("performance.images_without_dimensions", "performance", "low")
def images_without_dimensions(page, doc, snap):
    missing = [i.src for i in doc.images if i.src and not i.has_dimensions]
    if len(missing) >= 3:
        yield {"count": len(missing), "total": len(doc.images), "images": missing[:5]}


@page_rule("performance.no_lazy_loading", "performance", "low")
def no_lazy_loading(page, doc, snap):
    if len(doc.images) < 10:
        raise NotApplicable
    if not any(i.lazy for i in doc.images):
        yield {"images": len(doc.images)}


@page_rule("performance.large_inline_code", "performance", "low")
def large_inline_code(page, doc, snap):
    total = doc.inline_script_bytes + doc.inline_style_bytes
    if total > 100 * 1024:
        yield {"kb": round(total / 1024)}


@site_rule("performance.many_requests", "performance", "low")
def many_requests(snap):
    home = snap.home
    if home is None or home.doc is None:
        raise NotApplicable
    count = len(home.doc.scripts) + len(home.doc.stylesheets) + len(home.doc.images)
    if count > MANY_REQUESTS:
        yield home.final_url, {"count": count, "threshold": MANY_REQUESTS}


@site_rule("performance.entry_redirects", "performance", "medium")
def entry_redirects(snap):
    home = snap.home
    if home is None:
        raise NotApplicable
    if len(home.redirects) >= 2:
        yield (
            home.url,
            {"hops": len(home.redirects), "chain": [u for u, _ in home.redirects] + [home.final_url]},
        )


def _checked(snap, kind=None):
    items = [r for r in snap.resources.values() if r.error is None and r.status and r.status < 400]
    if kind:
        items = [r for r in items if r.kind == kind]
    return items


@site_rule("performance.static_not_cached", "performance", "medium")
def static_not_cached(snap):
    items = _checked(snap)
    if not items:
        raise Undetermined("no_resources_checked")
    for res in items:
        if not _cacheable(res.cache_control):
            yield None, {"resource": res.url, "cache_control": res.cache_control or "—"}


@site_rule("performance.text_resources_uncompressed", "performance", "medium")
def text_resources_uncompressed(snap):
    items = [r for r in _checked(snap) if r.kind in ("css", "js") or r.content_type.startswith(COMPRESSIBLE)]
    if not items:
        raise Undetermined("no_resources_checked")
    for res in items:
        if res.size is not None and res.size > 2048 and not res.content_encoding:
            yield None, {"resource": res.url, "kb": round(res.size / 1024)}


@site_rule("performance.large_images", "performance", "medium")
def large_images(snap):
    items = _checked(snap, "image")
    if not items:
        raise Undetermined("no_images_checked")
    for res in items:
        if res.size is not None and res.size > IMAGE_LARGE:
            yield (
                None,
                {"resource": res.url, "kb": round(res.size / 1024), "threshold_kb": IMAGE_LARGE // 1024},
            )


@site_rule("performance.heavy_javascript", "performance", "medium")
def heavy_javascript(snap):
    items = [r for r in _checked(snap, "js") if r.size is not None]
    if not items:
        raise Undetermined("no_scripts_checked")
    total = sum(r.size or 0 for r in items)
    if total > JS_TOTAL_LARGE:
        yield None, {"kb": round(total / 1024), "files": len(items), "threshold_kb": JS_TOTAL_LARGE // 1024}


@site_rule("performance.fonts_without_preconnect", "performance", "low")
def fonts_without_preconnect(snap):
    home = snap.home
    if home is None or home.doc is None or not home.doc.font_links:
        raise NotApplicable
    uses_google = any("fonts.googleapis.com" in f for f in home.doc.font_links)
    preconnected = any("fonts.gstatic.com" in p or "fonts.googleapis.com" in p for p in home.doc.preconnects)
    if uses_google and not preconnected:
        yield home.final_url, {}
