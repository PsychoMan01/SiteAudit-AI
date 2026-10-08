"""General web best-practice rules."""

from __future__ import annotations

from ..crawler.urls import same_site
from .base import NotApplicable, page_rule, site_rule


@page_rule("best_practices.doctype_missing", "best_practices", "low")
def doctype_missing(page, doc, snap):
    if not doc.has_doctype:
        yield {}


@page_rule("best_practices.charset_missing", "best_practices", "low")
def charset_missing(page, doc, snap):
    if not doc.charset_declared and "charset=" not in page.headers.get("content-type", "").lower():
        yield {}


@page_rule("best_practices.deprecated_html", "best_practices", "low")
def deprecated_html(page, doc, snap):
    if doc.deprecated_tags:
        yield {"tags": doc.deprecated_tags}


@page_rule("best_practices.meta_refresh", "best_practices", "low")
def meta_refresh(page, doc, snap):
    if doc.meta_refresh:
        yield {}


@page_rule("best_practices.target_blank", "best_practices", "info")
def target_blank(page, doc, snap):
    unsafe = [link.url for link in doc.links if link.blank_unsafe and not link.internal]
    if unsafe:
        yield {"count": len(unsafe), "links": unsafe[:5]}


@site_rule("best_practices.favicon_missing", "best_practices", "low")
def favicon_missing(snap):
    home = snap.home
    if home is None or home.doc is None:
        raise NotApplicable
    if not home.doc.has_favicon:
        yield home.final_url, {}


@site_rule("best_practices.server_errors", "best_practices", "high")
def server_errors(snap):
    for page in snap.pages:
        if page.status is not None and page.status >= 500:
            yield page.url, {"status": page.status}


@site_rule("best_practices.unreachable_pages", "best_practices", "medium")
def unreachable_pages(snap):
    for page in snap.pages:
        if page.error and page.error != "parse_error":
            yield page.url, {"error": page.error}


@site_rule("best_practices.broken_external_links", "best_practices", "medium")
def broken_external_links(snap):
    for key, check in sorted(snap.link_checks.items()):
        if same_site(check.url, snap.host) or key not in snap.link_sources:
            continue
        # 401/403/429 often mean "bots not welcome", not "broken"; only clear failures are reported.
        broken = (
            check.error in ("dns", "connection_refused", "tls")
            or check.status in (404, 410)
            or (check.status is not None and check.status >= 500)
        )
        if broken:
            for source in snap.link_sources[key][:3]:
                yield (
                    source,
                    {"link": check.url, "result": f"HTTP {check.status}" if check.status else check.error},
                )
