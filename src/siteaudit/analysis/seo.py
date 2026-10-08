"""SEO rules."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from ..crawler.extract import is_generic_anchor
from ..crawler.urls import normalize_url, same_site
from .base import NotApplicable, Undetermined, page_rule, site_rule

TITLE_MIN, TITLE_MAX = 15, 60
DESC_MIN, DESC_MAX = 70, 160
THIN_WORDS = 200


@page_rule("seo.title_missing", "seo", "high")
def title_missing(page, doc, snap):
    if not doc.title:
        yield {}


@page_rule("seo.title_length", "seo", "low")
def title_length(page, doc, snap):
    if not doc.title:
        raise NotApplicable
    n = len(doc.title)
    if n < TITLE_MIN or n > TITLE_MAX:
        yield {"title": doc.title, "length": n, "min": TITLE_MIN, "max": TITLE_MAX}


@page_rule("seo.title_multiple", "seo", "low")
def title_multiple(page, doc, snap):
    if doc.title_count > 1:
        yield {"count": doc.title_count}


@page_rule("seo.description_missing", "seo", "medium")
def description_missing(page, doc, snap):
    if not doc.meta_description:
        yield {}


@page_rule("seo.description_length", "seo", "low")
def description_length(page, doc, snap):
    if not doc.meta_description:
        raise NotApplicable
    n = len(doc.meta_description)
    if n < DESC_MIN or n > DESC_MAX:
        yield {"description": doc.meta_description, "length": n, "min": DESC_MIN, "max": DESC_MAX}


@page_rule("seo.h1_missing", "seo", "medium")
def h1_missing(page, doc, snap):
    if not any(level == 1 and text for level, text in doc.headings):
        yield {}


@page_rule("seo.h1_multiple", "seo", "low")
def h1_multiple(page, doc, snap):
    h1s = [text for level, text in doc.headings if level == 1]
    if len(h1s) > 1:
        yield {"count": len(h1s), "headings": h1s[:5]}


@page_rule("seo.canonical_missing", "seo", "low")
def canonical_missing(page, doc, snap):
    if not doc.canonicals:
        yield {}


@page_rule("seo.canonical_conflict", "seo", "medium")
def canonical_conflict(page, doc, snap):
    unique = sorted(set(doc.canonicals))
    if len(unique) > 1:
        yield {"canonicals": unique}


@page_rule("seo.canonical_other_site", "seo", "medium")
def canonical_other_site(page, doc, snap):
    if not doc.canonicals:
        raise NotApplicable
    target = doc.canonicals[0]
    if not same_site(target, snap.host):
        yield {"canonical": target}


@page_rule("seo.noindex", "seo", "info")
def noindex(page, doc, snap):
    header = page.headers.get("x-robots-tag", "").lower()
    if page is snap.home:
        raise NotApplicable  # the home page has a dedicated, more severe rule
    if "noindex" in doc.meta_robots or "noindex" in header:
        yield {"source": "meta" if "noindex" in doc.meta_robots else "header"}


@site_rule("seo.noindex_home", "seo", "critical")
def noindex_home(snap):
    home = snap.home
    if home is None or home.doc is None:
        raise NotApplicable
    header = home.headers.get("x-robots-tag", "").lower()
    if "noindex" in home.doc.meta_robots or "noindex" in header:
        yield home.final_url, {"source": "meta" if "noindex" in home.doc.meta_robots else "header"}


@page_rule("seo.thin_content", "seo", "low")
def thin_content(page, doc, snap):
    if doc.word_count < THIN_WORDS:
        yield {"words": doc.word_count, "min": THIN_WORDS}


@page_rule("seo.generic_anchor", "seo", "low")
def generic_anchor(page, doc, snap):
    found = sorted({link.text for link in doc.links if link.text and is_generic_anchor(link.text)})
    if found:
        yield {"anchors": found[:10], "count": len(found)}


@site_rule("seo.duplicate_title", "seo", "medium")
def duplicate_title(snap):
    groups: dict[str, list[str]] = defaultdict(list)
    for page in snap.html_pages:
        if page.doc and page.doc.title:
            groups[page.doc.title.strip().lower()].append(page.final_url)
    for urls in groups.values():
        if len(urls) > 1:
            title = next(p.doc.title for p in snap.html_pages if p.final_url == urls[0] and p.doc)
            for url in urls:
                yield url, {"title": title, "count": len(urls)}


@site_rule("seo.duplicate_description", "seo", "low")
def duplicate_description(snap):
    groups: dict[str, list[str]] = defaultdict(list)
    for page in snap.html_pages:
        if page.doc and page.doc.meta_description:
            groups[page.doc.meta_description.strip().lower()].append(page.final_url)
    for urls in groups.values():
        if len(urls) > 1:
            for url in urls:
                yield url, {"count": len(urls)}


@site_rule("seo.duplicate_content", "seo", "medium")
def duplicate_content(snap):
    groups: dict[str, list[str]] = defaultdict(list)
    for page in snap.html_pages:
        if page.doc and page.doc.text_hash:
            groups[page.doc.text_hash].append(page.final_url)
    for urls in groups.values():
        if len(urls) > 1:
            for url in urls:
                yield url, {"duplicates": [u for u in urls if u != url][:5]}


@site_rule("seo.robots_missing", "seo", "low")
def robots_missing(snap):
    if snap.robots.error and snap.robots.status is None:
        raise Undetermined("robots_unreachable")
    if not snap.robots.found:
        yield None, {"url": snap.origin + "/robots.txt", "status": snap.robots.status}


@site_rule("seo.robots_blocks_all", "seo", "critical")
def robots_blocks_all(snap):
    if not snap.robots.found:
        raise NotApplicable
    if snap.robots.disallow_all:
        yield None, {"url": snap.origin + "/robots.txt"}


@site_rule("seo.sitemap_missing", "seo", "low")
def sitemap_missing(snap):
    if not snap.sitemap.found:
        yield None, {"url": snap.sitemap.url, "status": snap.sitemap.status}


@site_rule("seo.sitemap_invalid", "seo", "medium")
def sitemap_invalid(snap):
    if not snap.sitemap.found:
        raise NotApplicable
    if not snap.sitemap.valid:
        yield None, {"url": snap.sitemap.url}


@site_rule("seo.broken_internal_links", "seo", "high")
def broken_internal_links(snap):
    for key, check in sorted(snap.link_checks.items()):
        if not same_site(check.url, snap.host):
            continue
        # 429 means the site rate-limited the audit itself, which says nothing about the link.
        broken = check.error is not None or (
            check.status is not None and check.status >= 400 and check.status != 429
        )
        if not broken or key not in snap.link_sources:
            continue
        for source in snap.link_sources[key][:5]:
            yield (
                source,
                {"link": check.url, "result": f"HTTP {check.status}" if check.status else check.error},
            )


@site_rule("seo.internal_redirects", "seo", "low")
def internal_redirects(snap):
    for key, check in sorted(snap.link_checks.items()):
        if not same_site(check.url, snap.host) or not check.redirected or key not in snap.link_sources:
            continue
        if normalize_url(check.final_url) == key:
            continue
        # http -> https or trailing-slash redirects are still an extra round trip, so they count.
        yield snap.link_sources[key][0], {"link": check.url, "target": check.final_url}


@site_rule("seo.open_graph_missing", "seo", "low")
def open_graph_missing(snap):
    home = snap.home
    if home is None or home.doc is None:
        raise NotApplicable
    missing = [k for k in ("og:title", "og:description", "og:image") if k not in home.doc.og]
    if missing:
        yield home.final_url, {"missing": missing}


@site_rule("seo.structured_data_missing", "seo", "info")
def structured_data_missing(snap):
    if not any(p.doc and p.doc.jsonld_count for p in snap.html_pages):
        yield None, {}


@site_rule("seo.https_canonical_mismatch", "seo", "medium")
def https_canonical_mismatch(snap):
    home = snap.home
    if home is None or home.doc is None or not home.doc.canonicals:
        raise NotApplicable
    canonical = urlsplit(home.doc.canonicals[0])
    if home.final_url.startswith("https://") and canonical.scheme == "http":
        yield home.final_url, {"canonical": home.doc.canonicals[0]}
