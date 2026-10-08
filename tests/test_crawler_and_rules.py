"""Crawler behaviour and rule results against a real local HTTP site."""

from __future__ import annotations

import pytest

from siteaudit.analysis.base import RULES, run_rules
from siteaudit.analysis.registry import CATEGORY_ORDER
from siteaudit.crawler.crawler import Cancelled, Crawler, CrawlError, CrawlLimits
from siteaudit.net.client import SafeClient
from siteaudit.net.urlsafety import Policy
from siteaudit.scoring import score

from .conftest import html_page

POLICY = Policy(allow_private=True)


def crawl(site, path: str = "/", **limits):  # type: ignore[no-untyped-def]
    with SafeClient(user_agent="SiteAuditBot/test", policy=POLICY, timeout=3) as client:
        return Crawler(client, CrawlLimits(delay=0, **limits)).run(site.base + path)


def analyse(snap):  # type: ignore[no-untyped-def]
    result = None
    for _cat, partial in run_rules(snap, CATEGORY_ORDER):
        result = partial
    return result


def rule_ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in result.findings}


def test_crawl_follows_links_respects_robots_and_limits(site) -> None:  # type: ignore[no-untyped-def]
    links = "".join(f'<a href="/p{i}">Page {i}</a>' for i in range(1, 8))
    site.page("/", html_page("Home page of the test site", links + '<a href="/private/x">Private</a>'))
    for i in range(1, 8):
        site.page(f"/p{i}", html_page(f"Page number {i} of the test site", '<a href="/">Home</a>'))
    site.add("/private/x", body=html_page("Secret page of the test site"))
    site.add("/robots.txt", body="User-agent: *\nDisallow: /private/\n", Content_Type="text/plain")

    snap = crawl(site, max_pages=5)
    fetched = [p.url for p in snap.pages]
    assert len(fetched) == 5
    assert snap.limit_reached
    assert not any("/private/" in h[1] for h in site.hits), "robots.txt Disallow must be respected"
    assert any(u.endswith("/private/x") for u in snap.blocked_by_robots)
    assert len(set(fetched)) == len(fetched), "no duplicate fetches"


def test_crawl_depth_limit(site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Level zero of the chain", '<a href="/l1">next</a>'))
    site.page("/l1", html_page("Level one of the chain", '<a href="/l2">next</a>'))
    site.page("/l2", html_page("Level two of the chain", '<a href="/l3">next</a>'))
    site.page("/l3", html_page("Level three of the chain"))
    snap = crawl(site, max_pages=50, max_depth=2)
    assert [p.url.rsplit("/", 1)[1] for p in snap.pages] == ["", "l1", "l2"]


def test_sitemap_is_used_for_discovery(site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Home without links to the orphan"))
    site.page("/orphan", html_page("Orphan page only in the sitemap"))
    site.add(
        "/robots.txt",
        body=f"User-agent: *\nAllow: /\nSitemap: {site.base}/map.xml\n",
        Content_Type="text/plain",
    )
    site.add(
        "/map.xml",
        body=f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<url><loc>{site.base}/</loc></url><url><loc>{site.base}/orphan</loc></url></urlset>",
        Content_Type="application/xml",
    )
    snap = crawl(site)
    assert snap.sitemap.found and snap.sitemap.valid and snap.sitemap.url_count == 2
    assert any(p.url.endswith("/orphan") for p in snap.pages)


def test_sitemap_xxe_is_not_expanded(site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Home page for the XXE test"))
    site.add(
        "/sitemap.xml",
        body='<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>&e;</loc></url></urlset>',
        Content_Type="application/xml",
    )
    snap = crawl(site)
    assert not any("root:" in u for u in snap.sitemap.urls)


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        (lambda s: s.add("/", status=503, body="down"), "http_503"),
        (lambda s: s.add("/", body=b"%PDF-1.4", Content_Type="application/pdf"), "not_html"),
        (
            lambda s: (s.add("/", status=301, Location="/x"), s.add("/x", status=301, Location="/")),
            "too_many_redirects",
        ),
    ],
)
def test_crawl_failures_are_classified(site, setup, code: str) -> None:  # type: ignore[no-untyped-def]
    setup(site)
    with pytest.raises(CrawlError) as exc:
        crawl(site)
    assert exc.value.code == code


def test_connection_refused_is_classified() -> None:
    with SafeClient(user_agent="t", policy=POLICY, timeout=2) as client, pytest.raises(CrawlError) as exc:
        Crawler(client, CrawlLimits(delay=0)).run("http://127.0.0.1:9/")
    assert exc.value.code in ("connection_refused", "connection_error")


def test_timeout_is_classified(site) -> None:  # type: ignore[no-untyped-def]
    from .conftest import Route

    site.routes["/"] = Route(200, "<html></html>", {}, delay=2.5)
    with SafeClient(user_agent="t", policy=POLICY, timeout=1) as client, pytest.raises(CrawlError) as exc:
        Crawler(client, CrawlLimits(delay=0)).run(site.base + "/")
    assert exc.value.code == "timeout"


def test_cancellation_stops_the_crawl(site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Home for the cancellation test", '<a href="/a">a</a>'))
    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    with SafeClient(user_agent="t", policy=POLICY, timeout=2) as client, pytest.raises(Cancelled):
        Crawler(client, CrawlLimits(delay=0), cancelled=cancelled).run(site.base + "/")


def test_problem_site_triggers_expected_rules(site) -> None:  # type: ignore[no-untyped-def]
    site.page(
        "/",
        "<html><head><title>x</title><meta name='viewport' content='width=1200'>"
        "<script src='/app.js'></script></head><body>"
        "<img src='/big.jpg'><a href='/missing'>click here</a><a href='/dup'>Duplicate</a>"
        "<form><input name='q'></form><button></button></body></html>",
        headers={"Set-Cookie": "sid=1; Path=/", "Server": "Apache/2.4.1", "X-Powered-By": "PHP/8.1"},
    )
    site.page("/dup", "<html><head><title>x</title></head><body><p>dup</p></body></html>")
    site.add("/app.js", body="console.log(1)" * 10, Content_Type="application/javascript")
    site.add("/big.jpg", body=b"\xff" * 400_000, Content_Type="image/jpeg")
    snap = crawl(site)
    result = analyse(snap)
    ids = rule_ids(result)
    expected = {
        "seo.title_length",
        "seo.description_missing",
        "seo.h1_missing",
        "seo.canonical_missing",
        "seo.broken_internal_links",
        "seo.generic_anchor",
        "seo.duplicate_title",
        "seo.robots_missing",
        "seo.sitemap_missing",
        "seo.thin_content",
        "performance.render_blocking_scripts",
        "performance.static_not_cached",
        "performance.large_images",
        "accessibility.lang_missing",
        "accessibility.image_alt_missing",
        "accessibility.control_unlabeled",
        "accessibility.button_unnamed",
        "accessibility.main_landmark_missing",
        "mobile.viewport_fixed_width",
        "security.no_https",
        "security.csp_missing",
        "security.clickjacking",
        "security.cookie_not_httponly",
        "security.cookie_no_samesite",
        "security.version_disclosure",
        "best_practices.doctype_missing",
        "best_practices.favicon_missing",
    }
    assert expected <= ids, f"missing: {sorted(expected - ids)}"
    # HTTPS-only checks do not apply to a plain-HTTP site and must not be reported.
    assert not ids & {"security.hsts_missing", "security.cookie_not_secure", "security.mixed_content"}
    broken = [f for f in result.findings if f.rule_id == "seo.broken_internal_links"]
    assert broken[0].evidence["result"] == "HTTP 404"
    assert not result.errored


def test_clean_site_has_no_significant_issues(site) -> None:  # type: ignore[no-untyped-def]
    head = (
        f'<link rel="icon" href="/f.svg"><link rel="canonical" href="{site.base}/">'
        '<meta property="og:title" content="t"><meta property="og:description" content="d">'
        f'<meta property="og:image" content="{site.base}/og.png">'
        '<script type="application/ld+json">{"@type":"Organization"}</script>'
        '<link rel="stylesheet" href="/s.css"><script src="/a.js" defer></script>'
    )
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    site.page(
        "/",
        html_page("A clean and well structured home", '<a href="/about">About the company</a>', head),
        headers=headers,
    )
    site.page(
        "/about",
        html_page("About the clean test company", "", head.replace(f'{site.base}/"', f'{site.base}/about"')),
        headers=headers,
    )
    cached = {"Cache-Control": "public, max-age=31536000, immutable"}
    site.add(
        "/s.css",
        body="body{}",
        Content_Type="text/css",
        **{k.replace("-", "_"): v for k, v in cached.items()},
    )
    site.add(
        "/a.js",
        body="1",
        Content_Type="application/javascript",
        **{k.replace("-", "_"): v for k, v in cached.items()},
    )
    site.add(
        "/robots.txt",
        body=f"User-agent: *\nAllow: /\nSitemap: {site.base}/sitemap.xml\n",
        Content_Type="text/plain",
    )
    site.add(
        "/sitemap.xml",
        body=f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{site.base}/</loc></url></urlset>',
        Content_Type="application/xml",
    )
    snap = crawl(site)
    result = analyse(snap)
    significant = {f.rule_id for f in result.findings if f.severity in ("critical", "high", "medium")}
    # The test server speaks plain, uncompressed HTTP; everything else must pass.
    assert significant == {"security.no_https", "performance.html_uncompressed"}, significant
    card = score(result)
    assert card.categories["seo"].score == 100
    assert card.categories["accessibility"].score == 100
    assert card.categories["mobile"].score == 100
    assert card.categories["best_practices"].score == 100


def test_every_rule_runs_without_error_on_varied_pages(site) -> None:  # type: ignore[no-untyped-def]
    from .test_extract import BAD_HTML

    site.page("/", BAD_HTML.replace('href="/internal"', 'href="/two"'))
    site.page("/two", html_page("Second page with normal content"))
    snap = crawl(site)
    result = analyse(snap)
    assert not result.errored
    ran = set().union(*result.evaluated.values())
    never = {r for r in RULES if r not in ran and r not in result.undetermined}
    # Rules may legitimately be "not applicable" (e.g. HTTPS checks on an HTTP site), never silently lost.
    assert never <= {
        "security.http_not_redirected",
        "security.certificate_invalid",
        "security.certificate_expiring",
        "security.hsts_missing",
        "security.cookie_not_secure",
        "security.mixed_content",
        "security.cookie_not_httponly",
        "security.cookie_no_samesite",
        "seo.robots_blocks_all",
        "seo.sitemap_invalid",
        "seo.https_canonical_mismatch",
        "performance.fonts_without_preconnect",
        "performance.no_lazy_loading",
        "mobile.images_not_responsive",
        "seo.description_length",
        "performance.html_uncompressed",
    }, never


def test_scoring_is_deterministic(site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Deterministic scoring home page", '<img src="/x.png">'))
    first = score(analyse(crawl(site)))
    second = score(analyse(crawl(site)))
    assert first == second


def test_politeness_delay_is_respected_per_host(site) -> None:  # type: ignore[no-untyped-def]
    links = "".join(f'<a href="/x{i}">Link {i}</a>' for i in range(8))
    site.page("/", html_page("Politeness test home page", links))
    with SafeClient(user_agent="t", policy=POLICY, timeout=3) as client:
        Crawler(client, CrawlLimits(max_pages=1, delay=0.2)).run(site.base + "/")
    gaps = [b - a for a, b in zip(site.hit_times, site.hit_times[1:], strict=False)]
    assert len(site.hit_times) >= 8
    assert min(gaps) >= 0.18, gaps


def test_head_failure_is_confirmed_with_get(site) -> None:  # type: ignore[no-untyped-def]
    site.page(
        "/", html_page("HEAD handling test home page", '<a href="/headless">Page that rejects HEAD</a>')
    )
    site.page("/headless", html_page("Works with GET only"))
    original = site.httpd.RequestHandlerClass.do_HEAD

    def head_404(handler) -> None:  # type: ignore[no-untyped-def]
        if handler.path == "/headless":
            handler.send_response(404)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
        else:
            original(handler)

    site.httpd.RequestHandlerClass.do_HEAD = head_404
    snap = crawl(site, max_pages=1)
    result = analyse(snap)
    assert "seo.broken_internal_links" not in rule_ids(result)
    assert ("GET", "/headless") in [(m, p) for m, p, _ in site.hits]
