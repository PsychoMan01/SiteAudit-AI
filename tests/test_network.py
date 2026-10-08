"""Optional checks against real public websites (run with `pytest -m network`). Small page limits only."""

from __future__ import annotations

import pytest

from siteaudit.analysis.base import run_rules
from siteaudit.analysis.registry import CATEGORY_ORDER
from siteaudit.crawler.crawler import Crawler, CrawlLimits
from siteaudit.net.client import SafeClient
from siteaudit.net.urlsafety import Policy
from siteaudit.scoring import score

pytestmark = pytest.mark.network


def _audit(url: str, pages: int = 3):  # type: ignore[no-untyped-def]
    with SafeClient(user_agent="SiteAuditBot/test", policy=Policy(), timeout=15) as client:
        snap = Crawler(client, CrawlLimits(max_pages=pages, delay=1.0)).run(url)
    result = None
    for _c, partial in run_rules(snap, CATEGORY_ORDER):
        result = partial
    return snap, result, score(result)


def test_simple_https_site() -> None:
    snap, result, card = _audit("https://example.com/", pages=1)
    assert snap.home is not None and snap.home.status == 200
    assert snap.tls is not None and snap.tls.valid
    assert card.overall is not None and not result.errored


def test_http_to_https_redirect_is_followed() -> None:
    snap, _result, _card = _audit("http://github.com/", pages=1)
    assert snap.start_url.startswith("https://")
    assert snap.home is not None and snap.home.redirects


def test_large_modern_site_with_sitemap() -> None:
    snap, result, _card = _audit("https://developer.mozilla.org/", pages=3)
    assert snap.robots.found
    assert len(snap.html_pages) >= 2
    assert not result.errored
