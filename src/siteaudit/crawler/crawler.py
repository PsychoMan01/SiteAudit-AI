"""Controlled crawler that produces a `SiteSnapshot` — every network fact the analyzers need.

Guarantees: page and depth limits, a global deadline, per-request timeout and size cap, a politeness delay
(raised to the site's Crawl-delay, max 5 s), robots.txt respected, URL de-duplication, redirect loop
protection (in the client), cancellation between requests, and SSRF protection on every request.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib import robotparser
from urllib.parse import urlsplit, urlunsplit

from lxml import etree

from ..net.client import FetchResult, SafeClient
from ..net.tls import TLSInfo, inspect_certificate
from .extract import PageDoc, extract
from .urls import looks_like_html, normalize_url, same_site

log = logging.getLogger(__name__)

BOT_TOKEN = "SiteAuditBot"  # noqa: S105 - robots.txt user-agent token, not a secret
MAX_SITEMAP_URLS = 5000
MAX_SITEMAP_BYTES = 10 * 1024 * 1024
MAX_HTML_TOTAL_BYTES = 200 * 1024 * 1024


class CrawlError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Cancelled(Exception):
    pass


@dataclass
class Page:
    url: str
    depth: int
    status: int | None
    final_url: str
    headers: dict[str, str]
    elapsed_ms: int | None
    html_bytes: int
    content_type: str
    redirects: list[tuple[str, int]]
    error: str | None
    truncated: bool
    http_version: str | None = None
    cookies: list[str] = field(default_factory=list)
    doc: PageDoc | None = None

    @property
    def is_html_ok(self) -> bool:
        return self.doc is not None and self.status is not None and 200 <= self.status < 300


@dataclass
class RobotsInfo:
    status: int | None = None
    error: str | None = None
    found: bool = False
    disallow_all: bool = False
    sitemaps: list[str] = field(default_factory=list)
    crawl_delay: float | None = None


@dataclass
class SitemapInfo:
    url: str | None = None
    found: bool = False
    status: int | None = None
    valid: bool = False
    url_count: int = 0
    error: str | None = None
    urls: list[str] = field(default_factory=list)


@dataclass
class LinkCheck:
    url: str
    status: int | None
    error: str | None
    redirected: bool
    final_url: str


@dataclass
class ResourceCheck:
    url: str
    kind: str
    status: int | None
    size: int | None
    cache_control: str
    content_encoding: str
    content_type: str
    error: str | None


@dataclass
class SiteSnapshot:
    input_url: str
    start_url: str
    origin: str
    host: str
    pages: list[Page] = field(default_factory=list)
    robots: RobotsInfo = field(default_factory=RobotsInfo)
    sitemap: SitemapInfo = field(default_factory=SitemapInfo)
    link_checks: dict[str, LinkCheck] = field(default_factory=dict)
    link_sources: dict[str, list[str]] = field(default_factory=dict)
    resources: dict[str, ResourceCheck] = field(default_factory=dict)
    http_probe: FetchResult | None = None
    tls: TLSInfo | None = None
    blocked_by_robots: list[str] = field(default_factory=list)
    limit_reached: bool = False
    deadline_reached: bool = False

    @property
    def home(self) -> Page | None:
        return self.pages[0] if self.pages else None

    @property
    def html_pages(self) -> list[Page]:
        return [p for p in self.pages if p.is_html_ok]


@dataclass
class CrawlLimits:
    max_pages: int = 10
    max_depth: int = 3
    max_link_checks: int = 60
    max_resource_checks: int = 20
    delay: float = 0.5
    deadline_seconds: float = 300.0


Progress = Callable[[str], None]
CancelCheck = Callable[[], bool]


class Crawler:
    def __init__(
        self,
        client: SafeClient,
        limits: CrawlLimits,
        *,
        progress: Progress | None = None,
        cancelled: CancelCheck | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.limits = limits
        self.progress = progress or (lambda _stage: None)
        self.cancelled = cancelled or (lambda: False)
        self.sleep = sleep
        self._deadline = 0.0
        self._last_request = 0.0
        self._delay = limits.delay
        self._robots: robotparser.RobotFileParser | None = None

    # -- helpers -----------------------------------------------------------------------------------------

    def _check(self) -> None:
        if self.cancelled():
            raise Cancelled()

    def _time_left(self) -> bool:
        return time.monotonic() < self._deadline

    def _polite_fetch(self, url: str, **kwargs: object) -> FetchResult:
        self._check()
        wait = self._last_request + self._delay - time.monotonic()
        if wait > 0:
            self.sleep(wait)
        try:
            return self.client.fetch(url, **kwargs)  # type: ignore[arg-type]
        finally:
            self._last_request = time.monotonic()

    # -- phases ------------------------------------------------------------------------------------------

    def run(self, input_url: str) -> SiteSnapshot:
        self._deadline = time.monotonic() + self.limits.deadline_seconds
        self.progress("connecting")
        first = self._polite_fetch(input_url)
        if first.error:
            raise CrawlError(first.error)
        if first.status is None:
            raise CrawlError("connection_error")
        if first.status >= 400:
            raise CrawlError(f"http_{first.status}")
        if not first.is_html:
            raise CrawlError("not_html")

        parts = urlsplit(first.final_url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        snap = SiteSnapshot(
            input_url=input_url, start_url=first.final_url, origin=origin, host=parts.hostname or ""
        )

        robots = self._robots = self._load_robots(snap)
        self._load_sitemap(snap)
        self.progress("crawling")
        self._crawl(snap, first, robots)
        self.progress("checking_links")
        self._check_links(snap)
        self._check_resources(snap)
        self._security_probes(snap, input_url)
        return snap

    def _load_robots(self, snap: SiteSnapshot) -> robotparser.RobotFileParser | None:
        res = self._polite_fetch(snap.origin + "/robots.txt", max_bytes=512 * 1024)
        info = snap.robots
        info.status, info.error = res.status, res.error
        if res.error or res.status is None or res.status >= 400 or "html" in res.content_type:
            return None
        info.found = True
        lines = res.text().splitlines()
        parser = robotparser.RobotFileParser()
        parser.parse(lines)
        info.sitemaps = [
            line.split(":", 1)[1].strip()
            for line in lines
            if line.lower().startswith("sitemap:") and line.split(":", 1)[1].strip()
        ][:10]
        # "Blocks everything" is judged from a generic search-engine crawler's point of view.
        info.disallow_all = not parser.can_fetch("Googlebot", snap.origin + "/")
        delay = parser.crawl_delay(BOT_TOKEN) or parser.crawl_delay("*")
        if delay:
            info.crawl_delay = float(delay)
            self._delay = max(self._delay, min(float(delay), 5.0))
        return parser

    def _load_sitemap(self, snap: SiteSnapshot) -> None:
        info = snap.sitemap
        candidates = [u for u in snap.robots.sitemaps if same_site(u, snap.host)] or [
            snap.origin + "/sitemap.xml"
        ]
        info.url = candidates[0]
        res = self._polite_fetch(info.url, max_bytes=MAX_SITEMAP_BYTES)
        info.status, info.error = res.status, res.error
        if res.error or res.status is None or res.status >= 400:
            return
        info.found = True
        urls, children, valid = _parse_sitemap(res.body)
        info.valid = valid
        for child in children[:3]:
            if not same_site(child, snap.host) or len(urls) >= MAX_SITEMAP_URLS:
                continue
            child_res = self._polite_fetch(child, max_bytes=MAX_SITEMAP_BYTES)
            if child_res.ok:
                more, _, child_valid = _parse_sitemap(child_res.body)
                urls.extend(more)
                info.valid = info.valid and child_valid
        info.urls = urls[:MAX_SITEMAP_URLS]
        info.url_count = len(info.urls)

    def _crawl(
        self, snap: SiteSnapshot, first: FetchResult, robots: robotparser.RobotFileParser | None
    ) -> None:
        seen: set[str] = {normalize_url(snap.input_url), normalize_url(first.final_url)}
        queue: deque[tuple[str, int]] = deque()
        total_html = 0

        def enqueue(url: str, depth: int) -> None:
            key = normalize_url(url)
            if key in seen or depth > self.limits.max_depth:
                return
            if not same_site(url, snap.host) or not looks_like_html(url):
                return
            seen.add(key)
            if robots is not None and not (robots.can_fetch(BOT_TOKEN, url)):
                snap.blocked_by_robots.append(url)
                return
            queue.append((url, depth))

        page = self._record(snap, first, snap.input_url, 0)
        total_html += page.html_bytes
        if page.doc:
            for link in page.doc.internal_links:
                enqueue(link.url, 1)
        for url in snap.sitemap.urls[: self.limits.max_pages * 2]:
            enqueue(url, 1)

        while queue:
            if len(snap.pages) >= self.limits.max_pages:
                snap.limit_reached = True
                break
            if not self._time_left():
                snap.deadline_reached = True
                break
            if total_html > MAX_HTML_TOTAL_BYTES:
                snap.limit_reached = True
                break
            url, depth = queue.popleft()
            res = self._polite_fetch(url)
            if res.final_url != url and normalize_url(res.final_url) in {
                normalize_url(p.final_url) for p in snap.pages
            }:
                # Redirected to a page we already have; keep the redirect fact for link checks only.
                snap.link_checks[normalize_url(url)] = LinkCheck(
                    url, res.status, res.error, True, res.final_url
                )
                continue
            page = self._record(snap, res, url, depth)
            total_html += page.html_bytes
            if page.doc:
                for link in page.doc.internal_links:
                    enqueue(link.url, depth + 1)

    def _record(self, snap: SiteSnapshot, res: FetchResult, url: str, depth: int) -> Page:
        page = Page(
            url=url,
            depth=depth,
            status=res.status,
            final_url=res.final_url,
            headers={k.lower(): v for k, v in res.headers.items()},
            elapsed_ms=res.elapsed_ms,
            html_bytes=len(res.body),
            content_type=res.content_type,
            redirects=res.redirects,
            error=res.error,
            truncated=res.truncated,
            http_version=res.http_version,
            cookies=res.headers.get_list("set-cookie")[:30],
        )
        if res.ok and res.is_html:
            try:
                page.doc = extract(res.text(), res.final_url, snap.host)
            except Exception:  # a malformed page must not stop the audit
                log.warning("extraction failed", extra={"event": "extract_failed"})
                page.error = "parse_error"
        snap.pages.append(page)
        snap.link_checks[normalize_url(url)] = LinkCheck(
            url, res.status, res.error, bool(res.redirects), res.final_url
        )
        if page.doc:
            for link in page.doc.links:
                snap.link_sources.setdefault(normalize_url(link.url), [])
                sources = snap.link_sources[normalize_url(link.url)]
                if page.final_url not in sources and len(sources) < 20:
                    sources.append(page.final_url)
        return page

    def _check_links(self, snap: SiteSnapshot) -> None:
        pending = [u for u in snap.link_sources if u not in snap.link_checks]
        # Internal links first (more actionable), then external, in a stable order.
        pending.sort(key=lambda u: (not same_site(u, snap.host), u))
        # Internal URLs disallowed by robots.txt are never requested, not even with HEAD.
        if self._robots is not None:
            robots = self._robots
            pending = [u for u in pending if not same_site(u, snap.host) or robots.can_fetch(BOT_TOKEN, u)]
        for url in pending[: self.limits.max_link_checks]:
            if not self._time_left():
                snap.deadline_reached = True
                return
            res = self._polite_fetch(url, method="HEAD")
            if res.error is None and res.status in (405, 501, 403, 400):
                res = self._polite_fetch(url, max_bytes=64 * 1024)
            snap.link_checks[url] = LinkCheck(url, res.status, res.error, bool(res.redirects), res.final_url)

    def _check_resources(self, snap: SiteSnapshot) -> None:
        home = snap.home
        if home is None or home.doc is None:
            return
        candidates: list[tuple[str, str]] = []
        candidates += [(s.href, "css") for s in home.doc.stylesheets]
        candidates += [(s.src, "js") for s in home.doc.scripts if s.src]
        candidates += [(i.src, "image") for i in home.doc.images if i.src]
        seen: set[str] = set()
        for url, kind in candidates:
            if len(snap.resources) >= self.limits.max_resource_checks or not self._time_left():
                return
            if url in seen or url.startswith("data:"):
                continue
            seen.add(url)
            res = self._polite_fetch(url, max_bytes=8 * 1024 * 1024)
            size = len(res.body) if res.body and not res.truncated else None
            if size is None and res.headers.get("content-length", "").isdigit():
                size = int(res.headers["content-length"])
            snap.resources[url] = ResourceCheck(
                url=url,
                kind=kind,
                status=res.status,
                size=size,
                cache_control=res.headers.get("cache-control", ""),
                content_encoding=res.headers.get("content-encoding", ""),
                content_type=res.content_type,
                error=res.error,
            )

    def _security_probes(self, snap: SiteSnapshot, input_url: str) -> None:
        if snap.start_url.startswith("https://"):
            http_url = "http://" + snap.start_url.split("://", 1)[1]
            snap.http_probe = self._polite_fetch(http_url, read_body=False)
            port = urlsplit(snap.start_url).port or 443
            snap.tls = inspect_certificate(
                snap.host, port, policy=self.client.policy, timeout=self.client.timeout
            )


def _parse_sitemap(body: bytes) -> tuple[list[str], list[str], bool]:
    """Returns (page urls, child sitemap urls, is_valid_xml)."""
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, recover=False)
        root = etree.fromstring(body, parser=parser)
    except (etree.XMLSyntaxError, ValueError):
        return [], [], False
    tag = etree.QName(root).localname
    locs = [
        (el.text or "").strip()
        for el in root.iter()
        if isinstance(el.tag, str) and etree.QName(el).localname == "loc" and (el.text or "").strip()
    ]
    if tag == "sitemapindex":
        return [], locs, True
    if tag == "urlset":
        return locs[:MAX_SITEMAP_URLS], [], True
    return [], [], False
