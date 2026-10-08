"""Passive technology detection from headers and markup already fetched.

Each detection carries a confidence level and the evidence that produced it. Nothing is reported without
evidence, and no extra requests are made for fingerprinting.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from ..crawler.crawler import SiteSnapshot


@dataclass(frozen=True)
class Signature:
    name: str
    group: str  # cms | framework | library | server | cdn | analytics | hosting | ecommerce
    header: tuple[str, str] | None = None  # (header name, regex on value)
    header_present: str | None = None
    generator: str | None = None  # regex on <meta name="generator">
    script: str | None = None  # regex on script src
    marker: str | None = None  # body marker id (e.g. __NEXT_DATA__)
    cookie: str | None = None  # cookie name prefix
    confidence: str = "high"


SIGNATURES: tuple[Signature, ...] = (
    Signature("WordPress", "cms", generator=r"wordpress"),
    Signature("WordPress", "cms", script=r"/wp-(?:content|includes)/", confidence="high"),
    Signature("Drupal", "cms", generator=r"drupal"),
    Signature("Drupal", "cms", header_present="x-drupal-cache"),
    Signature("Joomla", "cms", generator=r"joomla"),
    Signature("Wix", "cms", generator=r"wix\.com"),
    Signature("Wix", "cms", header_present="x-wix-request-id"),
    Signature("Squarespace", "cms", generator=r"squarespace"),
    Signature("Webflow", "cms", generator=r"webflow"),
    Signature("Ghost", "cms", generator=r"ghost"),
    Signature("Hugo", "framework", generator=r"hugo"),
    Signature("Jekyll", "framework", generator=r"jekyll"),
    Signature("Shopify", "ecommerce", header_present="x-shopid"),
    Signature("Shopify", "ecommerce", script=r"cdn\.shopify\.com"),
    Signature("WooCommerce", "ecommerce", script=r"/woocommerce/"),
    Signature("Magento", "ecommerce", cookie="mage-", confidence="medium"),
    Signature("Next.js", "framework", marker=r"__NEXT_DATA__"),
    Signature("Next.js", "framework", script=r"/_next/static/", confidence="high"),
    Signature("Next.js", "framework", header=("x-powered-by", r"next\.js")),
    Signature("Nuxt", "framework", marker=r"__NUXT__"),
    Signature("Nuxt", "framework", script=r"/_nuxt/"),
    Signature("Gatsby", "framework", generator=r"gatsby"),
    Signature("Angular", "framework", script=r"angular(?:\.min)?\.js", confidence="medium"),
    Signature(
        "React", "library", script=r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js", confidence="medium"
    ),
    Signature("Vue.js", "library", script=r"vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js", confidence="medium"),
    Signature("jQuery", "library", script=r"jquery(?:[.-]\d[\w.]*)?(?:\.min)?\.js"),
    Signature("Bootstrap", "library", script=r"bootstrap(?:\.bundle)?(?:\.min)?\.js", confidence="medium"),
    Signature("PHP", "framework", header=("x-powered-by", r"php")),
    Signature("ASP.NET", "framework", header=("x-powered-by", r"asp\.net")),
    Signature("ASP.NET", "framework", header_present="x-aspnet-version"),
    Signature("Express", "framework", header=("x-powered-by", r"express")),
    Signature("Nginx", "server", header=("server", r"nginx")),
    Signature("Apache", "server", header=("server", r"apache")),
    Signature("Microsoft IIS", "server", header=("server", r"microsoft-iis")),
    Signature("LiteSpeed", "server", header=("server", r"litespeed")),
    Signature("Caddy", "server", header=("server", r"caddy")),
    Signature("Cloudflare", "cdn", header=("server", r"cloudflare")),
    Signature("Cloudflare", "cdn", header_present="cf-ray"),
    Signature("Amazon CloudFront", "cdn", header_present="x-amz-cf-id"),
    Signature("Fastly", "cdn", header_present="x-fastly-request-id"),
    Signature("Akamai", "cdn", header_present="x-akamai-transformed"),
    Signature("Vercel", "hosting", header_present="x-vercel-id"),
    Signature("Netlify", "hosting", header_present="x-nf-request-id"),
    Signature("GitHub Pages", "hosting", header=("server", r"github\.com")),
    Signature("Google Tag Manager", "analytics", script=r"googletagmanager\.com/gtm\.js"),
    Signature("Google Analytics", "analytics", script=r"googletagmanager\.com/gtag/js|google-analytics\.com"),
    Signature("Plausible", "analytics", script=r"plausible\.io/js"),
    Signature("Matomo", "analytics", script=r"matomo\.js|piwik\.js", confidence="medium"),
    Signature("Hotjar", "analytics", script=r"static\.hotjar\.com"),
    Signature("Meta Pixel", "analytics", script=r"connect\.facebook\.net/.*/fbevents\.js"),
)


@dataclass
class Detection:
    name: str
    group: str
    confidence: str
    evidence: str


_RANK = {"high": 0, "medium": 1, "low": 2}


def detect(snap: SiteSnapshot) -> list[dict[str, str]]:
    found: dict[str, Detection] = {}
    pages = snap.html_pages[:5]
    headers: dict[str, str] = {}
    for page in pages:
        for k, v in page.headers.items():
            headers.setdefault(k, v)
    generators = [p.doc.generator for p in pages if p.doc and p.doc.generator]
    scripts = [s for p in pages if p.doc for s in p.doc.script_srcs_raw]
    markers = [m for p in pages if p.doc for m in p.doc.body_markers]
    cookies = [c.split("=", 1)[0].strip().lower() for p in snap.pages for c in p.cookies]

    def add(sig: Signature, evidence: str) -> None:
        current = found.get(sig.name)
        if current is None or _RANK[sig.confidence] < _RANK[current.confidence]:
            found[sig.name] = Detection(sig.name, sig.group, sig.confidence, evidence[:160])

    for sig in SIGNATURES:
        if sig.header and sig.header[0] in headers and re.search(sig.header[1], headers[sig.header[0]], re.I):
            add(sig, f"{sig.header[0]}: {headers[sig.header[0]]}")
        if sig.header_present and sig.header_present in headers:
            add(sig, f"header {sig.header_present}")
        if sig.generator:
            for gen in generators:
                if re.search(sig.generator, gen, re.I):
                    add(sig, f'meta generator "{gen}"')
        if sig.script:
            for src in scripts:
                if re.search(sig.script, src, re.I):
                    add(sig, f"script {src}")
                    break
        if sig.marker and any(re.search(sig.marker, m) for m in markers):
            add(sig, f"page marker {sig.marker}")
        if sig.cookie and any(c.startswith(sig.cookie) for c in cookies):
            add(sig, f"cookie {sig.cookie}*")

    return [asdict(d) for d in sorted(found.values(), key=lambda d: (d.group, d.name))]
