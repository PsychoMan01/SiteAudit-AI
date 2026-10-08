"""URL normalization helpers for crawling."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

_TRACKING_PREFIXES = ("utm_",)
_TRACKING_KEYS = {"gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "_ga"}

NON_HTML_EXTENSIONS = (
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".rar",
    ".7z",
    ".exe",
    ".dmg",
    ".msi",
    ".apk",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".avif",
    ".svg",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".webm",
    ".ogg",
    ".wav",
    ".m4a",
    ".css",
    ".js",
    ".json",
    ".xml",
    ".txt",
    ".csv",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
)


def absolutize(base: str, href: str) -> str | None:
    href = (href or "").strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "sms:", "about:")):
        return None
    try:
        joined = urljoin(base, href)
    except ValueError:
        return None
    if urlsplit(joined).scheme not in ("http", "https"):
        return None
    return joined


def normalize_url(url: str) -> str:
    """Canonical form used for de-duplication: lowercase scheme/host, no default port, no fragment,
    no tracking parameters. Path and remaining query are kept as-is."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, 80 if scheme == "http" else 443) else f"{host}:{port}"
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k not in _TRACKING_KEYS and not k.startswith(_TRACKING_PREFIXES)
        ],
        doseq=True,
    )
    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))


def site_key(host: str) -> str:
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def same_site(url: str, host: str) -> bool:
    other = urlsplit(url).hostname or ""
    return site_key(other) == site_key(host)


def looks_like_html(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return not path.endswith(NON_HTML_EXTENSIONS)
