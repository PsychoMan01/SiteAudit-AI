"""Passive security checks. Only the responses the crawler already received are inspected — no probing of
paths, no payloads, no brute force."""

from __future__ import annotations

import re

from .base import NotApplicable, Undetermined, site_rule

CERT_WARN_DAYS = 21
_VERSION = re.compile(r"\d+\.\d+")


def _home(snap):
    home = snap.home
    if home is None:
        raise NotApplicable
    return home


def _require_https(snap):
    home = _home(snap)
    if not home.final_url.startswith("https://"):
        raise NotApplicable
    return home


@site_rule("security.no_https", "security", "critical")
def no_https(snap):
    home = _home(snap)
    if not home.final_url.startswith("https://"):
        yield home.final_url, {}


@site_rule("security.http_not_redirected", "security", "high")
def http_not_redirected(snap):
    _require_https(snap)
    probe = snap.http_probe
    if probe is None or probe.status is None:
        raise Undetermined("http_unreachable")
    if not probe.final_url.startswith("https://"):
        yield probe.url, {"status": probe.status}


@site_rule("security.certificate_invalid", "security", "critical")
def certificate_invalid(snap):
    _require_https(snap)
    tls = snap.tls
    if tls is None or not tls.checked:
        raise Undetermined("tls_not_checked")
    if not tls.valid:
        yield None, {"error": tls.error}


@site_rule("security.certificate_expiring", "security", "high")
def certificate_expiring(snap):
    _require_https(snap)
    tls = snap.tls
    if tls is None or not tls.valid or tls.days_left is None:
        raise NotApplicable
    if tls.days_left < CERT_WARN_DAYS:
        yield (
            None,
            {"days": tls.days_left, "expires": tls.expires_at.date().isoformat() if tls.expires_at else ""},
        )


@site_rule("security.hsts_missing", "security", "medium")
def hsts_missing(snap):
    home = _require_https(snap)
    if "strict-transport-security" not in home.headers:
        yield home.final_url, {}


@site_rule("security.csp_missing", "security", "medium")
def csp_missing(snap):
    home = _home(snap)
    if "content-security-policy" not in home.headers:
        yield home.final_url, {}


@site_rule("security.clickjacking", "security", "medium")
def clickjacking(snap):
    home = _home(snap)
    csp = home.headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in home.headers and "frame-ancestors" not in csp:
        yield home.final_url, {}


@site_rule("security.nosniff_missing", "security", "low")
def nosniff_missing(snap):
    home = _home(snap)
    if home.headers.get("x-content-type-options", "").lower() != "nosniff":
        yield home.final_url, {}


@site_rule("security.referrer_policy_missing", "security", "low")
def referrer_policy_missing(snap):
    home = _home(snap)
    if "referrer-policy" not in home.headers:
        yield home.final_url, {}


@site_rule("security.permissions_policy_missing", "security", "low")
def permissions_policy_missing(snap):
    home = _home(snap)
    if "permissions-policy" not in home.headers:
        yield home.final_url, {}


def _cookies(snap):
    seen = {}
    for page in snap.pages:
        for raw in page.cookies:
            name = raw.split("=", 1)[0].strip()
            if name and name not in seen:
                seen[name] = (page.final_url, raw)
    if not seen:
        raise NotApplicable
    return seen


def _attrs(raw: str) -> set[str]:
    return {part.strip().split("=", 1)[0].lower() for part in raw.split(";")[1:]}


@site_rule("security.cookie_not_secure", "security", "medium")
def cookie_not_secure(snap):
    _require_https(snap)
    for name, (url, raw) in sorted(_cookies(snap).items()):
        if "secure" not in _attrs(raw):
            yield url, {"cookie": name}


@site_rule("security.cookie_not_httponly", "security", "low")
def cookie_not_httponly(snap):
    for name, (url, raw) in sorted(_cookies(snap).items()):
        if "httponly" not in _attrs(raw):
            yield url, {"cookie": name}


@site_rule("security.cookie_no_samesite", "security", "low")
def cookie_no_samesite(snap):
    for name, (url, raw) in sorted(_cookies(snap).items()):
        if "samesite" not in _attrs(raw):
            yield url, {"cookie": name}


@site_rule("security.mixed_content", "security", "high")
def mixed_content(snap):
    _require_https(snap)
    for page in snap.html_pages:
        if page.doc and page.doc.mixed_content:
            yield (
                page.final_url,
                {"count": len(page.doc.mixed_content), "resources": page.doc.mixed_content[:5]},
            )


@site_rule("security.version_disclosure", "security", "low")
def version_disclosure(snap):
    home = _home(snap)
    disclosed = []
    server = home.headers.get("server", "")
    if _VERSION.search(server):
        disclosed.append(f"Server: {server}")
    powered = home.headers.get("x-powered-by", "")
    if powered:
        disclosed.append(f"X-Powered-By: {powered}")
    for header in ("x-aspnet-version", "x-aspnetmvc-version"):
        if header in home.headers:
            disclosed.append(f"{header}: {home.headers[header]}")
    if disclosed:
        yield home.final_url, {"headers": disclosed}
