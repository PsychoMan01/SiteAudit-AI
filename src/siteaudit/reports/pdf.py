"""PDF report rendering with WeasyPrint.

The report HTML is built only from stored audit data, escaped by Jinja. WeasyPrint's URL fetcher is
replaced so it can load nothing but the bundled stylesheet and logo — no network access from report
generation, even if a value somehow contained a URL.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..analysis.base import RULES
from ..analysis.registry import CATEGORY_ORDER
from ..audits.summary import build_summary, pages_by_issue_count
from ..i18n import t, tn
from ..models import Audit
from ..scoring import CATEGORY_WEIGHTS, SEVERITY_WEIGHTS, grade

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_LOGO = Path(__file__).parent.parent / "web" / "static" / "img" / "logo.svg"
ALLOWED_FILES = {
    "report.css": TEMPLATE_DIR / "report.css",
    "logo.svg": STATIC_LOGO,
}

_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))


class BlockedFetch(Exception):
    pass


def _local_only_fetcher() -> Any:
    from weasyprint.urls import URLFetcher, URLFetcherResponse

    class LocalOnlyFetcher(URLFetcher):
        def fetch(self, url: str, headers: Any = None) -> Any:
            name = url.split("?", 1)[0].rsplit("/", 1)[-1]
            if url.startswith("file://") and name in ALLOWED_FILES:
                mime = "text/css" if name.endswith(".css") else "image/svg+xml"
                return URLFetcherResponse(
                    url, body=ALLOWED_FILES[name].read_bytes(), headers={"Content-Type": mime}
                )
            raise BlockedFetch(url)

    return LocalOnlyFetcher()


def _evidence(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def render_html(audit: Audit, locale: str, *, full: bool) -> str:
    def tr(key: str, **params: Any) -> str:
        return t(locale, key, **params)

    def tr_n(key: str, n: int, **params: Any) -> str:
        return tn(locale, key, n, **params)

    summary = build_summary(audit)
    groups = summary.groups if full else summary.priorities
    template = _env.get_template("report.html")
    return template.render(
        audit=audit,
        t=tr,
        tn=tr_n,
        full=full,
        summary=summary,
        groups=groups,
        scores={s.category: s for s in audit.scores},
        categories=CATEGORY_ORDER,
        evidence=_evidence,
        rules=RULES,
        grade=grade,
        facts=audit.site_facts or {},
        pages_ranked=pages_by_issue_count(audit)[:15],
        severity_weights=SEVERITY_WEIGHTS,
        category_weights=CATEGORY_WEIGHTS,
        generated=datetime.now(UTC),
        locale=locale,
        show_ai=bool(audit.ai_summary and (audit.site_facts or {}).get("ai_locale") == locale),
    )


def render_pdf(audit: Audit, locale: str, *, full: bool) -> bytes:
    from weasyprint import HTML

    html = render_html(audit, locale, full=full)
    return HTML(
        string=html, base_url=f"file://{TEMPLATE_DIR}/", url_fetcher=_local_only_fetcher()
    ).write_pdf()
