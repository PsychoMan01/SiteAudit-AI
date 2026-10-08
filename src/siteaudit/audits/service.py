"""Audit lifecycle: creation (validation + quotas), execution pipeline and persistence."""

from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..ai.providers import get_provider, safe_complete
from ..analysis import technology
from ..analysis.base import RULES, AnalysisResult, run_rules
from ..analysis.registry import CATEGORY_ORDER
from ..config import Settings
from ..crawler.crawler import Cancelled, Crawler, CrawlError, CrawlLimits, SiteSnapshot
from ..db import session_scope
from ..i18n import t
from ..models import Audit, AuditIssue, AuditPage, AuditScore, UsageEvent, User, utcnow
from ..net.client import SafeClient
from ..net.urlsafety import (
    BlockedDestinationError,
    DNSResolutionError,
    Policy,
    UnsafeURLError,
    normalize_target,
    resolve_allowed,
)
from ..plans import get_plan
from ..scoring import score

log = logging.getLogger(__name__)

STAGES = (
    "queued",
    "connecting",
    "crawling",
    "checking_links",
    "seo",
    "performance",
    "accessibility",
    "mobile",
    "security",
    "best_practices",
    "scoring",
    "report",
)
STALE_AFTER = timedelta(minutes=10)


class AuditRequestError(Exception):
    def __init__(self, code: str, **params: Any) -> None:
        super().__init__(code)
        self.code = code
        self.params = params


def policy_for(settings: Settings) -> Policy:
    return Policy(allow_private=settings.allow_private_targets)


def month_start() -> Any:
    now = utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def audits_this_month(db: Session, user_id: int) -> int:
    q = select(func.count(UsageEvent.id)).where(
        UsageEvent.user_id == user_id,
        UsageEvent.kind == "audit_created",
        UsageEvent.created_at >= month_start(),
    )
    return int(db.scalar(q) or 0)


def active_audits(db: Session, user_id: int) -> int:
    q = select(func.count(Audit.id)).where(Audit.user_id == user_id, Audit.status.in_(("queued", "running")))
    return int(db.scalar(q) or 0)


def create_audit(db: Session, user: User, raw_url: str, settings: Settings) -> Audit:
    policy = policy_for(settings)
    try:
        url = normalize_target(raw_url, policy)
    except UnsafeURLError as exc:
        raise AuditRequestError(f"url_{exc.code}") from exc

    plan = get_plan(user.plan)
    if active_audits(db, user.id) >= plan.concurrent_audits:
        raise AuditRequestError("too_many_running", limit=plan.concurrent_audits)
    if audits_this_month(db, user.id) >= plan.audits_per_month:
        raise AuditRequestError("monthly_limit", limit=plan.audits_per_month)

    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        resolve_allowed(hostname, port, policy)
    except DNSResolutionError as exc:
        raise AuditRequestError("url_dns") from exc
    except BlockedDestinationError as exc:
        raise AuditRequestError("url_private_address") from exc

    audit = Audit(
        user_id=user.id,
        url=url,
        host=hostname,
        status="queued",
        stage="queued",
        plan=plan.id,
        max_pages=plan.max_pages,
        max_depth=plan.max_depth,
    )
    db.add(audit)
    db.flush()
    db.add(UsageEvent(user_id=user.id, kind="audit_created", audit_id=audit.id))
    log.info("audit queued", extra={"event": "audit_queued", "audit_id": audit.public_id, "user_id": user.id})
    return audit


def request_cancel(db: Session, audit: Audit) -> bool:
    if audit.status == "queued":
        audit.status = "cancelled"
        audit.stage = None
        audit.finished_at = utcnow()
        return True
    if audit.status == "running":
        audit.cancel_requested = True
        return True
    return False


# --- queue -----------------------------------------------------------------------------------------------


def claim_next(db: Session) -> int | None:
    """Atomically move the oldest queued audit to running. Safe with several workers."""
    candidates = db.scalars(
        select(Audit.id).where(Audit.status == "queued").order_by(Audit.created_at, Audit.id).limit(5)
    ).all()
    for audit_id in candidates:
        now = utcnow()
        res = db.execute(
            update(Audit)
            .where(Audit.id == audit_id, Audit.status == "queued")
            .values(status="running", stage="connecting", started_at=now, heartbeat_at=now)
        )
        if res.rowcount == 1:  # type: ignore[attr-defined]
            db.commit()
            return audit_id
        db.rollback()
    return None


def fail_stale(db: Session) -> int:
    """Mark audits whose worker stopped sending heartbeats as failed; they do not count toward the quota."""
    cutoff = utcnow() - STALE_AFTER
    stale = db.scalars(select(Audit.id).where(Audit.status == "running", Audit.heartbeat_at < cutoff)).all()
    if not stale:
        return 0
    db.execute(
        update(Audit)
        .where(Audit.id.in_(stale))
        .values(status="failed", error_code="interrupted", finished_at=utcnow(), stage=None)
    )
    db.execute(delete(UsageEvent).where(UsageEvent.audit_id.in_(stale), UsageEvent.kind == "audit_created"))
    return len(stale)


# --- execution -------------------------------------------------------------------------------------------


class _Progress:
    """Writes the current stage and a heartbeat; reads the cancel flag (throttled)."""

    def __init__(self, audit_id: int) -> None:
        self.audit_id = audit_id
        self._last_cancel_check = 0.0
        self._cancelled = False
        self._last_pages_write = 0.0

    def stage(self, name: str) -> None:
        with session_scope() as db:
            db.execute(
                update(Audit).where(Audit.id == self.audit_id).values(stage=name, heartbeat_at=utcnow())
            )

    def pages(self, count: int) -> None:
        """Live page counter for the progress page (written at most every 2 s)."""
        now = time.monotonic()
        if now - self._last_pages_write >= 2.0:
            self._last_pages_write = now
            with session_scope() as db:
                db.execute(update(Audit).where(Audit.id == self.audit_id).values(pages_crawled=count))

    def cancelled(self) -> bool:
        now = time.monotonic()
        if now - self._last_cancel_check >= 2.0:
            self._last_cancel_check = now
            with session_scope() as db:
                self._cancelled = bool(
                    db.scalar(select(Audit.cancel_requested).where(Audit.id == self.audit_id))
                )
                db.execute(update(Audit).where(Audit.id == self.audit_id).values(heartbeat_at=utcnow()))
        return self._cancelled


def run_audit(audit_id: int, settings: Settings) -> str:
    """Execute one audit end to end. Never raises; returns the final status."""
    with session_scope() as db:
        audit = db.get(Audit, audit_id)
        if audit is None:
            return "missing"
        url, max_pages, max_depth, public_id = audit.url, audit.max_pages, audit.max_depth, audit.public_id
        locale = audit.user.locale

    progress = _Progress(audit_id)
    started = time.monotonic()
    limits = CrawlLimits(
        max_pages=max_pages,
        max_depth=max_depth,
        max_internal_link_checks=min(100, max(20, max_pages * 2)),
        delay=settings.crawl_delay,
        deadline_seconds=settings.crawl_audit_timeout,
    )
    log.info("audit started", extra={"event": "audit_started", "audit_id": public_id})
    try:
        with SafeClient(
            user_agent=settings.crawl_user_agent,
            timeout=settings.crawl_request_timeout,
            max_bytes=settings.crawl_max_response_bytes,
            policy=policy_for(settings),
        ) as client:
            crawler = Crawler(
                client, limits, progress=progress.stage, cancelled=progress.cancelled, on_page=progress.pages
            )
            snapshot = crawler.run(url)

        result: AnalysisResult | None = None
        for category, partial in run_rules(snapshot, CATEGORY_ORDER):
            progress.stage(category)
            if progress.cancelled():
                raise Cancelled()
            result = partial
        assert result is not None
        progress.stage("scoring")
        card = score(result)
        techs = _safe(lambda: technology.detect(snapshot), [])
        progress.stage("report")
        ai_text = _ai_summary(settings, snapshot, card, result, locale)
        _persist(audit_id, snapshot, result, card, techs, ai_text, locale)
        status = "completed"
    except Cancelled:
        _finish(audit_id, "cancelled", None)
        status = "cancelled"
    except CrawlError as exc:
        _finish(audit_id, "failed", exc.code)
        status = "failed"
    except Exception:
        log.exception("audit crashed", extra={"event": "audit_crashed", "audit_id": public_id})
        _finish(audit_id, "failed", "internal_error")
        status = "failed"
    log.info(
        "audit finished",
        extra={
            "event": "audit_finished",
            "audit_id": public_id,
            "status": status,
            "duration_ms": int((time.monotonic() - started) * 1000),
        },
    )
    return status


def _safe(fn: Any, default: Any) -> Any:
    try:
        return fn()
    except Exception:
        log.exception("optional step failed")
        return default


def _finish(audit_id: int, status: str, error_code: str | None) -> None:
    with session_scope() as db:
        db.execute(
            update(Audit)
            .where(Audit.id == audit_id)
            .values(status=status, error_code=error_code, stage=None, finished_at=utcnow())
        )
        if status == "failed":
            # Audits that could not run do not count toward the monthly quota.
            db.execute(
                delete(UsageEvent).where(UsageEvent.audit_id == audit_id, UsageEvent.kind == "audit_created")
            )


def _ai_summary(
    settings: Settings, snap: SiteSnapshot, card: Any, result: AnalysisResult, locale: str
) -> str | None:
    provider = get_provider(settings)
    if provider.name == "none":
        return None
    lines = [
        f"Website: {snap.start_url}",
        f"Pages audited: {len(snap.html_pages)}",
        f"Overall score: {card.overall}",
    ]
    for cat, cs in card.categories.items():
        lines.append(
            f"{t('en', 'category.' + cat)} score: {cs.score if cs.score is not None else 'not scored'}"
        )
    seen: set[str] = set()
    for f in sorted(
        result.findings, key=lambda f: ("critical", "high", "medium", "low", "info").index(f.severity)
    ):
        if f.rule_id in seen or f.severity == "info":
            continue
        seen.add(f.rule_id)
        lines.append(f"- [{f.severity}] {t('en', 'rules.' + f.rule_id + '.title')}")
        if len(seen) >= 12:
            break
    language = "European Portuguese" if locale == "pt" else "English"
    prompt = "\n".join(lines) + f"\n\nWrite the summary in {language}."
    return safe_complete(provider, prompt)


def _persist(
    audit_id: int,
    snap: SiteSnapshot,
    result: AnalysisResult,
    card: Any,
    techs: list[dict[str, str]],
    ai_text: str | None,
    locale: str,
) -> None:
    with session_scope() as db:
        audit = db.get(Audit, audit_id)
        assert audit is not None
        for page in snap.pages:
            audit.pages.append(
                AuditPage(
                    url=page.final_url[:2048],
                    depth=page.depth,
                    status_code=page.status,
                    content_type=(page.content_type or None) and page.content_type[:128],
                    response_ms=page.elapsed_ms,
                    html_bytes=page.html_bytes,
                    title=(page.doc.title[:512] if page.doc and page.doc.title else None),
                    error=page.error,
                )
            )
        # Several crawl entries can collapse to the same final URL; keep the first.
        unique: dict[str, AuditPage] = {}
        for p in audit.pages:
            unique.setdefault(p.url, p)
        audit.pages[:] = list(unique.values())

        for f in result.findings:
            audit.issues.append(
                AuditIssue(
                    rule_id=f.rule_id,
                    category=f.category,
                    severity=f.severity,
                    page_url=f.page_url[:2048] if f.page_url else None,
                    evidence=_dump(f.evidence),
                )
            )
        for cat, cs in card.categories.items():
            audit.scores.append(
                AuditScore(
                    category=cat, score=cs.score, checks_run=cs.checks_run, checks_failed=cs.checks_failed
                )
            )
        home = snap.home
        audit.final_url = snap.start_url[:2048]
        audit.pages_crawled = len(snap.pages)
        audit.overall_score = card.overall
        audit.technologies = techs
        audit.site_facts = {
            "html_pages": len(snap.html_pages),
            "robots": {
                "found": snap.robots.found,
                "status": snap.robots.status,
                "disallow_all": snap.robots.disallow_all,
                "crawl_delay": snap.robots.crawl_delay,
            },
            "sitemap": {
                "found": snap.sitemap.found,
                "url": snap.sitemap.url,
                "valid": snap.sitemap.valid,
                "url_count": snap.sitemap.url_count,
            },
            "tls": None
            if snap.tls is None
            else {
                "checked": snap.tls.checked,
                "valid": snap.tls.valid,
                "issuer": snap.tls.issuer,
                "expires": snap.tls.expires_at.date().isoformat() if snap.tls.expires_at else None,
                "protocol": snap.tls.protocol,
            },
            "home_response_ms": home.elapsed_ms if home else None,
            "home_html_kb": round(home.html_bytes / 1024, 1) if home else None,
            "links_checked": len(snap.link_checks),
            "resources_checked": len(snap.resources),
            "blocked_by_robots": len(snap.blocked_by_robots),
            "limit_reached": snap.limit_reached,
            "deadline_reached": snap.deadline_reached,
            "undetermined": dict(sorted(result.undetermined.items())),
            "errored_rules": sorted(result.errored),
            "rules_total": len(RULES),
            "ai_locale": locale if ai_text else None,
        }
        audit.ai_summary = ai_text
        audit.status = "completed"
        audit.stage = None
        audit.finished_at = utcnow()


def _dump(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, ensure_ascii=False, default=str)[:4000]
