"""Authenticated product pages: dashboard, audits, results, report export, account settings."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...analysis.base import RULES
from ...analysis.registry import CATEGORY_ORDER
from ...audits.service import (
    STAGES,
    AuditRequestError,
    active_audits,
    audits_this_month,
    create_audit,
    request_cancel,
)
from ...audits.summary import build_summary, group_issues, pages_by_issue_count
from ...config import get_settings
from ...models import SEVERITIES, Audit, AuditIssue, Report, User, utcnow
from ...plans import get_plan
from ...reports.pdf import render_pdf
from ...security import auth as A
from ..deps import SESSION_COOKIE, get_db, redirect, render, require_user

router = APIRouter()
log = logging.getLogger(__name__)
PAGE_SIZE = 25


def _visible_since(user: User) -> Any:
    days = get_plan(user.plan).history_days
    return None if days is None else utcnow() - timedelta(days=days)


def _owned_audit(db: Session, user: User, public_id: str) -> Audit:
    """Fetch an audit only if it belongs to `user`. Anything else is a 404 (no IDOR, no existence leak)."""
    if not public_id.isalnum() or len(public_id) > 32:
        raise HTTPException(status_code=404)
    audit = db.scalar(select(Audit).where(Audit.public_id == public_id, Audit.user_id == user.id))
    if audit is None:
        raise HTTPException(status_code=404)
    return audit


@router.get("/dashboard")
def dashboard(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    since = _visible_since(user)
    base = select(Audit).where(Audit.user_id == user.id)
    if since is not None:
        base = base.where(Audit.created_at >= since)
    recent = db.scalars(base.order_by(Audit.created_at.desc()).limit(8)).all()
    completed = [a for a in recent if a.status == "completed"]

    stats_q = select(
        func.count(Audit.id), func.avg(Audit.overall_score), func.count(func.distinct(Audit.host))
    ).where(Audit.user_id == user.id, Audit.status == "completed")
    if since is not None:
        stats_q = stats_q.where(Audit.created_at >= since)
    total, avg_score, sites = db.execute(stats_q).one()

    latest = completed[0] if completed else None
    critical_open = 0
    if latest is not None:
        critical_open = int(
            db.scalar(
                select(func.count(func.distinct(AuditIssue.rule_id))).where(
                    AuditIssue.audit_id == latest.id, AuditIssue.severity == "critical"
                )
            )
            or 0
        )
    plan = get_plan(user.plan)
    return render(
        request,
        "app/dashboard.html",
        {
            "recent": recent,
            "latest": latest,
            "stats": {
                "total": int(total or 0),
                "avg": None if avg_score is None else round(float(avg_score)),
                "sites": int(sites or 0),
                "critical": critical_open,
            },
            "plan": plan,
            "used": audits_this_month(db, user.id),
            "active": active_audits(db, user.id),
        },
        user=user,
    )


@router.get("/audits")
def audit_list(
    request: Request,
    page: int = 1,
    q: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    page = max(1, min(page, 1000))
    query = select(Audit).where(Audit.user_id == user.id)
    since = _visible_since(user)
    if since is not None:
        query = query.where(Audit.created_at >= since)
    q = q.strip()[:100]
    if q:
        query = query.where(Audit.host.contains(q.lower()))
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    audits = db.scalars(
        query.order_by(Audit.created_at.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
    ).all()
    return render(
        request,
        "app/audits.html",
        {
            "audits": audits,
            "page": page,
            "pages": max(1, -(-total // PAGE_SIZE)),
            "q": q,
            "total": total,
            "plan": get_plan(user.plan),
        },
        user=user,
    )


@router.post("/audits")
def audit_create(
    request: Request, url: str = Form(""), user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    try:
        audit = create_audit(db, user, url, get_settings())
    except AuditRequestError as exc:
        plan = get_plan(user.plan)
        return render(
            request,
            "app/new_audit.html",
            {
                "error": exc.code,
                "error_params": exc.params,
                "url": url[:2048],
                "plan": plan,
                "used": audits_this_month(db, user.id),
            },
            user=user,
            status_code=400 if exc.code.startswith("url_") else 429,
        )
    return redirect(f"/audits/{audit.public_id}")


@router.get("/audits/new")
def audit_new(
    request: Request, url: str = "", user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    return render(
        request,
        "app/new_audit.html",
        {"url": url[:2048], "plan": get_plan(user.plan), "used": audits_this_month(db, user.id)},
        user=user,
    )


def _decode(issue: AuditIssue) -> dict[str, Any]:
    try:
        value = json.loads(issue.evidence or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


@router.get("/audits/{public_id}")
def audit_detail(
    request: Request,
    public_id: str,
    category: str = "",
    severity: str = "",
    page_url: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    audit = _owned_audit(db, user, public_id)
    if not audit.is_finished or audit.status != "completed":
        return render(request, "app/audit_progress.html", {"audit": audit, "stages": STAGES}, user=user)

    summary = build_summary(audit)
    issues = audit.issues
    if category in CATEGORY_ORDER:
        issues = [i for i in issues if i.category == category]
    else:
        category = ""
    if severity in SEVERITIES:
        issues = [i for i in issues if i.severity == severity]
    else:
        severity = ""
    if page_url:
        issues = [i for i in issues if i.page_url == page_url]
    groups = group_issues(issues)
    evidence = {i.id: _decode(i) for i in audit.issues}
    scores = {s.category: s for s in audit.scores}
    page_options = sorted({i.page_url for i in audit.issues if i.page_url})
    return render(
        request,
        "app/audit_result.html",
        {
            "audit": audit,
            "summary": summary,
            "groups": groups,
            "evidence": evidence,
            "scores": scores,
            "categories": CATEGORY_ORDER,
            "filters": {"category": category, "severity": severity, "page_url": page_url},
            "page_options": page_options,
            "page_counts": dict(pages_by_issue_count(audit)),
            "facts": audit.site_facts or {},
            "rules": RULES,
            "plan": get_plan(user.plan),
            "show_ai": bool(audit.ai_summary and (audit.site_facts or {}).get("ai_locale") == user.locale),
        },
        user=user,
    )


@router.get("/audits/{public_id}/status")
def audit_status(
    public_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> JSONResponse:
    audit = _owned_audit(db, user, public_id)
    return JSONResponse(
        {
            "status": audit.status,
            "stage": audit.stage,
            "pages": audit.pages_crawled,
            "finished": audit.is_finished,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/audits/{public_id}/cancel")
def audit_cancel(
    public_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    audit = _owned_audit(db, user, public_id)
    request_cancel(db, audit)
    return redirect(f"/audits/{audit.public_id}")


@router.post("/audits/{public_id}/delete")
def audit_delete(
    public_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    audit = _owned_audit(db, user, public_id)
    if audit.status in ("queued", "running"):
        return redirect(f"/audits/{audit.public_id}", "audit_delete_running")
    db.delete(audit)
    return redirect("/audits", "audit_deleted")


@router.get("/audits/{public_id}/report.pdf")
def audit_report(
    public_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    audit = _owned_audit(db, user, public_id)
    if audit.status != "completed":
        raise HTTPException(status_code=404)
    full = get_plan(user.plan).full_report
    pdf = render_pdf(audit, user.locale, full=full)
    db.add(Report(audit_id=audit.id, user_id=user.id, format="pdf", size_bytes=len(pdf)))
    filename = f"siteaudit-{audit.host}-{audit.created_at:%Y%m%d}.pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


# --- account settings ------------------------------------------------------------------------------------


@router.get("/settings")
def settings_page(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)
) -> Response:
    return render(
        request,
        "app/settings.html",
        {"plan": get_plan(user.plan), "used": audits_this_month(db, user.id)},
        user=user,
    )


@router.post("/settings/profile")
def settings_profile(
    name: str = Form(""),
    locale: str = Form("en"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    user.name = name.strip()[:100]
    if locale in ("en", "pt"):
        user.locale = locale
    return redirect("/settings", "profile_saved")


@router.post("/settings/password")
def settings_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    error = None
    if not A.verify_password(user.password_hash, current_password[: A.MAX_PASSWORD]):
        error = "invalid_current_password"
    else:
        error = A.validate_password(new_password, user.email)
    if error:
        return render(
            request,
            "app/settings.html",
            {"plan": get_plan(user.plan), "used": audits_this_month(db, user.id), "password_error": error},
            user=user,
            status_code=400,
        )
    user.password_hash = A.hash_password(new_password)
    A.destroy_all_sessions(db, user.id)
    token = A.create_session(db, user)
    response = redirect("/settings", "password_changed")
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=get_settings().secure_cookies,
        samesite="lax",
        max_age=int(A.SESSION_TTL.total_seconds()),
        path="/",
    )
    return response


@router.post("/settings/delete")
def settings_delete(
    request: Request,
    password: str = Form(""),
    confirm: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    if confirm != "DELETE" or not A.verify_password(user.password_hash, password[: A.MAX_PASSWORD]):
        return render(
            request,
            "app/settings.html",
            {"plan": get_plan(user.plan), "used": audits_this_month(db, user.id), "delete_error": True},
            user=user,
            status_code=400,
        )
    log.info("account deleted", extra={"event": "account_deleted", "user_id": user.id})
    db.delete(user)
    response = redirect("/", "account_deleted")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
