"""Administration area. Every route requires an admin; non-admins get a 404 (the area is not advertised)."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import AUDIT_STATUSES, PLANS, Audit, Report, Subscription, User, utcnow
from ...plans import PLANS as PLAN_LIMITS
from ...security.auth import destroy_all_sessions
from ...worker import worker_alive
from ..deps import DB, redirect, render, require_admin

router = APIRouter(prefix="/admin")
log = logging.getLogger(__name__)


@router.get("")
def overview(request: Request, admin: User = Depends(require_admin), db: Session = DB) -> Response:
    now = utcnow()
    day, week = now - timedelta(days=1), now - timedelta(days=7)

    def count(q: Any) -> int:
        return int(db.scalar(q) or 0)

    durations = db.execute(
        select(Audit.started_at, Audit.finished_at).where(
            Audit.status == "completed", Audit.finished_at >= week, Audit.started_at.is_not(None)
        )
    ).all()
    avg_duration = (
        round(sum((f - s).total_seconds() for s, f in durations if s and f) / len(durations))
        if durations
        else None
    )
    stats = {
        "users": count(select(func.count(User.id))),
        "users_week": count(select(func.count(User.id)).where(User.created_at >= week)),
        "audits_day": count(select(func.count(Audit.id)).where(Audit.created_at >= day)),
        "audits_week": count(select(func.count(Audit.id)).where(Audit.created_at >= week)),
        "failed_week": count(
            select(func.count(Audit.id)).where(Audit.status == "failed", Audit.created_at >= week)
        ),
        "queued": count(select(func.count(Audit.id)).where(Audit.status == "queued")),
        "running": count(select(func.count(Audit.id)).where(Audit.status == "running")),
        "reports_week": count(select(func.count(Report.id)).where(Report.created_at >= week)),
        "avg_duration": avg_duration,
    }
    plan_rows = db.execute(
        select(Subscription.plan, func.count(Subscription.id))
        .where(Subscription.status == "active")
        .group_by(Subscription.plan)
    ).all()
    errors = db.execute(
        select(Audit.error_code, func.count(Audit.id))
        .where(Audit.status == "failed", Audit.created_at >= week)
        .group_by(Audit.error_code)
        .order_by(func.count(Audit.id).desc())
    ).all()
    return render(
        request,
        "admin/overview.html",
        {
            "stats": stats,
            "plans": dict(plan_rows),
            "errors": errors,
            "worker_ok": worker_alive(),
            "limits": PLAN_LIMITS,
        },
        user=admin,
    )


@router.get("/users")
def users(
    request: Request,
    q: str = "",
    page: int = 1,
    admin: User = Depends(require_admin),
    db: Session = DB,
) -> Response:
    page = max(1, min(page, 1000))
    query = select(User)
    q = q.strip()[:100]
    if q:
        query = query.where(User.email.contains(q.lower()))
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(User.created_at.desc()).offset((page - 1) * 50).limit(50)).all()
    audit_counts = dict(
        db.execute(
            select(Audit.user_id, func.count(Audit.id))
            .where(Audit.user_id.in_([u.id for u in rows]))
            .group_by(Audit.user_id)
        ).all()
    )
    return render(
        request,
        "admin/users.html",
        {
            "rows": rows,
            "q": q,
            "page": page,
            "pages": max(1, -(-total // 50)),
            "audit_counts": audit_counts,
            "plan_ids": PLANS,
        },
        user=admin,
    )


@router.post("/users/{user_id}")
def update_user(
    user_id: int,
    plan: str = Form(...),
    active: str = Form("no"),
    admin: User = Depends(require_admin),
    db: Session = DB,
) -> Response:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    if plan not in PLANS:
        raise HTTPException(status_code=400)
    if target.id == admin.id and active != "yes":
        return redirect("/admin/users", "admin_self_disable")
    if target.subscription is None:
        target.subscription = Subscription(plan=plan, status="active", provider="manual")
    else:
        target.subscription.plan = plan
        target.subscription.status = "active"
    was_active = target.is_active
    target.is_active = active == "yes"
    if was_active and not target.is_active:
        destroy_all_sessions(db, target.id)
    log.info("admin updated user", extra={"event": "admin_user_update", "user_id": target.id})
    return redirect("/admin/users", "admin_user_saved")


@router.get("/audits")
def audits(
    request: Request,
    status: str = "",
    page: int = 1,
    admin: User = Depends(require_admin),
    db: Session = DB,
) -> Response:
    page = max(1, min(page, 1000))
    query = select(Audit)
    if status in AUDIT_STATUSES:
        query = query.where(Audit.status == status)
    else:
        status = ""
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(Audit.created_at.desc()).offset((page - 1) * 50).limit(50)).all()
    emails = dict(db.execute(select(User.id, User.email).where(User.id.in_([a.user_id for a in rows]))).all())
    return render(
        request,
        "admin/audits.html",
        {
            "rows": rows,
            "status": status,
            "statuses": AUDIT_STATUSES,
            "emails": emails,
            "page": page,
            "pages": max(1, -(-total // 50)),
        },
        user=admin,
    )
