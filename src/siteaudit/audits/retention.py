"""Plan-based retention: audits older than the plan's history window are deleted."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import Audit, Subscription, User, utcnow
from ..plans import PLANS


def purge_expired(db: Session) -> int:
    deleted = 0
    for plan in PLANS.values():
        if plan.history_days is None:
            continue
        cutoff = utcnow() - timedelta(days=plan.history_days)
        if plan.id == "free":
            # Users without an active paid subscription are on the free plan.
            paid = select(Subscription.user_id).where(
                Subscription.status == "active", Subscription.plan != "free"
            )
            owners = select(User.id).where(User.id.not_in(paid))
        else:
            owners = select(Subscription.user_id).where(
                Subscription.status == "active", Subscription.plan == plan.id
            )
        res = db.execute(
            delete(Audit).where(
                Audit.user_id.in_(owners),
                Audit.created_at < cutoff,
                Audit.status.in_(("completed", "failed", "cancelled")),
            )
        )
        deleted += int(res.rowcount or 0)  # type: ignore[attr-defined]
    return deleted
