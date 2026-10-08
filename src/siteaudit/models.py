"""Database models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

CATEGORIES = ("seo", "performance", "accessibility", "mobile", "security", "best_practices")
SEVERITIES = ("critical", "high", "medium", "low", "info")
AUDIT_STATUSES = ("queued", "running", "completed", "failed", "cancelled")
PLANS = ("free", "pro", "agency")


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores naive UTC, always returns timezone-aware UTC (consistent on SQLite and PostgreSQL)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to UTCDateTime")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


def _sql_in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, onupdate=utcnow, nullable=False
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    locale: Mapped[str] = mapped_column(String(8), nullable=False, default="en")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    subscription: Mapped[Subscription | None] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def plan(self) -> str:
        sub = self.subscription
        if sub is not None and sub.status == "active":
            return sub.plan
        return "free"


class Subscription(TimestampMixin, Base):
    """Billing state. `provider='manual'` until a payment gateway is integrated."""

    __tablename__ = "subscriptions"
    __table_args__ = (
        CheckConstraint(_sql_in("plan", PLANS), name="ck_subscriptions_plan"),
        CheckConstraint("status IN ('active', 'cancelled')", name="ck_subscriptions_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    plan: Mapped[str] = mapped_column(String(16), nullable=False, default="free")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    provider_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user: Mapped[User] = relationship(back_populates="subscription")


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)

    user: Mapped[User] = relationship()


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user: Mapped[User] = relationship()


class AuthEvent(Base):
    """Authentication events for brute-force throttling. Stores an e-mail hash, never the password."""

    __tablename__ = "auth_events"
    __table_args__ = (
        Index("ix_auth_events_email_kind_time", "email_hash", "kind", "created_at"),
        Index("ix_auth_events_ip_kind_time", "ip", "kind", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    email_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class Audit(Base):
    __tablename__ = "audits"
    __table_args__ = (
        CheckConstraint(_sql_in("status", AUDIT_STATUSES), name="ck_audits_status"),
        Index("ix_audits_user_created", "user_id", "created_at"),
        Index("ix_audits_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, default=lambda: uuid.uuid4().hex
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    plan: Mapped[str] = mapped_column(String(16), nullable=False, default="free")
    max_pages: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    pages_crawled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    overall_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    technologies: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    site_facts: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user: Mapped[User] = relationship()
    pages: Mapped[list[AuditPage]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="AuditPage.id"
    )
    issues: Mapped[list[AuditIssue]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="AuditIssue.id"
    )
    scores: Mapped[list[AuditScore]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="AuditScore.id"
    )

    @property
    def is_finished(self) -> bool:
        return self.status in {"completed", "failed", "cancelled"}


class AuditPage(Base):
    __tablename__ = "audit_pages"
    __table_args__ = (UniqueConstraint("audit_id", "url", name="uq_audit_pages_audit_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    html_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error: Mapped[str | None] = mapped_column(String(64), nullable=True)

    audit: Mapped[Audit] = relationship(back_populates="pages")


class AuditIssue(Base):
    __tablename__ = "audit_issues"
    __table_args__ = (
        CheckConstraint(_sql_in("category", CATEGORIES), name="ck_audit_issues_category"),
        CheckConstraint(_sql_in("severity", SEVERITIES), name="ck_audit_issues_severity"),
        Index("ix_audit_issues_audit_rule", "audit_id", "rule_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    page_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    audit: Mapped[Audit] = relationship(back_populates="issues")


class AuditScore(Base):
    __tablename__ = "audit_scores"
    __table_args__ = (
        UniqueConstraint("audit_id", "category", name="uq_audit_scores_audit_category"),
        CheckConstraint(_sql_in("category", CATEGORIES), name="ck_audit_scores_category"),
        CheckConstraint("score IS NULL OR (score >= 0 AND score <= 100)", name="ck_audit_scores_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checks_run: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    audit: Mapped[Audit] = relationship(back_populates="scores")


class Report(Base):
    """One row per exported report (used for plan limits and the admin view)."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class UsageEvent(Base):
    __tablename__ = "usage"
    __table_args__ = (Index("ix_usage_user_kind_time", "user_id", "kind", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    audit_id: Mapped[int | None] = mapped_column(ForeignKey("audits.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    beat_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
