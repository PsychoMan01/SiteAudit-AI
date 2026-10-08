"""Log redaction and session fixation."""

from __future__ import annotations

import pytest

from siteaudit.logging_setup import redact

from .conftest import csrf_of, register


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        ('"GET /reset-password?token=abcDEF_123-xyz HTTP/1.1" 200', "abcDEF_123-xyz"),
        ("Authorization: Bearer sk-abc.def", "sk-abc.def"),
        ("password=hunter2hunter2", "hunter2hunter2"),
        ('{"api_key": "AKIA1234"}', "AKIA1234"),
        ("cookie: sa_session=s3cr3t", "s3cr3t"),
    ],
)
def test_secrets_are_redacted(line: str, secret: str) -> None:
    out = redact(line)
    assert secret not in out and "[REDACTED]" in out


def test_login_replaces_pre_existing_session(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    old = client.cookies.get("sa_session")
    token = csrf_of(client, "/dashboard")
    resp = client.post(
        "/login",
        data={
            "email": "user@example.com",
            "password": "correct horse battery",
            "next": "/dashboard",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    new = client.cookies.get("sa_session")
    assert new and new != old
    client.cookies.set("sa_session", old)
    assert client.get("/dashboard", follow_redirects=False).status_code == 303  # old token no longer valid


def test_backup_command(settings) -> None:  # type: ignore[no-untyped-def]
    import sqlite3

    from siteaudit.cli import main

    assert main(["backup"]) == 0
    files = list((settings.data_dir / "backups").glob("siteaudit-*.db"))
    assert len(files) == 1
    with sqlite3.connect(files[0]) as conn:
        assert conn.execute("select count(*) from alembic_version").fetchone()[0] == 1


def test_stale_running_audit_is_failed_and_not_counted(client, site) -> None:  # type: ignore[no-untyped-def]
    from datetime import timedelta

    from sqlalchemy import select

    from siteaudit.audits.service import audits_this_month, claim_next, fail_stale
    from siteaudit.db import session_scope
    from siteaudit.models import Audit, utcnow

    from .conftest import html_page

    site.page("/", html_page("Stale audit test home page"))
    register(client, url=site.base + "/")
    with session_scope() as db:
        assert claim_next(db) is not None
        audit = db.scalar(select(Audit))
        audit.heartbeat_at = utcnow() - timedelta(minutes=30)
    with session_scope() as db:
        assert fail_stale(db) == 1
        audit = db.scalar(select(Audit))
        assert audit.status == "failed" and audit.error_code == "interrupted"
        assert audits_this_month(db, audit.user_id) == 0
