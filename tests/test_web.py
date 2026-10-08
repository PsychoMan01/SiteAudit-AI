"""Web application: pages, authentication, CSRF, authorization (IDOR), quotas, headers, health."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from .conftest import csrf_of, html_page, register, run_queued_audits

PASSWORD = "correct horse battery"


def login(client, email: str, password: str = PASSWORD, next_: str = "/dashboard"):  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/login")
    return client.post(
        "/login",
        data={"email": email, "password": password, "next": next_, "csrf_token": token},
        follow_redirects=False,
    )


def logout(client) -> None:  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token}, follow_redirects=False)


# --- public pages ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/", "/methodology", "/privacy", "/terms", "/bot", "/login", "/register", "/forgot-password"]
)
def test_public_pages_render(client, path: str) -> None:  # type: ignore[no-untyped-def]
    resp = client.get(path)
    assert resp.status_code == 200
    assert "<title>" in resp.text and 'lang="en"' in resp.text
    assert "Traceback" not in resp.text


def test_portuguese_via_accept_language_and_switch(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/", headers={"Accept-Language": "pt-PT,pt;q=0.9"})
    assert 'lang="pt"' in resp.text and "Analisar website" in resp.text
    assert "Analyze website" not in resp.text
    token = csrf_of(client, "/")
    client.post(
        "/lang", data={"lang": "pt", "next": "/methodology", "csrf_token": token}, follow_redirects=False
    )
    resp = client.get("/methodology")
    assert "Metodologia" in resp.text


def test_seo_endpoints(client) -> None:  # type: ignore[no-untyped-def]
    assert "Sitemap: http://testserver/sitemap.xml" in client.get("/robots.txt").text
    sitemap = client.get("/sitemap.xml")
    assert sitemap.headers["content-type"].startswith("application/xml")
    assert "<loc>http://testserver/methodology</loc>" in sitemap.text
    home = client.get("/").text
    assert 'rel="canonical" href="http://testserver/"' in home
    assert 'property="og:title"' in home and "application/ld+json" in home
    assert 'content="noindex"' in client.get("/login").text


def test_security_headers(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/")
    h = resp.headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "server" not in {k.lower() for k in h if h[k].lower().startswith("uvicorn")}
    assert 'style="' not in resp.text, "inline styles would violate the CSP"


def test_404_page_has_no_stack_trace(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404 and "Page not found" in resp.text


def test_health(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["checks"]["database"] is True
    assert body["status"] in ("ok", "degraded")


# --- authentication --------------------------------------------------------------------------------------


def test_register_login_logout(client, settings) -> None:  # type: ignore[no-untyped-def]
    resp = register(client)
    assert resp.status_code == 303 and resp.headers["location"] == "/dashboard"
    cookie = resp.headers["set-cookie"]
    assert "sa_session=" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie.replace("Lax", "lax")
    assert client.get("/dashboard").status_code == 200
    logout(client)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"].startswith("/login")
    assert login(client, "user@example.com").headers["location"] == "/dashboard"


def test_password_is_hashed_with_argon2(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    from siteaudit.db import session_scope
    from siteaudit.models import User

    with session_scope() as db:
        user = db.scalar(select(User))
        assert user.password_hash.startswith("$argon2")
        assert PASSWORD not in user.password_hash


@pytest.mark.parametrize(
    ("email", "password", "error"),
    [
        ("not-an-email", PASSWORD, "Enter a valid email"),
        ("a@b.co", "short", "at least 10 characters"),
        ("same@example.com", "same@example.com", "cannot be the same"),
    ],
)
def test_register_validation(client, email: str, password: str, error: str) -> None:  # type: ignore[no-untyped-def]
    resp = register(client, email=email, password=password)
    assert resp.status_code == 400 and error in resp.text


def test_register_requires_terms(client) -> None:  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/register")
    resp = client.post(
        "/register", data={"email": "x@example.com", "password": PASSWORD, "csrf_token": token}
    )
    assert resp.status_code == 400


def test_duplicate_email_rejected(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    logout(client)
    resp = register(client, email="USER@example.com")
    assert resp.status_code == 400 and "already exists" in resp.text


def test_wrong_password_generic_message(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    logout(client)
    resp = login(client, "user@example.com", "wrong password!!")
    assert resp.status_code == 400 and "email or password is incorrect" in resp.text
    resp = login(client, "nobody@example.com", "wrong password!!")
    assert resp.status_code == 400 and "email or password is incorrect" in resp.text


def test_brute_force_lockout(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    logout(client)
    for _ in range(5):
        assert login(client, "user@example.com", "bad password 123").status_code == 400
    resp = login(client, "user@example.com")  # even the right password is refused while locked
    assert resp.status_code == 429 and "Too many attempts" in resp.text


def test_open_redirect_is_prevented(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    logout(client)
    for evil in ("https://evil.example/", "//evil.example/", "/\\evil.example"):
        assert login(client, "user@example.com", next_=evil).headers["location"] == "/dashboard"
    assert login(client, "user@example.com", next_="/audits").headers["location"] == "/audits"


def test_password_reset_flow(client, settings) -> None:  # type: ignore[no-untyped-def]
    register(client)
    logout(client)
    token = csrf_of(client, "/forgot-password")
    resp = client.post("/forgot-password", data={"email": "user@example.com", "csrf_token": token})
    assert "reset link is on its way" in resp.text
    resp_unknown = client.post("/forgot-password", data={"email": "ghost@example.com", "csrf_token": token})
    assert resp_unknown.text.count("reset link is on its way") == 1  # same answer: no account enumeration

    mails = list((settings.data_dir / "outbox").glob("*.eml"))
    assert len(mails) == 1
    from email import message_from_bytes, policy

    body = message_from_bytes(mails[0].read_bytes(), policy=policy.default).get_body().get_content()
    link = re.search(r"reset-password\?token=([\w-]+)", body)
    assert link
    reset_token = link.group(1)
    page = client.get(f"/reset-password?token={reset_token}")
    form_token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text).group(1)
    resp = client.post(
        "/reset-password",
        data={"token": reset_token, "password": "a brand new password", "csrf_token": form_token},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert login(client, "user@example.com", "a brand new password").status_code == 303
    logout(client)
    # The token is single-use.
    resp = client.post(
        "/reset-password",
        data={"token": reset_token, "password": "another new password", "csrf_token": form_token},
    )
    assert resp.status_code == 400 and "invalid or has expired" in resp.text


def test_password_change_signs_out_other_sessions(app, client) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    register(client)
    with TestClient(app, base_url="http://testserver") as other:
        assert login(other, "user@example.com").status_code == 303
        token = csrf_of(client, "/settings")
        client.post(
            "/settings/password",
            data={"current_password": PASSWORD, "new_password": "rotated password 1", "csrf_token": token},
            follow_redirects=False,
        )
        assert other.get("/dashboard", follow_redirects=False).status_code == 303
    assert client.get("/dashboard").status_code == 200


# --- CSRF ------------------------------------------------------------------------------------------------


def test_post_without_csrf_token_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    client.get("/login")
    resp = client.post("/login", data={"email": "a@b.co", "password": "x"})
    assert resp.status_code == 403


def test_post_with_forged_token_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    client.get("/login")
    resp = client.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": "0" * 64})
    assert resp.status_code == 403


def test_cross_origin_post_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/login")
    resp = client.post(
        "/login",
        data={"email": "a@b.co", "password": "x", "csrf_token": token},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_csrf_token_bound_to_cookie(app, client) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    token = csrf_of(client, "/login")
    with TestClient(app, base_url="http://testserver") as attacker:
        attacker.get("/login")  # has its own, different cookie
        resp = attacker.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": token})
    assert resp.status_code == 403


# --- audits, authorization and quotas --------------------------------------------------------------------


def _start_audit(client, url: str):  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/audits/new")
    return client.post("/audits", data={"url": url, "csrf_token": token}, follow_redirects=False)


def test_audit_requires_login(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/audits", follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/login?next=%2Faudits"


def test_invalid_audit_urls_are_explained(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    resp = _start_audit(client, "ftp://example.com")
    assert resp.status_code == 400 and "Only http:// and https://" in resp.text
    resp = _start_audit(client, "")
    assert resp.status_code == 400 and "Enter a website address" in resp.text


def test_private_targets_are_refused_in_strict_mode(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from siteaudit import config

    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    config.get_settings.cache_clear()
    assert not config.get_settings().allow_private_targets
    register(client)
    for url in (
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://[::1]/",
        "http://10.0.0.1/",
    ):
        resp = _start_audit(client, url)
        assert resp.status_code == 400, url
        assert "cannot be audited" in resp.text or "public website address" in resp.text, url


def test_users_cannot_access_each_others_audits(app, client, site) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    site.page("/", html_page("Owner site for the IDOR test"))
    register(client, email="owner@example.com")
    location = _start_audit(client, site.base + "/").headers["location"]
    public_id = location.rsplit("/", 1)[1]
    run_queued_audits()
    assert client.get(location).status_code == 200

    with TestClient(app, base_url="http://testserver") as intruder:
        register(intruder, email="intruder@example.com")
        assert intruder.get(location).status_code == 404
        assert intruder.get(location + "/status").status_code == 404
        assert intruder.get(location + "/report.pdf").status_code == 404
        token = csrf_of(intruder, "/dashboard")
        assert intruder.post(location + "/delete", data={"csrf_token": token}).status_code == 404
        assert intruder.post(location + "/cancel", data={"csrf_token": token}).status_code == 404
        assert public_id not in intruder.get("/audits").text
        assert intruder.get("/admin").status_code == 404
    assert client.get(location).status_code == 200


def test_concurrent_and_monthly_limits(client, site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Quota test site home page"))
    register(client)
    assert _start_audit(client, site.base + "/").status_code == 303
    resp = _start_audit(client, site.base + "/")
    assert resp.status_code == 429 and "one audit at a time" in resp.text
    run_queued_audits()
    for _ in range(4):
        assert _start_audit(client, site.base + "/").status_code == 303
        run_queued_audits()
    resp = _start_audit(client, site.base + "/")
    assert resp.status_code == 429 and "used all 5 audits" in resp.text


def test_failed_audits_do_not_consume_quota(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    for _ in range(6):
        assert _start_audit(client, "http://127.0.0.1:9/").status_code == 303
        assert run_queued_audits() == ["failed"]


def test_failed_audit_shows_reason(client) -> None:  # type: ignore[no-untyped-def]
    register(client)
    location = _start_audit(client, "http://127.0.0.1:9/").headers["location"]
    run_queued_audits()
    page = client.get(location).text
    assert "analyse this website" in page and "Audit in progress" not in page
    assert ("refused the connection" in page) or ("could not connect" in page)
    assert "Traceback" not in page


def test_admin_area(client, settings) -> None:  # type: ignore[no-untyped-def]
    register(client, email="boss@example.com")
    from siteaudit.db import session_scope
    from siteaudit.models import User

    with session_scope() as db:
        db.scalar(select(User).where(User.email == "boss@example.com")).role = "admin"
    for path in ("/admin", "/admin/users", "/admin/audits"):
        assert client.get(path).status_code == 200
    with session_scope() as db:
        uid = db.scalar(select(User.id).where(User.email == "boss@example.com"))
    token = csrf_of(client, "/admin/users")
    resp = client.post(
        f"/admin/users/{uid}",
        data={"plan": "pro", "active": "yes", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "Pro" in client.get("/settings").text
    resp = client.post(
        f"/admin/users/{uid}", data={"plan": "pro", "csrf_token": token}, follow_redirects=False
    )
    assert "admin_self_disable" in resp.headers["location"]


def test_account_deletion_removes_data(client, site) -> None:  # type: ignore[no-untyped-def]
    site.page("/", html_page("Site for the deletion test"))
    register(client)
    _start_audit(client, site.base + "/")
    run_queued_audits()
    token = csrf_of(client, "/settings")
    resp = client.post(
        "/settings/delete",
        data={"password": PASSWORD, "confirm": "DELETE", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    from siteaudit.db import session_scope
    from siteaudit.models import Audit, AuditIssue, User

    with session_scope() as db:
        assert db.scalar(select(User)) is None
        assert db.scalar(select(Audit)) is None
        assert db.scalar(select(AuditIssue)) is None
