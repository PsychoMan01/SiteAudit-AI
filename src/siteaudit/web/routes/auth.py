"""Registration, login, logout and password reset."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audits.service import AuditRequestError, create_audit
from ...config import get_settings
from ...i18n import t
from ...mailer import send_email
from ...models import User
from ...security import auth as A
from ..deps import (
    DB,
    SESSION_COOKIE,
    client_ip,
    current_user,
    redirect,
    render,
    request_locale,
    safe_next,
)

router = APIRouter()
log = logging.getLogger(__name__)


def _login_response(db: Session, user: User, target: str) -> Response:
    token = A.create_session(db, user)
    response = redirect(target)
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


def _start_pending_audit(db: Session, user: User, url: str) -> str:
    """When a visitor typed a URL on the landing page before signing up, start that audit right away."""
    if not url:
        return "/dashboard"
    try:
        audit = create_audit(db, user, url, get_settings())
    except AuditRequestError as exc:
        return (
            f"/dashboard?msg=audit_{exc.code}"
            if exc.code in ("monthly_limit", "too_many_running")
            else ("/dashboard?msg=audit_invalid_url")
        )
    return f"/audits/{audit.public_id}"


@router.get("/register")
def register_form(request: Request, url: str = "", user: User | None = Depends(current_user)) -> Response:
    if user is not None:
        return redirect("/dashboard")
    return render(request, "auth/register.html", {"url": url[:2048], "values": {}})


@router.post("/register")
def register(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    name: str = Form(""),
    url: str = Form(""),
    accept_terms: str = Form(""),
    db: Session = DB,
) -> Response:
    ip = client_ip(request)
    values = {"email": email[:254], "name": name[:100]}
    if A.throttled(db, "register", ip, A.REGISTER_MAX_PER_IP, A.REGISTER_WINDOW):
        return render(
            request,
            "auth/register.html",
            {"error": "too_many_attempts", "values": values, "url": url},
            status_code=429,
        )
    if accept_terms != "yes":
        return render(
            request,
            "auth/register.html",
            {"error": "terms_required", "values": values, "url": url},
            status_code=400,
        )
    try:
        user = A.create_user(db, email, password, name, locale=request_locale(request))
    except A.AuthError as exc:
        return render(
            request, "auth/register.html", {"error": exc.code, "values": values, "url": url}, status_code=400
        )
    A.record_event(db, "register", ip=ip)
    log.info("user registered", extra={"event": "user_registered", "user_id": user.id})
    return _login_response(db, user, _start_pending_audit(db, user, url))


@router.get("/login")
def login_form(request: Request, next: str = "", user: User | None = Depends(current_user)) -> Response:
    if user is not None:
        return redirect(safe_next(next))
    return render(request, "auth/login.html", {"next": safe_next(next), "values": {}})


@router.post("/login")
def login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    next: str = Form("/dashboard"),
    db: Session = DB,
) -> Response:
    settings = get_settings()
    ip = client_ip(request)
    email_hash = A.email_digest(A.normalize_email(email), settings.session_secret)
    ctx = {"next": safe_next(next), "values": {"email": email[:254]}}
    if A.login_throttled(db, email_hash, ip):
        return render(request, "auth/login.html", {**ctx, "error": "too_many_attempts"}, status_code=429)
    user = A.authenticate(db, email, password[: A.MAX_PASSWORD])
    if user is None:
        A.record_event(db, "login_failed", email_hash=email_hash, ip=ip)
        log.info("login failed", extra={"event": "login_failed"})
        return render(request, "auth/login.html", {**ctx, "error": "invalid_credentials"}, status_code=400)
    A.record_event(db, "login_ok", email_hash=email_hash, ip=ip)
    return _login_response(db, user, safe_next(next))


@router.post("/logout")
def logout(request: Request, db: Session = DB) -> Response:
    A.destroy_session(db, request.cookies.get(SESSION_COOKIE))
    response = redirect("/")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/forgot-password")
def forgot_form(request: Request) -> Response:
    return render(request, "auth/forgot.html", {"sent": False})


@router.post("/forgot-password")
def forgot(request: Request, email: str = Form(""), db: Session = DB) -> Response:
    settings = get_settings()
    ip = client_ip(request)
    if A.throttled(db, "reset_requested", ip, A.RESET_MAX_PER_IP, A.LOGIN_WINDOW):
        return render(
            request, "auth/forgot.html", {"sent": False, "error": "too_many_attempts"}, status_code=429
        )
    A.record_event(db, "reset_requested", ip=ip)
    user = db.scalar(select(User).where(User.email == A.normalize_email(email)))
    if user is not None and user.is_active:
        token = A.create_reset_token(db, user)
        link = f"{settings.app_url}/reset-password?token={token}"
        loc = user.locale
        send_email(settings, user.email, t(loc, "email.reset.subject"), t(loc, "email.reset.body", link=link))
    # Same response whether or not the account exists (no account enumeration).
    return render(request, "auth/forgot.html", {"sent": True})


@router.get("/reset-password")
def reset_form(request: Request, token: str = "", db: Session = DB) -> Response:
    valid = A.find_reset_token(db, token) is not None
    return render(request, "auth/reset.html", {"token": token if valid else "", "invalid": not valid})


@router.post("/reset-password")
def reset(request: Request, token: str = Form(""), password: str = Form(""), db: Session = DB) -> Response:
    try:
        A.consume_reset_token(db, token, password)
    except A.AuthError as exc:
        invalid = exc.code == "reset_invalid"
        return render(
            request,
            "auth/reset.html",
            {"token": "" if invalid else token, "invalid": invalid, "error": exc.code},
            status_code=400,
        )
    return redirect("/login", "password_reset")
