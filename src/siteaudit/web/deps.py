"""Request-scoped helpers: database session, current user, CSRF, rendering."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import session_factory
from ..i18n import LOCALES, has, pick_locale, t, tn
from ..models import User
from ..scoring import grade
from ..security import csrf
from ..security.auth import resolve_session

SESSION_COOKIE = "sa_session"
LOCALE_COOKIE = "sa_lang"
TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals.update(grade=grade)


def get_db() -> Iterator[Session]:
    """One session per request. Always declare it as `Depends(get_db, scope="function")` so the commit
    happens *before* the response is sent; otherwise a client can follow a redirect faster than the
    commit (e.g. a new login session not yet visible on the next request)."""
    db = session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


DB = Depends(get_db, scope="function")
"""Default for every `db: Session` route parameter: committed before the response is sent (see `get_db`)."""


def client_ip(request: Request, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    peer = request.client.host if request.client else ""
    if peer and settings.trusted_proxies and _in_networks(peer, settings.trusted_proxies):
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if hops:
            return hops[-1][:64]
    return peer[:64]


def _in_networks(ip: str, networks: tuple[str, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


@dataclass(frozen=True)
class UserView:
    """Detached, read-only copy of the signed-in user for templates rendered outside the request's DB
    session (error pages): the ORM object may already be expired after a rollback."""

    id: int
    email: str
    name: str
    locale: str
    is_admin: bool


def current_user(request: Request, db: Session = DB) -> User | None:
    if hasattr(request.state, "user"):
        cached: User | None = request.state.user
        return cached
    user = resolve_session(db, request.cookies.get(SESSION_COOKIE))
    request.state.user = user
    request.state.user_view = (
        None if user is None else UserView(user.id, user.email, user.name, user.locale, user.is_admin)
    )
    return user


class LoginRequired(Exception):
    pass


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise LoginRequired()
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=404)
    return user


def request_locale(request: Request, user: User | UserView | None = None) -> str:
    if user is not None and user.locale in LOCALES:
        return user.locale
    return pick_locale(request.headers.get("accept-language"), request.cookies.get(LOCALE_COOKIE))


async def csrf_protect(request: Request) -> None:
    """Applied to every route; only state-changing methods are checked."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    settings = get_settings()
    origin = request.headers.get("origin")
    if origin and origin != "null":
        expected = {_origin(settings.app_url), _origin(str(request.base_url))}
        if _origin(origin) not in expected:
            raise HTTPException(status_code=403, detail="origin")
    seed = request.cookies.get(csrf.COOKIE_NAME)
    token = request.headers.get("x-csrf-token")
    if token is None:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()
            value = form.get(csrf.FIELD_NAME)
            token = value if isinstance(value, str) else None
    if not csrf.valid(seed, token, settings.session_secret):
        raise HTTPException(status_code=403, detail="csrf")


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def csrf_seed(request: Request) -> str:
    seed = request.cookies.get(csrf.COOKIE_NAME) or getattr(request.state, "csrf_seed", None)
    if not seed:
        seed = csrf.new_seed()
    request.state.csrf_seed = seed
    return seed


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    user: User | UserView | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    settings = get_settings()
    if user is None:
        user = getattr(request.state, "user_view", None)
    locale = request_locale(request, user)
    seed = csrf_seed(request)

    def tr(key: str, **params: Any) -> str:
        return t(locale, key, **params)

    def tr_n(key: str, n: int, **params: Any) -> str:
        return tn(locale, key, n, **params)

    def tr_has(key: str) -> bool:
        return has(locale, key)

    msg = request.query_params.get("msg", "")
    ctx: dict[str, Any] = {
        "request": request,
        "user": user,
        "locale": locale,
        "t": tr,
        "t_has": tr_has,
        "tn": tr_n,
        "csrf_token": csrf.token_for(seed, settings.session_secret),
        "settings": settings,
        "flash": f"flash.{msg}" if msg and has(locale, f"flash.{msg}") else None,
        "path": request.url.path,
    }
    ctx.update(context or {})
    return templates.TemplateResponse(request, template, ctx, status_code=status_code)


def redirect(url: str, msg: str | None = None) -> RedirectResponse:
    if msg:
        url = f"{url}{'&' if '?' in url else '?'}msg={msg}"
    return RedirectResponse(url, status_code=303)


def safe_next(value: str | None, default: str = "/dashboard") -> str:
    """Only allow local, absolute-path redirects (prevents open redirects)."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    return value
