"""Public marketing pages, language switch, robots.txt and sitemap.xml."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from ...analysis.registry import CATEGORY_ORDER, rules_for
from ...config import get_settings
from ...i18n import LOCALES
from ...models import User
from ...plans import PLANS
from ...scoring import CATEGORY_WEIGHTS, SEVERITY_WEIGHTS
from ..deps import DB, LOCALE_COOKIE, current_user, redirect, render, safe_next

router = APIRouter()

PUBLIC_PAGES = ("/", "/methodology", "/privacy", "/terms")


@router.get("/")
def landing(request: Request, user: User | None = Depends(current_user)) -> Response:
    return render(request, "landing.html", {"plans": PLANS, "categories": CATEGORY_ORDER}, user=user)


@router.get("/methodology")
def methodology(request: Request, user: User | None = Depends(current_user)) -> Response:
    rules = {c: rules_for(c) for c in CATEGORY_ORDER}
    return render(
        request,
        "methodology.html",
        {"rules": rules, "severity_weights": SEVERITY_WEIGHTS, "category_weights": CATEGORY_WEIGHTS},
        user=user,
    )


@router.get("/privacy")
def privacy(request: Request, user: User | None = Depends(current_user)) -> Response:
    return render(request, "legal_privacy.html", user=user)


@router.get("/terms")
def terms(request: Request, user: User | None = Depends(current_user)) -> Response:
    return render(request, "legal_terms.html", user=user)


@router.get("/bot")
def bot(request: Request, user: User | None = Depends(current_user)) -> Response:
    return render(request, "bot.html", user=user)


@router.post("/lang")
def set_language(
    request: Request,
    lang: str = Form(...),
    next: str = Form("/"),
    user: User | None = Depends(current_user),
    db: Session = DB,
) -> Response:
    if lang not in LOCALES:
        lang = "en"
    if user is not None:
        user.locale = lang
    response = redirect(safe_next(next, "/"))
    response.set_cookie(
        LOCALE_COOKIE,
        lang,
        max_age=60 * 60 * 24 * 365,
        samesite="lax",
        secure=get_settings().secure_cookies,
        httponly=True,
    )
    return response


@router.get("/robots.txt", include_in_schema=False)
def robots() -> PlainTextResponse:
    base = get_settings().app_url
    body = (
        "User-agent: *\n"
        "Disallow: /dashboard\nDisallow: /audits\nDisallow: /settings\nDisallow: /admin\n"
        "Disallow: /reset-password\n"
        f"\nSitemap: {base}/sitemap.xml\n"
    )
    return PlainTextResponse(body)


@router.get("/sitemap.xml", include_in_schema=False)
def sitemap() -> Response:
    base = get_settings().app_url
    urls = "".join(f"<url><loc>{base}{p}</loc></url>" for p in (*PUBLIC_PAGES, "/register"))
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    return Response(xml, media_type="application/xml")
