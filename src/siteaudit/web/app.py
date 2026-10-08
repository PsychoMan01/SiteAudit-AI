"""FastAPI application factory."""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..config import Settings, get_settings
from ..db import init_engine
from ..logging_setup import configure_logging
from ..security import csrf
from ..security.ratelimit import RateLimiter
from .deps import LoginRequired, client_ip, csrf_protect, redirect, render
from .routes import admin, app_routes, auth, health, public

log = logging.getLogger("siteaudit.web")
STATIC_DIR = Path(__file__).parent / "static"


def _csp(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    init_engine(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        worker = None
        if settings.worker_embedded:
            from ..worker import Worker

            worker = Worker(settings)
            worker.start_background()
        yield
        if worker is not None:
            worker.stop()

    app = FastAPI(
        title="SiteAudit AI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        dependencies=[Depends(csrf_protect)],
    )
    app.state.settings = settings
    burst_limiter = RateLimiter(limit=240, window_seconds=60)
    post_limiter = RateLimiter(limit=30, window_seconds=60)
    app.state.limiters = (burst_limiter, post_limiter)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        started = time.monotonic()
        ip = client_ip(request, settings)
        if not request.url.path.startswith("/static/") and request.url.path != "/health":
            limiter = post_limiter if request.method == "POST" else burst_limiter
            if not limiter.allow(f"{request.method == 'POST'}:{ip}"):
                return PlainTextResponse(
                    "Too many requests. Please wait a minute and try again.",
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
        request.state.csp_nonce = secrets.token_urlsafe(16)
        response: Response = await call_next(request)

        seed = getattr(request.state, "csrf_seed", None)
        if seed and request.cookies.get(csrf.COOKIE_NAME) != seed:
            response.set_cookie(
                csrf.COOKIE_NAME,
                seed,
                httponly=True,
                secure=settings.secure_cookies,
                samesite="lax",
                max_age=60 * 60 * 24 * 7,
                path="/",
            )
        h = response.headers
        h.setdefault("Content-Security-Policy", _csp(request.state.csp_nonce))
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if settings.secure_cookies:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith(
            (
                "/dashboard",
                "/audits",
                "/settings",
                "/admin",
                "/login",
                "/register",
                "/reset-password",
                "/forgot-password",
            )
        ):
            h.setdefault("Cache-Control", "no-store")
        if response.status_code >= 500:
            log.error(
                "request failed",
                extra={"event": "http_error", "path": request.url.path, "status": response.status_code},
            )
        log.debug(
            "request",
            extra={
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
        return response

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    for module in (public, auth, app_routes, admin, health):
        app.include_router(module.router)

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, _exc: LoginRequired) -> Response:
        if request.url.path.endswith("/status"):
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        from urllib.parse import quote

        return redirect(f"/login?next={quote(target, safe='')}")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if request.url.path.endswith("/status") or request.url.path == "/health":
            return JSONResponse({"error": exc.status_code}, status_code=exc.status_code)
        key = {403: "forbidden", 404: "not_found", 405: "not_found"}.get(exc.status_code, "generic")
        return render(
            request, "error.html", {"error_key": key, "code": exc.status_code}, status_code=exc.status_code
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> Response:
        log.exception("unhandled error", extra={"event": "unhandled", "path": request.url.path})
        return render(request, "error.html", {"error_key": "generic", "code": 500}, status_code=500)

    _ = HTTPException  # re-exported for routers
    return app
