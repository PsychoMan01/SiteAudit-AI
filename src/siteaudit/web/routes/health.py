"""Health check for load balancers and monitoring."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ... import __version__
from ...db import ping

router = APIRouter()


@router.get("/health")
def health() -> JSONResponse:
    from ...worker import worker_alive

    database = ping()
    try:
        worker = worker_alive() if database else False
    except Exception:
        worker = False
    # The web tier is healthy if it can reach the database. A missing worker degrades the service
    # (audits stay queued) and is reported, but does not take the web tier out of rotation.
    status = "ok" if database and worker else ("degraded" if database else "error")
    return JSONResponse(
        {"status": status, "version": __version__, "checks": {"database": database, "worker": worker}},
        status_code=200 if database else 503,
        headers={"Cache-Control": "no-store"},
    )
