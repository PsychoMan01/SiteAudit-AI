"""Background worker: claims queued audits from the database and runs them in a bounded thread pool.

Run standalone with `siteaudit worker`, or embedded in the web process for development
(`WORKER_EMBEDDED=true`).
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import select

from .audits.retention import purge_expired
from .audits.service import claim_next, fail_stale, run_audit
from .config import Settings
from .db import session_scope
from .models import WorkerHeartbeat, utcnow
from .security.auth import prune_events, prune_sessions

log = logging.getLogger(__name__)

POLL_SECONDS = 1.0
MAINTENANCE_SECONDS = 60.0


class Worker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.name = f"{socket.gethostname()}:{os.getpid()}"
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=settings.worker_concurrency, thread_name_prefix="audit")
        self._running: set[Future[str]] = set()
        self._thread: threading.Thread | None = None

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.run_forever, name="audit-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self._pool.shutdown(wait=False, cancel_futures=True)

    def beat(self) -> None:
        with session_scope() as db:
            row = db.get(WorkerHeartbeat, self.name)
            if row is None:
                db.add(WorkerHeartbeat(name=self.name, beat_at=utcnow()))
            else:
                row.beat_at = utcnow()

    def maintenance(self) -> None:
        with session_scope() as db:
            stale = fail_stale(db)
            if stale:
                log.warning("marked %d stale audits as failed", stale, extra={"event": "audits_stale"})
            prune_sessions(db)
            prune_events(db)
            purged = purge_expired(db)
            if purged:
                log.info("purged %d expired audits", purged, extra={"event": "audits_purged"})

    def tick(self) -> bool:
        """Claim at most one audit if there is capacity. Returns True if one was started."""
        self._running = {f for f in self._running if not f.done()}
        if len(self._running) >= self.settings.worker_concurrency:
            return False
        with session_scope() as db:
            audit_id = claim_next(db)
        if audit_id is None:
            return False
        self._running.add(self._pool.submit(run_audit, audit_id, self.settings))
        return True

    def run_forever(self) -> None:
        log.info("worker %s started (concurrency=%d)", self.name, self.settings.worker_concurrency)
        last_maintenance = 0.0
        last_beat = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now - last_beat >= 10:
                    self.beat()
                    last_beat = now
                if now - last_maintenance >= MAINTENANCE_SECONDS:
                    self.maintenance()
                    last_maintenance = now
                if self.tick():
                    continue
            except Exception:
                log.exception("worker loop error")
            self._stop.wait(POLL_SECONDS)
        log.info("worker %s stopped", self.name)


def worker_alive(max_age_seconds: int = 60) -> bool:
    with session_scope() as db:
        latest = db.scalar(select(WorkerHeartbeat.beat_at).order_by(WorkerHeartbeat.beat_at.desc()).limit(1))
    return latest is not None and utcnow() - latest <= timedelta(seconds=max_age_seconds)
