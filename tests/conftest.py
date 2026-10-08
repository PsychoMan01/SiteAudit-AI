"""Shared fixtures: isolated settings and database, a real local HTTP test site, a web client."""

from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

# Settings are read from the environment; set them before the application is imported.
os.environ.update(
    {
        "APP_ENV": "test",
        "SESSION_SECRET": "test-secret-0123456789-0123456789-abcdef",
        "ALLOW_PRIVATE_TARGETS": "true",
        "WORKER_EMBEDDED": "false",
        "CRAWL_DELAY": "0",
        "CRAWL_REQUEST_TIMEOUT": "3",
        "AI_PROVIDER": "none",
        "LOG_LEVEL": "WARNING",
        "APP_URL": "http://testserver",
    }
)


@dataclass
class Route:
    status: int = 200
    body: bytes | str = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0


class SiteServer:
    """A tiny programmable HTTP server on 127.0.0.1 used as the site under audit."""

    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.hits: list[tuple[str, str, dict[str, str]]] = []
        self.hit_times: list[float] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self, with_body: bool) -> None:
                path = self.path.split("#", 1)[0]
                server.hits.append((self.command, path, dict(self.headers.items())))
                server.hit_times.append(time.monotonic())
                route = server.routes.get(path) or server.routes.get(path.split("?", 1)[0])
                if route is None:
                    route = Route(
                        404,
                        "<!doctype html><title>Not found</title><h1>Not found</h1>",
                        {"Content-Type": "text/html; charset=utf-8"},
                    )
                if route.delay:
                    time.sleep(route.delay)
                body = route.body.encode() if isinstance(route.body, str) else route.body
                self.send_response(route.status)
                headers = {"Content-Type": "text/html; charset=utf-8", **route.headers}
                for k, v in headers.items():
                    if k.lower() == "set-cookie":
                        for cookie in v.split("\n"):
                            self.send_header("Set-Cookie", cookie)
                    else:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if with_body:
                    self.wfile.write(body)

            def do_GET(self) -> None:
                self._serve(True)

            def do_HEAD(self) -> None:
                self._serve(False)

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.handle_error = lambda *_args: None  # client hang-ups are expected in some tests
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def add(self, path: str, body: bytes | str = b"", status: int = 200, **headers: str) -> None:
        hdrs = {k.replace("_", "-"): v for k, v in headers.items()}
        self.routes[path] = Route(status, body, hdrs)

    def page(self, path: str, body: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.routes[path] = Route(status, body, headers or {})

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def site() -> Iterator[SiteServer]:
    server = SiteServer()
    yield server
    server.close()


def html_page(
    title: str = "A good page title for tests", body: str = "", head: str = "", lang: str = "en"
) -> str:
    words = " ".join(["Readable content about the topic of this page."] * 40)
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title}</title>"
        f'<meta name="description" content="{title}: a description long enough to fall between seventy and one hundred sixty characters.">'
        f"{head}</head><body><main><h1>{title}</h1>{body}<p>{words}</p></main></body></html>"
    )


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from siteaudit import config

    config.get_settings.cache_clear()
    s = config.get_settings()
    from siteaudit.db import init_engine
    from siteaudit.migrations_config import upgrade

    upgrade(s)
    init_engine(s)
    yield s
    config.get_settings.cache_clear()


@pytest.fixture
def app(settings):  # type: ignore[no-untyped-def]
    from siteaudit.web.app import create_app

    return create_app(settings)


@pytest.fixture
def client(app):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="http://testserver") as c:
        yield c


_CSRF = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')


def csrf_of(client, path: str = "/login") -> str:  # type: ignore[no-untyped-def]
    resp = client.get(path)
    match = _CSRF.search(resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def register(client, email: str = "user@example.com", password: str = "correct horse battery", url: str = ""):  # type: ignore[no-untyped-def]
    token = csrf_of(client, "/register")
    return client.post(
        "/register",
        data={
            "email": email,
            "password": password,
            "name": "Test",
            "accept_terms": "yes",
            "csrf_token": token,
            "url": url,
        },
        follow_redirects=False,
    )


def run_queued_audits() -> list[str]:
    """Run every queued audit synchronously (what the worker does)."""
    from siteaudit.audits.service import claim_next, run_audit
    from siteaudit.config import get_settings
    from siteaudit.db import session_scope

    statuses = []
    while True:
        with session_scope() as db:
            audit_id = claim_next(db)
        if audit_id is None:
            return statuses
        statuses.append(run_audit(audit_id, get_settings()))


@pytest.fixture
def helpers() -> dict[str, Callable[..., object]]:
    return {"csrf_of": csrf_of, "register": register, "run": run_queued_audits, "html": html_page}
