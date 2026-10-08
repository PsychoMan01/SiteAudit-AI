"""Smoke test against a real uvicorn server (catches issues the in-process TestClient cannot, such as
work that happens after the response has been sent)."""

from __future__ import annotations

import re
import socket
import threading
import time

import httpx
import uvicorn


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_login_session_is_usable_immediately(app) -> None:  # type: ignore[no-untyped-def]
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        with httpx.Client(base_url=base, follow_redirects=False) as client:
            token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', client.get("/register").text).group(1)
            resp = client.post(
                "/register",
                data={
                    "email": "live@example.com",
                    "password": "live server pass",
                    "accept_terms": "yes",
                    "csrf_token": token,
                },
            )
            assert resp.status_code == 303
            # Follow the redirect immediately, like a browser does.
            for _ in range(20):
                assert client.get("/dashboard").status_code == 200
            assert client.get("/health").json()["checks"]["database"] is True
    finally:
        server.should_exit = True
        thread.join(5)
