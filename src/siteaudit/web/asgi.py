"""ASGI entry point: `uvicorn siteaudit.web.asgi:app`."""

from .app import create_app

app = create_app()
