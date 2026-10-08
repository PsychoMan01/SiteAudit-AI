"""Structured logging with secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)(\"?\s*[:=]\s*\"?)([^\s\"&,;]+)"
    ),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]+)"),
]


def redact(text: str) -> str:
    # Bearer tokens first, so "Authorization: Bearer x" does not leave the token behind.
    text = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    return _SECRET_PATTERNS[0].sub(
        lambda m: m.group(0) if m.group(3).startswith("Bearer") else f"{m.group(1)}{m.group(2)}[REDACTED]",
        text,
    )


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


class JsonFormatter(logging.Formatter):
    _EXTRA = ("audit_id", "user_id", "event", "path", "status", "duration_ms", "error_code")

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in self._EXTRA:
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Never log request URLs with query strings from the HTTP client libraries.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("fontTools").setLevel(logging.WARNING)
    logging.getLogger("weasyprint").setLevel(logging.ERROR)
