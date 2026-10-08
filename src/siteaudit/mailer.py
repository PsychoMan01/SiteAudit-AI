"""Transactional e-mail. Uses SMTP when configured; otherwise writes messages to `DATA_DIR/outbox/` so local
development works without an e-mail provider. Message bodies are never logged."""

from __future__ import annotations

import logging
import smtplib
import ssl
import uuid
from email.message import EmailMessage

from .config import Settings

log = logging.getLogger(__name__)


def send_email(settings: Settings, to: str, subject: str, body: str) -> bool:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if not settings.smtp_host:
        outbox = settings.data_dir / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / f"{uuid.uuid4().hex}.eml").write_bytes(bytes(msg))
        log.info("e-mail written to outbox (SMTP not configured)", extra={"event": "email_outbox"})
        return True
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
            if settings.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        log.error("e-mail delivery failed: %s", type(exc).__name__, extra={"event": "email_failed"})
        return False
