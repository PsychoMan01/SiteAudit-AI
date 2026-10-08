"""CSRF protection: signed double-submit token.

A random value lives in an HttpOnly cookie; forms carry `HMAC(secret, value)`. A POST is accepted only when
the form token matches the cookie under the server secret. Combined with SameSite=Lax cookies and an
Origin check, this covers both anonymous (login, register) and authenticated forms.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

COOKIE_NAME = "sa_csrf"
FIELD_NAME = "csrf_token"


def new_seed() -> str:
    return secrets.token_urlsafe(24)


def token_for(seed: str, secret: str) -> str:
    return hmac.new(secret.encode(), f"csrf:{seed}".encode(), hashlib.sha256).hexdigest()


def valid(seed: str | None, token: str | None, secret: str) -> bool:
    if not seed or not token or len(seed) > 64 or len(token) > 128:
        return False
    return hmac.compare_digest(token_for(seed, secret), token)
