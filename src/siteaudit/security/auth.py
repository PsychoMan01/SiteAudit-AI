"""Passwords, sessions, password-reset tokens and brute-force throttling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models import AuthEvent, PasswordResetToken, Subscription, User, UserSession, utcnow

SESSION_TTL = timedelta(days=14)
SESSION_TOUCH_INTERVAL = timedelta(minutes=10)
RESET_TTL = timedelta(hours=1)
MIN_PASSWORD = 10
MAX_PASSWORD = 256

# Brute-force limits (sliding window).
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_MAX_PER_EMAIL = 5
LOGIN_MAX_PER_IP = 20
RESET_MAX_PER_IP = 5
REGISTER_MAX_PER_IP = 5
REGISTER_WINDOW = timedelta(hours=1)

_hasher = PasswordHasher()
# Used to equalise timing when the e-mail does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


class AuthError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def email_digest(email: str, secret: str) -> str:
    return hmac.new(secret.encode(), email.lower().encode(), hashlib.sha256).hexdigest()


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_email(email: str) -> bool:
    if not 3 <= len(email) <= 254 or email.count("@") != 1:
        return False
    local, domain = email.split("@")
    return bool(local) and "." in domain and not domain.startswith(".") and " " not in email


def validate_password(password: str, email: str = "") -> str | None:
    if len(password) < MIN_PASSWORD:
        return "password_too_short"
    if len(password) > MAX_PASSWORD:
        return "password_too_long"
    if email and password.lower() == email.lower():
        return "password_is_email"
    return None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored: str, password: str) -> bool:
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# --- throttling ---------------------------------------------------------------------------------------


def record_event(db: Session, kind: str, *, email_hash: str = "", ip: str = "") -> None:
    db.add(AuthEvent(kind=kind, email_hash=email_hash, ip=ip))


def _count(
    db: Session, kind: str, window: timedelta, *, email_hash: str | None = None, ip: str | None = None
) -> int:
    q = select(func.count(AuthEvent.id)).where(
        AuthEvent.kind == kind, AuthEvent.created_at >= utcnow() - window
    )
    if email_hash is not None:
        q = q.where(AuthEvent.email_hash == email_hash)
    if ip is not None:
        q = q.where(AuthEvent.ip == ip)
    return int(db.scalar(q) or 0)


def login_throttled(db: Session, email_hash: str, ip: str) -> bool:
    return (
        _count(db, "login_failed", LOGIN_WINDOW, email_hash=email_hash) >= LOGIN_MAX_PER_EMAIL
        or _count(db, "login_failed", LOGIN_WINDOW, ip=ip) >= LOGIN_MAX_PER_IP
    )


def throttled(db: Session, kind: str, ip: str, limit: int, window: timedelta) -> bool:
    return _count(db, kind, window, ip=ip) >= limit


def prune_events(db: Session, older_than: timedelta = timedelta(days=2)) -> None:
    db.execute(delete(AuthEvent).where(AuthEvent.created_at < utcnow() - older_than))


# --- users ----------------------------------------------------------------------------------------------


def create_user(db: Session, email: str, password: str, name: str = "", locale: str = "en") -> User:
    email = normalize_email(email)
    if not validate_email(email):
        raise AuthError("invalid_email")
    problem = validate_password(password, email)
    if problem:
        raise AuthError(problem)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise AuthError("email_taken")
    user = User(email=email, name=name.strip()[:100], password_hash=hash_password(password), locale=locale)
    user.subscription = Subscription(plan="free", status="active", provider="manual")
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, email: str, password: str) -> User | None:
    email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(_DUMMY_HASH, password)
        return None
    if not verify_password(user.password_hash, password) or not user.is_active:
        return None
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = utcnow()
    return user


# --- sessions -------------------------------------------------------------------------------------------


def create_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(UserSession(user_id=user.id, token_hash=hash_token(token), expires_at=utcnow() + SESSION_TTL))
    return token


def resolve_session(db: Session, token: str | None) -> User | None:
    if not token or len(token) > 128:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    now = utcnow()
    if sess is None or sess.expires_at <= now:
        return None
    user = sess.user
    if not user.is_active:
        return None
    if now - sess.last_seen_at > SESSION_TOUCH_INTERVAL:
        sess.last_seen_at = now
        sess.expires_at = now + SESSION_TTL
    return user


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))


def destroy_all_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))


def prune_sessions(db: Session) -> None:
    db.execute(delete(UserSession).where(UserSession.expires_at < utcnow()))


# --- password reset -------------------------------------------------------------------------------------


def create_reset_token(db: Session, user: User) -> str:
    db.execute(
        delete(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)
        )
    )
    token = secrets.token_urlsafe(32)
    db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(token), expires_at=utcnow() + RESET_TTL))
    return token


def find_reset_token(db: Session, token: str) -> PasswordResetToken | None:
    if not token or len(token) > 128:
        return None
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token)))
    if row is None or row.used_at is not None or row.expires_at <= utcnow():
        return None
    return row


def consume_reset_token(db: Session, token: str, new_password: str) -> User:
    row = find_reset_token(db, token)
    if row is None:
        raise AuthError("reset_invalid")
    user = row.user
    problem = validate_password(new_password, user.email)
    if problem:
        raise AuthError(problem)
    user.password_hash = hash_password(new_password)
    row.used_at = utcnow()
    destroy_all_sessions(db, user.id)
    return user
