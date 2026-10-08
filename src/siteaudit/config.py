"""Application settings, read from environment variables (and an optional `.env` file)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def _load_dotenv(path: Path) -> None:
    """Minimal `.env` loader. Real environment variables always win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc


@dataclass(frozen=True)
class Settings:
    app_env: str
    app_url: str
    database_url: str
    session_secret: str
    data_dir: Path
    log_level: str
    log_format: str

    # Worker / crawler
    worker_concurrency: int
    worker_embedded: bool
    crawl_request_timeout: float
    crawl_audit_timeout: float
    crawl_delay: float
    crawl_max_response_bytes: int
    crawl_user_agent: str
    allow_private_targets: bool

    # AI (optional)
    ai_provider: str
    ai_api_key: str
    ai_base_url: str
    ai_model: str
    ai_timeout: float

    # E-mail (optional; without SMTP, messages are written to the outbox directory)
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_starttls: bool

    contact_email: str
    trusted_proxies: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def secure_cookies(self) -> bool:
        return self.app_url.startswith("https://")


_DEV_SECRET = "dev-insecure-secret-change-me-0000000000000000"  # noqa: S105 - development only, refused in production


def load_settings(env_file: Path | None = None) -> Settings:
    _load_dotenv(env_file or Path.cwd() / ".env")
    app_env = os.environ.get("APP_ENV", "development").strip().lower()
    if app_env not in {"development", "test", "production"}:
        raise ConfigError("APP_ENV must be development, test or production")

    data_dir = Path(os.environ.get("DATA_DIR", "var")).resolve()
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        if app_env == "production":
            raise ConfigError("SESSION_SECRET is required in production")
        secret = _DEV_SECRET
    if app_env == "production" and len(secret) < 32:
        raise ConfigError("SESSION_SECRET must be at least 32 characters")

    allow_private = _bool("ALLOW_PRIVATE_TARGETS", False)
    if allow_private and app_env == "production":
        raise ConfigError("ALLOW_PRIVATE_TARGETS cannot be enabled in production")

    app_url = os.environ.get("APP_URL", "http://localhost:8000").rstrip("/")
    if app_env == "production" and not app_url.startswith("https://"):
        raise ConfigError("APP_URL must use https:// in production")

    database_url = os.environ.get("DATABASE_URL", "") or f"sqlite:///{data_dir / 'siteaudit.db'}"

    return Settings(
        app_env=app_env,
        app_url=app_url,
        database_url=database_url,
        session_secret=secret,
        data_dir=data_dir,
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        log_format=os.environ.get("LOG_FORMAT", "json" if app_env == "production" else "text"),
        worker_concurrency=max(1, _int("WORKER_CONCURRENCY", 2)),
        worker_embedded=_bool("WORKER_EMBEDDED", app_env == "development"),
        crawl_request_timeout=_float("CRAWL_REQUEST_TIMEOUT", 10.0),
        crawl_audit_timeout=_float("CRAWL_AUDIT_TIMEOUT", 300.0),
        crawl_delay=_float("CRAWL_DELAY", 0.5),
        crawl_max_response_bytes=_int("CRAWL_MAX_RESPONSE_BYTES", 5 * 1024 * 1024),
        crawl_user_agent=os.environ.get("CRAWL_USER_AGENT", f"SiteAuditBot/0.1 (+{app_url}/bot)"),
        allow_private_targets=allow_private,
        ai_provider=os.environ.get("AI_PROVIDER", "none").strip().lower(),
        ai_api_key=os.environ.get("AI_API_KEY", ""),
        ai_base_url=os.environ.get("AI_BASE_URL", ""),
        ai_model=os.environ.get("AI_MODEL", ""),
        ai_timeout=_float("AI_TIMEOUT", 60.0),
        smtp_host=os.environ.get("SMTP_HOST", ""),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.environ.get("SMTP_USER", ""),
        smtp_password=os.environ.get("SMTP_PASSWORD", ""),
        smtp_from=os.environ.get("SMTP_FROM", "SiteAudit <no-reply@localhost>"),
        smtp_starttls=_bool("SMTP_STARTTLS", True),
        contact_email=os.environ.get("CONTACT_EMAIL", ""),
        trusted_proxies=tuple(
            p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
        ),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
