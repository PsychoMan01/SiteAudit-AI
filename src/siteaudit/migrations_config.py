"""Programmatic Alembic configuration (no alembic.ini needed at runtime)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from .config import Settings, get_settings


def alembic_config(settings: Settings | None = None) -> Config:
    settings = settings or get_settings()
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    return cfg


def upgrade(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.database_url.startswith("sqlite"):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(settings), "head")
