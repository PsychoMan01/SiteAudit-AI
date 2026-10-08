"""Imports every analyzer module so their rules are registered."""

from __future__ import annotations

from . import accessibility, best_practices, mobile, performance, security, seo  # noqa: F401
from .base import RULES, Rule

CATEGORY_ORDER = ("seo", "performance", "accessibility", "mobile", "security", "best_practices")


def rules_for(category: str) -> list[Rule]:
    return sorted((r for r in RULES.values() if r.category == category), key=lambda r: r.id)
