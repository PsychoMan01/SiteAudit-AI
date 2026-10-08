"""Plan definitions and limits. Prices are configured in the payment provider, not here."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    id: str
    audits_per_month: int
    max_pages: int
    max_depth: int
    concurrent_audits: int
    full_report: bool
    history_days: int | None  # None = unlimited


PLANS: dict[str, Plan] = {
    "free": Plan(
        "free",
        audits_per_month=5,
        max_pages=10,
        max_depth=3,
        concurrent_audits=1,
        full_report=False,
        history_days=30,
    ),
    "pro": Plan(
        "pro",
        audits_per_month=100,
        max_pages=100,
        max_depth=5,
        concurrent_audits=2,
        full_report=True,
        history_days=None,
    ),
    "agency": Plan(
        "agency",
        audits_per_month=500,
        max_pages=500,
        max_depth=6,
        concurrent_audits=5,
        full_report=True,
        history_days=None,
    ),
}


def get_plan(plan_id: str) -> Plan:
    return PLANS.get(plan_id, PLANS["free"])
