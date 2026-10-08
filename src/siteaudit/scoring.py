"""Deterministic, documented scoring (see SCORING.md).

Per category, every rule that failed deducts points once, based on its severity. Page-level rules are
scaled by how many of the audited pages they affect:

    deduction = weight(severity) × (0.5 + 0.5 × affected_pages / audited_pages)

Category score = max(0, 100 − Σ deductions), rounded. Categories in which no rule could be evaluated
get no score (shown as "not scored") and are excluded from the overall score.

Overall = weighted mean of the scored categories (weights below, renormalized over scored categories).
"""

from __future__ import annotations

from dataclasses import dataclass

from .analysis.base import RULES, AnalysisResult

SEVERITY_WEIGHTS = {"critical": 25.0, "high": 12.0, "medium": 6.0, "low": 2.0, "info": 0.0}
CATEGORY_WEIGHTS = {
    "seo": 0.20,
    "performance": 0.20,
    "accessibility": 0.20,
    "security": 0.20,
    "mobile": 0.10,
    "best_practices": 0.10,
}


@dataclass(frozen=True)
class CategoryScore:
    category: str
    score: int | None
    checks_run: int
    checks_failed: int
    deduction: float


@dataclass(frozen=True)
class ScoreCard:
    overall: int | None
    categories: dict[str, CategoryScore]


def score(result: AnalysisResult) -> ScoreCard:
    pages = max(1, result.html_page_count)
    affected: dict[str, set[str | None]] = {}
    for finding in result.findings:
        affected.setdefault(finding.rule_id, set()).add(finding.page_url)

    categories: dict[str, CategoryScore] = {}
    for category in CATEGORY_WEIGHTS:
        evaluated = result.evaluated.get(category, set())
        deduction = 0.0
        failed = 0
        for rule_id in sorted(evaluated):
            if rule_id not in affected:
                continue
            rule = RULES[rule_id]
            weight = SEVERITY_WEIGHTS[rule.severity]
            if weight == 0:
                continue
            failed += 1
            if rule.scope == "page":
                share = min(1.0, len(affected[rule_id]) / pages)
                deduction += weight * (0.5 + 0.5 * share)
            else:
                deduction += weight
        value = None if not evaluated else max(0, round(100 - deduction))
        categories[category] = CategoryScore(category, value, len(evaluated), failed, round(deduction, 2))

    scored = {c: s.score for c, s in categories.items() if s.score is not None}
    overall = None
    if scored:
        total_weight = sum(CATEGORY_WEIGHTS[c] for c in scored)
        overall = round(sum(CATEGORY_WEIGHTS[c] * v for c, v in scored.items()) / total_weight)
    return ScoreCard(overall, categories)


def grade(value: int | None) -> str:
    """Band used for colour and wording only; never changes the number."""
    if value is None:
        return "none"
    if value >= 90:
        return "good"
    if value >= 70:
        return "fair"
    if value >= 50:
        return "poor"
    return "bad"
