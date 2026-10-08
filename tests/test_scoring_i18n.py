"""Scoring formula and translation catalogue completeness."""

from __future__ import annotations

import re
import string
from pathlib import Path

import pytest

from siteaudit.analysis.base import AnalysisResult, Finding
from siteaudit.analysis.registry import CATEGORY_ORDER, RULES
from siteaudit.audits.service import STAGES
from siteaudit.i18n import LOCALES, has, keys, t
from siteaudit.scoring import CATEGORY_WEIGHTS, SEVERITY_WEIGHTS, grade, score


def _result(
    findings: list[tuple[str, str | None]], pages: int = 4, evaluated: dict | None = None
) -> AnalysisResult:
    res = AnalysisResult(html_page_count=pages)
    res.evaluated = evaluated or {c: {r for r in RULES if RULES[r].category == c} for c in CATEGORY_ORDER}
    for rule_id, page in findings:
        rule = RULES[rule_id]
        res.findings.append(Finding(rule_id, rule.category, rule.severity, page, {}))
    return res


def test_perfect_score() -> None:
    card = score(_result([]))
    assert card.overall == 100
    assert all(c.score == 100 for c in card.categories.values())


def test_site_rule_deducts_full_weight_once() -> None:
    card = score(_result([("security.csp_missing", "u"), ("security.csp_missing", "u2")]))
    assert card.categories["security"].score == 100 - SEVERITY_WEIGHTS["medium"]


def test_page_rule_scales_with_affected_share() -> None:
    w = SEVERITY_WEIGHTS["high"]
    one = score(_result([("accessibility.image_alt_missing", "a")], pages=4))
    assert one.categories["accessibility"].score == round(100 - w * (0.5 + 0.5 * 1 / 4))
    every = score(_result([("accessibility.image_alt_missing", p) for p in "abcd"], pages=4))
    assert every.categories["accessibility"].score == round(100 - w)


def test_info_findings_do_not_affect_score() -> None:
    card = score(_result([("seo.structured_data_missing", None)]))
    assert card.categories["seo"].score == 100
    assert card.categories["seo"].checks_failed == 0


def test_score_never_negative() -> None:
    sec = [r for r in RULES if RULES[r].category == "security"]
    card = score(_result([(r, "u") for r in sec]))
    assert card.categories["security"].score == 0


def test_unscored_category_is_excluded_from_overall() -> None:
    evaluated = {c: {r for r in RULES if RULES[r].category == c} for c in CATEGORY_ORDER}
    evaluated["performance"] = set()
    card = score(_result([("security.csp_missing", "u")], evaluated=evaluated))
    assert card.categories["performance"].score is None
    scored = {c: w for c, w in CATEGORY_WEIGHTS.items() if c != "performance"}
    expected = round(
        sum(w * (94 if c == "security" else 100) for c, w in scored.items()) / sum(scored.values())
    )
    assert card.overall == expected


def test_grades() -> None:
    assert [grade(v) for v in (100, 90, 89, 70, 69, 50, 49, None)] == [
        "good",
        "good",
        "fair",
        "fair",
        "poor",
        "poor",
        "bad",
        "none",
    ]


def test_category_weights_sum_to_one() -> None:
    assert abs(sum(CATEGORY_WEIGHTS.values()) - 1.0) < 1e-9


# --- i18n -------------------------------------------------------------------------------------------------


def test_catalogues_have_identical_keys() -> None:
    en, pt = keys("en"), keys("pt")
    assert en - pt == set(), f"missing in pt: {sorted(en - pt)}"
    assert pt - en == set(), f"missing in en: {sorted(pt - en)}"


def _placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


@pytest.mark.parametrize("locale", LOCALES)
def test_placeholders_match_between_languages(locale: str) -> None:
    for key in keys("en"):
        assert _placeholders(t("en", key)) == _placeholders(t(locale, key)), key


@pytest.mark.parametrize("locale", LOCALES)
def test_every_rule_is_fully_described(locale: str) -> None:
    for rule_id in RULES:
        for part in ("title", "description", "impact", "recommendation"):
            assert has(locale, f"rules.{rule_id}.{part}"), f"{locale}: rules.{rule_id}.{part}"


@pytest.mark.parametrize("locale", LOCALES)
def test_dynamic_keys_exist(locale: str) -> None:
    from siteaudit.models import AUDIT_STATUSES, SEVERITIES
    from siteaudit.plans import PLANS

    required = [f"category.{c}" for c in CATEGORY_ORDER]
    required += [f"severity.{s}" for s in SEVERITIES] + [f"severity_help.{s}" for s in SEVERITIES]
    required += [f"status.{s}" for s in AUDIT_STATUSES] + [f"stage.{s}" for s in STAGES]
    required += [f"grade.{g}" for g in ("good", "fair", "poor", "bad", "none")]
    required += [f"plans.{p}.name" for p in PLANS]
    for key in required:
        assert has(locale, key), f"{locale}: {key}"


_TEMPLATE_KEY = re.compile(r"""\bt\(\s*'([a-z_]+(?:\.[a-z0-9_]+)+)'\s*[,)]""")


def test_literal_template_keys_exist() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "siteaudit"
    missing = []
    for path in list(root.rglob("templates/**/*.html")) + list(root.rglob("templates/*.html")):
        for key in _TEMPLATE_KEY.findall(path.read_text(encoding="utf-8")):
            for locale in LOCALES:
                if not has(locale, key):
                    missing.append(f"{path.name}: {locale}:{key}")
    assert not missing, missing


def test_formatting_with_lists_and_missing_params() -> None:
    assert t("en", "rules.seo.h1_multiple.evidence", count=2, headings=["A", "B"]) == "2 H1 headings: A, B"
    assert "{headings}" in t("en", "rules.seo.h1_multiple.evidence", count=2)
    assert t("xx", "nav.login") == "Log in"
    assert t("pt", "nav.login") == "Entrar"
