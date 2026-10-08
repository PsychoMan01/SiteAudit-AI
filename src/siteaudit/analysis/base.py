"""Rule framework.

A rule is a small pure function over the `SiteSnapshot`. Page rules run once per successfully fetched HTML
page; site rules run once per audit. Rules yield *evidence parameters* (rendered later through the i18n
catalogue), never prose, so results stay language-independent and deterministic.

A rule that raises is recorded as errored and skipped — one broken check never fails the audit.
A rule may raise `Undetermined` when the data needed to decide is not available.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ..crawler.crawler import Page, SiteSnapshot
from ..crawler.extract import PageDoc

log = logging.getLogger(__name__)

Evidence = dict[str, Any]
PageRuleFn = Callable[[Page, PageDoc, SiteSnapshot], Iterable[Evidence] | None]
SiteRuleFn = Callable[[SiteSnapshot], Iterable[tuple[str | None, Evidence]] | None]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Undetermined(Exception):
    """Raised by a rule when the snapshot does not contain enough data to decide."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class NotApplicable(Exception):
    """Raised by a rule that does not apply to this site (e.g. HSTS on a plain-HTTP site)."""


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    scope: str  # "page" | "site"
    fn: Callable[..., Any]


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    page_url: str | None
    evidence: Evidence


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    evaluated: dict[str, set[str]] = field(default_factory=dict)  # category -> rule ids that ran
    undetermined: dict[str, str] = field(default_factory=dict)  # rule id -> reason key
    errored: list[str] = field(default_factory=list)
    html_page_count: int = 0

    def failed_rules(self, category: str) -> set[str]:
        return {f.rule_id for f in self.findings if f.category == category}


RULES: dict[str, Rule] = {}


def _register(rule: Rule) -> None:
    if rule.id in RULES:
        raise ValueError(f"duplicate rule id {rule.id}")
    RULES[rule.id] = rule


def page_rule(rule_id: str, category: str, severity: str) -> Callable[[PageRuleFn], PageRuleFn]:
    def deco(fn: PageRuleFn) -> PageRuleFn:
        _register(Rule(rule_id, category, severity, "page", fn))
        return fn

    return deco


def site_rule(rule_id: str, category: str, severity: str) -> Callable[[SiteRuleFn], SiteRuleFn]:
    def deco(fn: SiteRuleFn) -> SiteRuleFn:
        _register(Rule(rule_id, category, severity, "site", fn))
        return fn

    return deco


def clip(value: Any, limit: int = 200) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 1] + "…"
    if isinstance(value, list):
        return [clip(v, limit) for v in value[:10]]
    return value


def _clean(evidence: Evidence) -> Evidence:
    return {k: clip(v) for k, v in evidence.items()}


def run_rules(snapshot: SiteSnapshot, categories: Iterable[str]) -> Iterator[tuple[str, AnalysisResult]]:
    """Run every rule, category by category. Yields (category, cumulative result) after each category."""
    result = AnalysisResult(html_page_count=len(snapshot.html_pages))
    for category in categories:
        evaluated = result.evaluated.setdefault(category, set())
        for rule in sorted((r for r in RULES.values() if r.category == category), key=lambda r: r.id):
            buffer: list[Finding] = []
            try:
                if rule.scope == "page":
                    applicable = False
                    for page in snapshot.html_pages:
                        assert page.doc is not None
                        try:
                            produced = rule.fn(page, page.doc, snapshot)
                            evidence = list(produced or ())
                        except NotApplicable:
                            continue
                        applicable = True
                        buffer += [
                            Finding(rule.id, rule.category, rule.severity, page.final_url, _clean(ev))
                            for ev in evidence
                        ]
                    if not applicable:
                        continue
                else:
                    buffer += [
                        Finding(rule.id, rule.category, rule.severity, page_url, _clean(ev))
                        for page_url, ev in (rule.fn(snapshot) or ())
                    ]
                evaluated.add(rule.id)
                result.findings += buffer
            except NotApplicable:
                continue
            except Undetermined as exc:
                result.undetermined[rule.id] = exc.reason
            except Exception:
                log.exception("rule %s failed", rule.id, extra={"event": "rule_error"})
                result.errored.append(rule.id)
        yield category, result
