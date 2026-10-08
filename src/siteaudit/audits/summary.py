"""Deterministic executive summary built from stored results (no AI required)."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..analysis.base import SEVERITY_ORDER
from ..models import Audit, AuditIssue


@dataclass
class IssueGroup:
    rule_id: str
    category: str
    severity: str
    occurrences: list[AuditIssue] = field(default_factory=list)

    @property
    def pages(self) -> list[str]:
        seen: list[str] = []
        for issue in self.occurrences:
            if issue.page_url and issue.page_url not in seen:
                seen.append(issue.page_url)
        return seen


@dataclass
class Summary:
    groups: list[IssueGroup]
    severity_counts: dict[str, int]
    priorities: list[IssueGroup]
    weakest: str | None
    strongest: str | None


def group_issues(issues: list[AuditIssue]) -> list[IssueGroup]:
    groups: dict[str, IssueGroup] = {}
    for issue in issues:
        group = groups.get(issue.rule_id)
        if group is None:
            group = groups[issue.rule_id] = IssueGroup(issue.rule_id, issue.category, issue.severity)
        group.occurrences.append(issue)
    return sorted(
        groups.values(),
        key=lambda g: (SEVERITY_ORDER[g.severity], -len(g.pages) or -len(g.occurrences), g.rule_id),
    )


def build_summary(audit: Audit) -> Summary:
    groups = group_issues(audit.issues)
    counts = Counter(g.severity for g in groups)
    severity_counts = {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")}
    priorities = [g for g in groups if g.severity in ("critical", "high", "medium")][:5]
    scored = [(s.category, s.score) for s in audit.scores if s.score is not None]
    weakest = min(scored, key=lambda x: (x[1], x[0]))[0] if scored else None
    strongest = max(scored, key=lambda x: (x[1], x[0]))[0] if scored else None
    return Summary(groups, severity_counts, priorities, weakest, strongest)


def pages_by_issue_count(audit: Audit) -> list[tuple[str, int]]:
    per_page: dict[str, set[str]] = defaultdict(set)
    for issue in audit.issues:
        if issue.page_url and issue.severity != "info":
            per_page[issue.page_url].add(issue.rule_id)
    return sorted(((url, len(rules)) for url, rules in per_page.items()), key=lambda x: (-x[1], x[0]))
