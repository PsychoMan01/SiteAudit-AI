"""Accessibility rules (static HTML checks, mapped to WCAG 2.2 where relevant).

Colour contrast can only be computed for elements whose inline style declares both foreground and
background colours; everything else is reported as not determined rather than guessed.
"""

from __future__ import annotations

import re

from .base import NotApplicable, Undetermined, page_rule, site_rule

_MAX_SCALE = re.compile(r"maximum-scale\s*=\s*([\d.]+)", re.I)


@page_rule("accessibility.lang_missing", "accessibility", "medium")
def lang_missing(page, doc, snap):
    if not doc.lang:
        yield {}


@page_rule("accessibility.image_alt_missing", "accessibility", "high")
def image_alt_missing(page, doc, snap):
    missing = [i.src or "(inline)" for i in doc.images if i.alt is None]
    if missing:
        yield {"count": len(missing), "total": len(doc.images), "images": missing[:8]}


@page_rule("accessibility.control_unlabeled", "accessibility", "high")
def control_unlabeled(page, doc, snap):
    if doc.unlabeled_controls:
        yield {
            "count": len(doc.unlabeled_controls),
            "placeholder_only": doc.placeholder_only_controls,
            "elements": doc.unlabeled_controls[:5],
        }


@page_rule("accessibility.button_unnamed", "accessibility", "high")
def button_unnamed(page, doc, snap):
    if doc.unnamed_buttons:
        yield {"count": len(doc.unnamed_buttons), "elements": doc.unnamed_buttons[:5]}


@page_rule("accessibility.link_unnamed", "accessibility", "medium")
def link_unnamed(page, doc, snap):
    if doc.unnamed_links:
        yield {"count": len(doc.unnamed_links), "elements": doc.unnamed_links[:5]}


@page_rule("accessibility.iframe_untitled", "accessibility", "medium")
def iframe_untitled(page, doc, snap):
    if doc.iframes_without_title:
        yield {"count": doc.iframes_without_title}


@page_rule("accessibility.invalid_role", "accessibility", "medium")
def invalid_role(page, doc, snap):
    if doc.invalid_roles:
        yield {"roles": sorted(set(doc.invalid_roles))[:10]}


@page_rule("accessibility.duplicate_ids", "accessibility", "low")
def duplicate_ids(page, doc, snap):
    if doc.duplicate_ids:
        yield {"count": len(doc.duplicate_ids), "ids": doc.duplicate_ids[:10]}


@page_rule("accessibility.positive_tabindex", "accessibility", "low")
def positive_tabindex(page, doc, snap):
    if doc.positive_tabindex:
        yield {"count": doc.positive_tabindex}


@page_rule("accessibility.heading_order", "accessibility", "low")
def heading_order(page, doc, snap):
    skips = []
    previous = 0
    for level, text in doc.headings:
        if previous and level > previous + 1:
            skips.append(f"h{previous} → h{level}: {text[:60]}")
        previous = level
    if skips:
        yield {"skips": skips[:6]}


@page_rule("accessibility.empty_heading", "accessibility", "low")
def empty_heading(page, doc, snap):
    empty = sum(1 for _level, text in doc.headings if not text)
    if empty:
        yield {"count": empty}


@page_rule("accessibility.main_landmark_missing", "accessibility", "low")
def main_landmark_missing(page, doc, snap):
    if "main" not in doc.landmarks:
        yield {}


@page_rule("accessibility.table_headers_missing", "accessibility", "low")
def table_headers_missing(page, doc, snap):
    if doc.tables_without_headers:
        yield {"count": doc.tables_without_headers}


@page_rule("accessibility.zoom_disabled", "accessibility", "high")
def zoom_disabled(page, doc, snap):
    if not doc.viewport:
        raise NotApplicable
    vp = doc.viewport.lower().replace(" ", "")
    m = _MAX_SCALE.search(vp)
    if "user-scalable=no" in vp or "user-scalable=0" in vp or (m and float(m.group(1)) < 2):
        yield {"viewport": doc.viewport}


@page_rule("accessibility.low_contrast", "accessibility", "medium")
def low_contrast(page, doc, snap):
    if doc.low_contrast:
        yield {"count": len(doc.low_contrast), "elements": doc.low_contrast[:5]}


@site_rule("accessibility.contrast_stylesheets", "accessibility", "info")
def contrast_stylesheets(snap):
    # Contrast defined in stylesheets needs a rendering engine; this is stated explicitly, not guessed.
    raise Undetermined("needs_rendering")
