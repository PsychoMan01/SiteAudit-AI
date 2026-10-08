"""Mobile-friendliness rules based on markup. Layout overflow and tap-target sizes require rendering and are
reported as not determined."""

from __future__ import annotations

import re

from .base import NotApplicable, Undetermined, page_rule, site_rule

_WIDTH = re.compile(r"width\s*=\s*([\w-]+)", re.I)


@page_rule("mobile.viewport_missing", "mobile", "high")
def viewport_missing(page, doc, snap):
    if not doc.viewport:
        yield {}


@page_rule("mobile.viewport_fixed_width", "mobile", "high")
def viewport_fixed_width(page, doc, snap):
    if not doc.viewport:
        raise NotApplicable
    m = _WIDTH.search(doc.viewport)
    if m and m.group(1).lower() != "device-width":
        yield {"viewport": doc.viewport}


@page_rule("mobile.plugins", "mobile", "medium")
def plugins(page, doc, snap):
    if doc.plugins:
        yield {"count": doc.plugins}


@page_rule("mobile.wide_fixed_elements", "mobile", "low")
def wide_fixed_elements(page, doc, snap):
    if doc.wide_fixed_elements:
        yield {"count": doc.wide_fixed_elements}


@page_rule("mobile.small_inline_fonts", "mobile", "low")
def small_inline_fonts(page, doc, snap):
    if doc.small_font_elements:
        yield {"count": doc.small_font_elements}


@page_rule("mobile.images_not_responsive", "mobile", "low")
def images_not_responsive(page, doc, snap):
    content_images = [i for i in doc.images if i.src and not i.src.lower().endswith(".svg")]
    if len(content_images) < 4:
        raise NotApplicable
    if not any(i.has_srcset for i in content_images):
        yield {"images": len(content_images)}


@site_rule("mobile.layout_overflow", "mobile", "info")
def layout_overflow(snap):
    raise Undetermined("needs_rendering")


@site_rule("mobile.tap_targets", "mobile", "info")
def tap_targets(snap):
    raise Undetermined("needs_rendering")
