"""Single-pass HTML extraction into a compact, analyzer-friendly structure.

The raw HTML is parsed once and discarded; analyzers only ever see `PageDoc`. This keeps memory bounded
and makes every rule a pure function of recorded facts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, Doctype, Tag

from .urls import absolutize, same_site

_WS = re.compile(r"\s+")
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)
_PX_WIDTH = re.compile(r"(?:^|;)\s*(?:min-)?width\s*:\s*(\d{3,5})px", re.I)
_FONT_PX = re.compile(r"(?:^|;)\s*font-size\s*:\s*(\d+(?:\.\d+)?)px", re.I)
_COLOR = re.compile(r"(?:^|;)\s*color\s*:\s*([^;]+)", re.I)
_BG = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;]+)", re.I)

VALID_ROLES = frozenset(
    [
        "alert",
        "alertdialog",
        "application",
        "article",
        "banner",
        "blockquote",
        "button",
        "caption",
        "cell",
        "checkbox",
        "code",
        "columnheader",
        "combobox",
        "comment",
        "complementary",
        "contentinfo",
        "definition",
        "deletion",
        "dialog",
        "directory",
        "document",
        "emphasis",
        "feed",
        "figure",
        "form",
        "generic",
        "grid",
        "gridcell",
        "group",
        "heading",
        "img",
        "image",
        "insertion",
        "link",
        "list",
        "listbox",
        "listitem",
        "log",
        "main",
        "mark",
        "marquee",
        "math",
        "menu",
        "menubar",
        "menuitem",
        "menuitemcheckbox",
        "menuitemradio",
        "meter",
        "navigation",
        "none",
        "note",
        "option",
        "paragraph",
        "presentation",
        "progressbar",
        "radio",
        "radiogroup",
        "region",
        "row",
        "rowgroup",
        "rowheader",
        "scrollbar",
        "search",
        "searchbox",
        "separator",
        "slider",
        "spinbutton",
        "status",
        "strong",
        "subscript",
        "superscript",
        "switch",
        "tab",
        "table",
        "tablist",
        "tabpanel",
        "term",
        "textbox",
        "time",
        "timer",
        "toolbar",
        "tooltip",
        "tree",
        "treegrid",
        "treeitem",
        "doc-abstract",
        "doc-acknowledgments",
        "doc-afterword",
        "doc-appendix",
        "doc-backlink",
        "doc-biblioentry",
        "doc-bibliography",
        "doc-biblioref",
        "doc-chapter",
        "doc-colophon",
        "doc-conclusion",
        "doc-cover",
        "doc-credit",
        "doc-credits",
        "doc-dedication",
        "doc-endnote",
        "doc-endnotes",
        "doc-epigraph",
        "doc-epilogue",
        "doc-errata",
        "doc-example",
        "doc-footnote",
        "doc-foreword",
        "doc-glossary",
        "doc-glossref",
        "doc-index",
        "doc-introduction",
        "doc-noteref",
        "doc-notice",
        "doc-pagebreak",
        "doc-pagelist",
        "doc-part",
        "doc-preface",
        "doc-prologue",
        "doc-pullquote",
        "doc-qna",
        "doc-subtitle",
        "doc-tip",
        "doc-toc",
        "graphics-document",
        "graphics-object",
        "graphics-symbol",
    ]
)
DEPRECATED_TAGS = ("font", "center", "marquee", "blink", "frameset", "frame", "big", "strike", "tt")
GENERIC_ANCHORS = frozenset(
    {
        "click here",
        "here",
        "read more",
        "more",
        "learn more",
        "link",
        "this",
        "click",
        "continue",
        "details",
        "go",
        "saiba mais",
        "clique aqui",
        "aqui",
        "ler mais",
        "mais",
    }
)


@dataclass
class Link:
    url: str
    text: str
    internal: bool
    rel: str = ""
    blank_unsafe: bool = False


@dataclass
class Image:
    src: str | None
    alt: str | None
    has_srcset: bool
    has_dimensions: bool
    lazy: bool


@dataclass
class Script:
    src: str | None
    in_head: bool
    is_async: bool
    is_defer: bool
    is_module: bool


@dataclass
class Stylesheet:
    href: str
    in_head: bool
    media: str


@dataclass
class PageDoc:
    lang: str | None = None
    title: str | None = None
    title_count: int = 0
    meta_description: str | None = None
    meta_description_count: int = 0
    meta_robots: str = ""
    viewport: str | None = None
    canonicals: list[str] = field(default_factory=list)
    charset_declared: bool = False
    has_doctype: bool = False
    has_favicon: bool = False
    generator: str | None = None
    og: dict[str, str] = field(default_factory=dict)
    twitter_card: str | None = None
    jsonld_count: int = 0
    meta_refresh: bool = False
    headings: list[tuple[int, str]] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    images: list[Image] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    stylesheets: list[Stylesheet] = field(default_factory=list)
    inline_script_bytes: int = 0
    inline_style_bytes: int = 0
    preconnects: list[str] = field(default_factory=list)
    font_links: list[str] = field(default_factory=list)
    unlabeled_controls: list[str] = field(default_factory=list)
    placeholder_only_controls: int = 0
    unnamed_buttons: list[str] = field(default_factory=list)
    unnamed_links: list[str] = field(default_factory=list)
    iframes_without_title: int = 0
    duplicate_ids: list[str] = field(default_factory=list)
    positive_tabindex: int = 0
    invalid_roles: list[str] = field(default_factory=list)
    landmarks: set[str] = field(default_factory=set)
    deprecated_tags: list[str] = field(default_factory=list)
    plugins: int = 0
    wide_fixed_elements: int = 0
    small_font_elements: int = 0
    mixed_content: list[str] = field(default_factory=list)
    low_contrast: list[str] = field(default_factory=list)
    word_count: int = 0
    text_hash: str | None = None
    forms: int = 0
    tables_without_headers: int = 0
    script_srcs_raw: list[str] = field(default_factory=list)
    body_markers: list[str] = field(default_factory=list)

    @property
    def internal_links(self) -> list[Link]:
        return [link for link in self.links if link.internal]

    @property
    def external_links(self) -> list[Link]:
        return [link for link in self.links if not link.internal]


def _text(node: Tag) -> str:
    return _WS.sub(" ", node.get_text(" ", strip=True)).strip()


def _attr(node: Tag, name: str) -> str:
    value = node.get(name)
    if isinstance(value, list):
        return " ".join(value)
    return (value or "").strip()


def _has_accessible_name(node: Tag) -> bool:
    if _attr(node, "aria-label") or _attr(node, "aria-labelledby") or _attr(node, "title"):
        return True
    if _text(node):
        return True
    return any(_attr(img, "alt") for img in node.find_all("img"))


def _snippet(node: Tag, limit: int = 160) -> str:
    html = str(node)
    html = _WS.sub(" ", html)
    return html if len(html) <= limit else html[: limit - 1] + "…"


# --- colour contrast (only for inline styles where both colours are declared) -------------------------

_NAMED = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (255, 0, 0),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "silver": (192, 192, 192),
    "yellow": (255, 255, 0),
    "blue": (0, 0, 255),
    "green": (0, 128, 0),
    "orange": (255, 165, 0),
    "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211),
    "navy": (0, 0, 128),
}


def parse_color(value: str) -> tuple[int, int, int] | None:
    v = value.strip().lower().split("!", 1)[0].strip()
    if v in _NAMED:
        return _NAMED[v]
    m = re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    m = re.fullmatch(r"rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)", v)
    if m:
        r, g, b = (min(255, int(x)) for x in m.groups())
        return r, g, b
    return None


def contrast_ratio(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    def lum(c: tuple[int, int, int]) -> float:
        def ch(x: int) -> float:
            s = x / 255
            return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4

        return 0.2126 * ch(c[0]) + 0.7152 * ch(c[1]) + 0.0722 * ch(c[2])

    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


# --- main entry point ----------------------------------------------------------------------------------


def extract(html: str, page_url: str, site_host: str) -> PageDoc:
    soup = BeautifulSoup(html, "lxml")
    doc = PageDoc()
    https_page = page_url.startswith("https://")

    doc.has_doctype = any(isinstance(item, Doctype) for item in soup.contents)
    html_tag = soup.find("html")
    if isinstance(html_tag, Tag):
        doc.lang = _attr(html_tag, "lang") or None
    head = soup.find("head")
    head_tag = head if isinstance(head, Tag) else None

    titles = soup.find_all("title")
    doc.title_count = len(titles)
    if titles:
        doc.title = _text(titles[0]) or None

    for meta in soup.find_all("meta"):
        name = _attr(meta, "name").lower()
        prop = _attr(meta, "property").lower()
        content = _attr(meta, "content")
        if meta.get("charset") is not None or "charset=" in _attr(meta, "content").lower():
            doc.charset_declared = True
        if name == "description":
            doc.meta_description_count += 1
            if doc.meta_description is None:
                doc.meta_description = content
        elif name in ("robots", "googlebot"):
            doc.meta_robots = (doc.meta_robots + "," + content.lower()).strip(",")
        elif name == "viewport":
            doc.viewport = content
        elif name == "generator" and content:
            doc.generator = content[:120]
        elif name == "twitter:card":
            doc.twitter_card = content
        if prop.startswith("og:") and content:
            doc.og[prop] = content[:300]
        if _attr(meta, "http-equiv").lower() == "refresh":
            doc.meta_refresh = True

    for link in soup.find_all("link"):
        rel = _attr(link, "rel").lower().split()
        href = _attr(link, "href")
        absolute = absolutize(page_url, href) if href else None
        if "canonical" in rel and href:
            doc.canonicals.append(absolute or href)
        if "icon" in rel or "apple-touch-icon" in rel:
            doc.has_favicon = True
        if "preconnect" in rel and absolute:
            doc.preconnects.append(absolute)
        if "stylesheet" in rel and absolute:
            in_head = head_tag is not None and link in head_tag.descendants
            doc.stylesheets.append(Stylesheet(absolute, in_head, _attr(link, "media").lower()))
            if "fonts.googleapis.com" in absolute or "use.typekit.net" in absolute:
                doc.font_links.append(absolute)
        if "preload" in rel and _attr(link, "as").lower() == "font" and absolute:
            doc.font_links.append(absolute)

    for script in soup.find_all("script"):
        stype = _attr(script, "type").lower()
        if stype == "application/ld+json":
            doc.jsonld_count += 1
            continue
        src = _attr(script, "src")
        in_head = head_tag is not None and script in head_tag.descendants
        if src:
            absolute = absolutize(page_url, src)
            doc.script_srcs_raw.append(src[:300])
            if absolute:
                doc.scripts.append(
                    Script(
                        absolute,
                        in_head,
                        script.has_attr("async"),
                        script.has_attr("defer"),
                        stype == "module",
                    )
                )
                if https_page and absolute.startswith("http://"):
                    doc.mixed_content.append(absolute)
        elif stype in ("", "text/javascript", "application/javascript", "module"):
            doc.inline_script_bytes += len(script.get_text() or "")
            body_text = script.get_text() or ""
            if "__NEXT_DATA__" in _attr(script, "id") or "__NUXT__" in body_text[:2000]:
                doc.body_markers.append(_attr(script, "id") or "__NUXT__")
    for style_tag in soup.find_all("style"):
        doc.inline_style_bytes += len(style_tag.get_text() or "")

    for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        doc.headings.append((int(h.name[1]), _text(h)[:200]))

    for a in soup.find_all("a"):
        href = _attr(a, "href")
        if not href:
            continue
        absolute = absolutize(page_url, href)
        if not _has_accessible_name(a):
            doc.unnamed_links.append(_snippet(a))
        if absolute is None:
            continue
        link_rel = _attr(a, "rel").lower()
        blank_unsafe = _attr(a, "target").lower() == "_blank" and not (
            "noopener" in link_rel or "noreferrer" in link_rel
        )
        doc.links.append(
            Link(
                absolute,
                _text(a)[:200] or _attr(a, "aria-label")[:200],
                same_site(absolute, site_host),
                link_rel,
                blank_unsafe,
            )
        )

    for img in soup.find_all("img"):
        img_src = _attr(img, "src") or None
        absolute = absolutize(page_url, img_src) if img_src else None
        alt = img.get("alt")
        doc.images.append(
            Image(
                absolute,
                None if alt is None else _attr(img, "alt"),
                img.has_attr("srcset") or (img.parent is not None and img.parent.name == "picture"),
                img.has_attr("width") and img.has_attr("height"),
                _attr(img, "loading").lower() == "lazy",
            )
        )
        if https_page and absolute and absolute.startswith("http://"):
            doc.mixed_content.append(absolute)

    for iframe in soup.find_all("iframe"):
        if not _attr(iframe, "title") and not _attr(iframe, "aria-label"):
            doc.iframes_without_title += 1
        src = _attr(iframe, "src")
        if https_page and src.startswith("http://"):
            doc.mixed_content.append(src)

    # Forms and controls
    doc.forms = len(soup.find_all("form"))
    labelled_ids = {_attr(label, "for") for label in soup.find_all("label") if _attr(label, "for")}
    for control in soup.find_all(["input", "select", "textarea"]):
        ctype = _attr(control, "type").lower() if control.name == "input" else control.name
        if ctype in ("hidden", "submit", "button", "reset", "image"):
            # submit/reset have a default accessible name; type=button and type=image do not.
            if ctype == "button" and not (
                _attr(control, "value") or _attr(control, "aria-label") or _attr(control, "title")
            ):
                doc.unnamed_buttons.append(_snippet(control))
            if ctype == "image" and not (_attr(control, "alt") or _attr(control, "aria-label")):
                doc.unnamed_buttons.append(_snippet(control))
            continue
        cid = _attr(control, "id")
        labelled = (
            (cid and cid in labelled_ids)
            or control.find_parent("label") is not None
            or _attr(control, "aria-label")
            or _attr(control, "aria-labelledby")
            or _attr(control, "title")
        )
        if not labelled:
            doc.unlabeled_controls.append(_snippet(control))
            if _attr(control, "placeholder"):
                doc.placeholder_only_controls += 1

    for button in soup.find_all("button"):
        if not _has_accessible_name(button):
            doc.unnamed_buttons.append(_snippet(button))
    for node in soup.find_all(attrs={"role": True}):  # type: ignore[call-overload]
        roles = _attr(node, "role").lower().split()
        if roles and roles[0] not in VALID_ROLES:
            doc.invalid_roles.append(roles[0][:40])
        if (
            roles
            and roles[0] == "button"
            and node.name not in ("button", "input")
            and not _has_accessible_name(node)
        ):
            doc.unnamed_buttons.append(_snippet(node))
        if roles and roles[0] in ("main", "navigation", "banner", "contentinfo"):
            doc.landmarks.add(roles[0])
    for tag, landmark in (
        ("main", "main"),
        ("nav", "navigation"),
        ("header", "banner"),
        ("footer", "contentinfo"),
    ):
        if soup.find(tag) is not None:
            doc.landmarks.add(landmark)

    seen_ids: dict[str, int] = {}
    for node in soup.find_all(id=True):
        nid = _attr(node, "id")
        if nid:
            seen_ids[nid] = seen_ids.get(nid, 0) + 1
    doc.duplicate_ids = sorted(k for k, v in seen_ids.items() if v > 1)[:50]

    for node in soup.find_all(attrs={"tabindex": True}):  # type: ignore[call-overload]
        try:
            if int(_attr(node, "tabindex")) > 0:
                doc.positive_tabindex += 1
        except ValueError:
            pass

    doc.deprecated_tags = sorted({t.name for t in soup.find_all(list(DEPRECATED_TAGS))})
    doc.plugins = len(soup.find_all(["object", "embed", "applet"]))

    for table in soup.find_all("table"):
        if (
            table.find("th") is None
            and len(table.find_all("tr")) > 1
            and _attr(table, "role") != "presentation"
        ):
            doc.tables_without_headers += 1

    for node in soup.find_all(style=True):
        style = _attr(node, "style")
        m = _PX_WIDTH.search(style)
        if m and int(m.group(1)) > 640:
            doc.wide_fixed_elements += 1
        f = _FONT_PX.search(style)
        if f and float(f.group(1)) < 12 and _text(node):
            doc.small_font_elements += 1
        c, bgm = _COLOR.search(style), _BG.search(style)
        if c and bgm:
            fg, bg = parse_color(c.group(1)), parse_color(bgm.group(1))
            if fg and bg and _text(node):
                ratio = contrast_ratio(fg, bg)
                if ratio < 4.5:
                    doc.low_contrast.append(f"{ratio:.2f}:1 — {_snippet(node, 120)}")

    # Visible text
    body = soup.find("body")
    if isinstance(body, Tag):
        for junk in body.find_all(["script", "style", "noscript", "template", "svg"]):
            junk.decompose()
        for comment in body.find_all(string=lambda s: isinstance(s, Comment)):
            comment.extract()
        text = _WS.sub(" ", body.get_text(" ", strip=True))
        words = _WORD.findall(text.lower())
        doc.word_count = len(words)
        if len(words) >= 50:
            doc.text_hash = hashlib.sha256(" ".join(words).encode()).hexdigest()

    return doc


def is_generic_anchor(text: str) -> bool:
    return text.strip().lower().rstrip(".…»›>→ ") in GENERIC_ANCHORS
