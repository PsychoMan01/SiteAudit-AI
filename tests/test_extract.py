"""HTML extraction."""

from __future__ import annotations

from siteaudit.crawler.extract import contrast_ratio, extract, is_generic_anchor, parse_color

BAD_HTML = """
<html><head>
<title>Hi</title><title>Second</title>
<meta name="viewport" content="width=1024, user-scalable=no">
<meta name="robots" content="noindex, nofollow">
<link rel="canonical" href="https://other.example/x"><link rel="canonical" href="/y">
<script src="/blocking.js"></script><script src="/ok.js" defer></script>
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
</head>
<body>
<h2>Skipped h1</h2><h4>Skip to h4</h4><h3></h3>
<img src="/a.png"><img src="/b.png" alt=""><img src="http://cdn.example/c.png" alt="c" width="10" height="10">
<a href="/internal">click here</a><a href="https://external.example/" target="_blank">External site</a>
<a href="/icon"><img src="/i.png"></a>
<form><input type="text" name="q" placeholder="Search"><input id="e" type="email"><label for="e">Email</label>
<button></button><input type="button"><input type="submit"></form>
<div role="buton">x</div><div id="d"></div><div id="d"></div><span tabindex="3">t</span>
<iframe src="https://maps.example/"></iframe>
<center>old</center><embed src="x.swf">
<table><tr><td>a</td></tr><tr><td>b</td></tr></table>
<p style="color:#777;background-color:#888">low contrast</p>
<div style="width: 980px">wide</div><span style="font-size:10px">tiny</span>
</body></html>
"""


def test_extract_bad_page() -> None:
    doc = extract(BAD_HTML, "https://site.example/page", "site.example")
    assert doc.lang is None
    assert doc.title == "Hi" and doc.title_count == 2
    assert doc.meta_description is None
    assert "noindex" in doc.meta_robots
    assert doc.viewport == "width=1024, user-scalable=no"
    assert doc.canonicals == ["https://other.example/x", "https://site.example/y"]
    assert not doc.has_doctype and not doc.charset_declared
    assert [(lvl) for lvl, _ in doc.headings] == [2, 4, 3]
    assert [s.src for s in doc.scripts if s.in_head and not s.is_defer] == [
        "https://site.example/blocking.js"
    ]
    assert len(doc.images) == 4
    assert sum(1 for i in doc.images if i.alt is None) == 2  # /a.png and the image inside the link
    assert doc.mixed_content == ["http://cdn.example/c.png"]
    assert [link.internal for link in doc.links] == [True, False, True]
    assert doc.links[1].blank_unsafe
    assert len(doc.unnamed_links) == 1  # link whose only content is an image without alt
    assert doc.placeholder_only_controls == 1 and len(doc.unlabeled_controls) == 1
    assert len(doc.unnamed_buttons) == 2  # empty <button> and <input type=button>
    assert doc.invalid_roles == ["buton"]
    assert doc.duplicate_ids == ["d"]
    assert doc.positive_tabindex == 1
    assert doc.iframes_without_title == 1
    assert doc.deprecated_tags == ["center"]
    assert doc.plugins == 1
    assert doc.tables_without_headers == 1
    assert doc.wide_fixed_elements == 1 and doc.small_font_elements == 1
    assert len(doc.low_contrast) == 1 and doc.low_contrast[0].startswith("1.")
    assert doc.font_links and not doc.preconnects
    assert "main" not in doc.landmarks


def test_extract_good_page(helpers) -> None:  # type: ignore[no-untyped-def]
    html = helpers["html"](
        head='<link rel="icon" href="/f.svg">', body='<img src="/x.png" alt="X" width="1" height="1">'
    )
    doc = extract(html, "https://site.example/", "site.example")
    assert doc.has_doctype and doc.charset_declared and doc.lang == "en"
    assert doc.has_favicon
    assert doc.word_count > 200 and doc.text_hash
    assert not doc.unnamed_buttons and not doc.unlabeled_controls and not doc.duplicate_ids
    assert "main" in doc.landmarks


def test_www_is_same_site() -> None:
    doc = extract(
        '<a href="https://www.site.example/a">A</a><a href="https://blog.site.example/">B</a>',
        "https://site.example/",
        "site.example",
    )
    assert [link.internal for link in doc.links] == [True, False]


def test_ignores_non_http_links() -> None:
    doc = extract(
        '<a href="mailto:x@y.z">m</a><a href="javascript:void(0)">j</a><a href="#top">t</a>',
        "https://site.example/",
        "site.example",
    )
    assert doc.links == []


def test_colour_helpers() -> None:
    assert parse_color("#fff") == (255, 255, 255)
    assert parse_color("rgb(0, 0, 0)") == (0, 0, 0)
    assert parse_color("var(--x)") is None
    assert round(contrast_ratio((0, 0, 0), (255, 255, 255)), 1) == 21.0
    assert is_generic_anchor("Read more »")
    assert not is_generic_anchor("Read the 2024 report")


def test_malformed_html_does_not_crash() -> None:
    doc = extract(
        "<html><body><div><p>unclosed <a href='/x'>link<table><tr><td>" * 50,
        "https://s.example/",
        "s.example",
    )
    assert doc.links
