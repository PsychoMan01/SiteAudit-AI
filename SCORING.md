# Scoring

SiteAudit's scores are computed by fixed rules. No AI is involved. The same site under the same conditions
produces the same score (verified by `test_scoring_is_deterministic`).

## Formula

For each category, every check (rule) that fails deducts points **once**, according to its severity:

```
page-level rule:  deduction = weight(severity) × (0.5 + 0.5 × affected_pages / audited_pages)
site-level rule:  deduction = weight(severity)
category score  = max(0, round(100 − Σ deductions))
overall score   = round( Σ (category_score × category_weight) / Σ category_weight )   # scored categories only
```

A rule that fails on half the pages costs 75% of its weight; on every page, 100%. A category in which no
check could run has no score and is excluded from the overall score (weights are renormalised).

| Severity | Points | | Category | Weight |
|---|---|---|---|---|
| critical | 25 | | SEO | 20% |
| high | 12 | | Performance | 20% |
| medium | 6 | | Accessibility | 20% |
| low | 2 | | Security | 20% |
| info | 0 | | Mobile | 10% |
|  |  | | Best practices | 10% |

Grades (wording/colour only): 90–100 good · 70–89 needs work · 50–69 poor · 0–49 critical problems.

## Outcomes of a check

- **Passed** — evaluated, no finding.
- **Failed** — one or more findings; deducts points unless severity is *info*.
- **Not applicable** — e.g. HSTS on a site without HTTPS; neither counted nor shown.
- **Not determined** — the data needed is unavailable (e.g. requires a browser); listed in the results, never scored.
- **Errored** — the rule raised an exception; logged, excluded, and the audit continues.

## All checks (87 scored checks + 3 reported as not determined)

### SEO

| Check | Id | Severity | Scope |
|---|---|---|---|
| Broken internal links | `seo.broken_internal_links` | high | site |
| Conflicting canonical URLs | `seo.canonical_conflict` | medium | page |
| No canonical URL | `seo.canonical_missing` | low | page |
| Canonical points to another website | `seo.canonical_other_site` | medium | page |
| Meta description is too short or too long | `seo.description_length` | low | page |
| Meta description is missing | `seo.description_missing` | medium | page |
| Duplicate page content | `seo.duplicate_content` | medium | site |
| Same meta description on several pages | `seo.duplicate_description` | low | site |
| Same title used on several pages | `seo.duplicate_title` | medium | site |
| Links with vague text | `seo.generic_anchor` | low | page |
| Page has no H1 heading | `seo.h1_missing` | medium | page |
| Page has several H1 headings | `seo.h1_multiple` | low | page |
| Canonical uses http:// on an HTTPS site | `seo.https_canonical_mismatch` | medium | site |
| Internal links that redirect | `seo.internal_redirects` | low | site |
| Page is excluded from search results | `seo.noindex` | info | page |
| Home page is excluded from search results | `seo.noindex_home` | critical | site |
| Open Graph tags missing | `seo.open_graph_missing` | low | site |
| robots.txt blocks search engines | `seo.robots_blocks_all` | critical | site |
| No robots.txt file | `seo.robots_missing` | low | site |
| Sitemap is not valid XML | `seo.sitemap_invalid` | medium | site |
| No XML sitemap found | `seo.sitemap_missing` | low | site |
| No structured data | `seo.structured_data_missing` | info | site |
| Little text content | `seo.thin_content` | low | page |
| Title is too short or too long | `seo.title_length` | low | page |
| Page has no title | `seo.title_missing` | high | page |
| Page has several title elements | `seo.title_multiple` | low | page |

### Performance

| Check | Id | Severity | Scope |
|---|---|---|---|
| Redirect chain on the entry URL | `performance.entry_redirects` | medium | site |
| Web fonts without preconnect | `performance.fonts_without_preconnect` | low | site |
| Heavy JavaScript | `performance.heavy_javascript` | medium | site |
| Very large HTML document | `performance.html_large` | medium | page |
| HTML is not compressed | `performance.html_uncompressed` | medium | page |
| Images without width and height | `performance.images_without_dimensions` | low | page |
| Large images | `performance.large_images` | medium | site |
| Large inline scripts or styles | `performance.large_inline_code` | low | page |
| Many resources on the home page | `performance.many_requests` | low | site |
| Many render-blocking stylesheets | `performance.many_stylesheets` | low | page |
| No lazy loading for images | `performance.no_lazy_loading` | low | page |
| Render-blocking scripts | `performance.render_blocking_scripts` | medium | page |
| Slow server response | `performance.response_slow` | medium | page |
| Very slow server response | `performance.response_very_slow` | high | page |
| Assets without long-term caching | `performance.static_not_cached` | medium | site |
| Uncompressed CSS or JavaScript | `performance.text_resources_uncompressed` | medium | site |

### Accessibility

| Check | Id | Severity | Scope |
|---|---|---|---|
| Buttons without an accessible name | `accessibility.button_unnamed` | high | page |
| Colour contrast of styled text (always *not determined*) | `accessibility.contrast_stylesheets` | info | site |
| Form fields without labels | `accessibility.control_unlabeled` | high | page |
| Duplicate element IDs | `accessibility.duplicate_ids` | low | page |
| Empty headings | `accessibility.empty_heading` | low | page |
| Heading levels are skipped | `accessibility.heading_order` | low | page |
| Frames without a title | `accessibility.iframe_untitled` | medium | page |
| Images without alternative text | `accessibility.image_alt_missing` | high | page |
| Invalid ARIA roles | `accessibility.invalid_role` | medium | page |
| Page language not declared | `accessibility.lang_missing` | medium | page |
| Links without an accessible name | `accessibility.link_unnamed` | medium | page |
| Low colour contrast | `accessibility.low_contrast` | medium | page |
| No main landmark | `accessibility.main_landmark_missing` | low | page |
| Positive tabindex values | `accessibility.positive_tabindex` | low | page |
| Data tables without headers | `accessibility.table_headers_missing` | low | page |
| Zoom is disabled | `accessibility.zoom_disabled` | high | page |

### Mobile

| Check | Id | Severity | Scope |
|---|---|---|---|
| Images are not responsive | `mobile.images_not_responsive` | low | page |
| Horizontal overflow on small screens (always *not determined*) | `mobile.layout_overflow` | info | site |
| Embedded plugins | `mobile.plugins` | medium | page |
| Very small text | `mobile.small_inline_fonts` | low | page |
| Size of tap targets (always *not determined*) | `mobile.tap_targets` | info | site |
| Viewport has a fixed width | `mobile.viewport_fixed_width` | high | page |
| No mobile viewport | `mobile.viewport_missing` | high | page |
| Wide fixed-width elements | `mobile.wide_fixed_elements` | low | page |

### Security

| Check | Id | Severity | Scope |
|---|---|---|---|
| TLS certificate expires soon | `security.certificate_expiring` | high | site |
| TLS certificate is not valid | `security.certificate_invalid` | critical | site |
| Page can be embedded by other sites | `security.clickjacking` | medium | site |
| Cookies without SameSite | `security.cookie_no_samesite` | low | site |
| Cookies readable by JavaScript | `security.cookie_not_httponly` | low | site |
| Cookies without the Secure flag | `security.cookie_not_secure` | medium | site |
| No Content Security Policy | `security.csp_missing` | medium | site |
| HSTS header missing | `security.hsts_missing` | medium | site |
| HTTP does not redirect to HTTPS | `security.http_not_redirected` | high | site |
| Mixed content | `security.mixed_content` | high | site |
| Site is not served over HTTPS | `security.no_https` | critical | site |
| X-Content-Type-Options missing | `security.nosniff_missing` | low | site |
| Permissions-Policy missing | `security.permissions_policy_missing` | low | site |
| Referrer-Policy missing | `security.referrer_policy_missing` | low | site |
| Server software version disclosed | `security.version_disclosure` | low | site |

### Best practices

| Check | Id | Severity | Scope |
|---|---|---|---|
| Broken outbound links | `best_practices.broken_external_links` | medium | site |
| Character encoding not declared | `best_practices.charset_missing` | low | page |
| Deprecated HTML elements | `best_practices.deprecated_html` | low | page |
| No HTML doctype | `best_practices.doctype_missing` | low | page |
| No favicon declared | `best_practices.favicon_missing` | low | site |
| Meta refresh used | `best_practices.meta_refresh` | low | page |
| Pages return server errors | `best_practices.server_errors` | high | site |
| External links opening new tabs without rel=noopener | `best_practices.target_blank` | info | page |
| Pages could not be reached | `best_practices.unreachable_pages` | medium | site |

## Changing the scoring

Weights live in `src/siteaudit/scoring.py`; thresholds live next to each rule in `src/siteaudit/analysis/`.
Any change alters historic comparability: record it in the changelog and in this document.
