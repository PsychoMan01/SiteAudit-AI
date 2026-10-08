# SiteAudit AI — Project status

_Last updated: 2026-10-08_

## Summary

Working product: sign-up → audit → live progress → results with filters → PDF report, in English and
Portuguese, with an admin area, plan limits and a hardened crawler. Verified with automated tests and with
real audits of public websites through the browser UI. Not yet deployed to a production host.

## Phase 0 — discovery (2026-10-07)

No SiteAudit code existed. The workspace the request came from (`SoftwareCompany-v3`) is an unrelated tool and
was left untouched; this repository was created at `~/Projetos/siteaudit-ai`.

Environment: Linux, Python 3.12.3, SQLite, Google Chrome (QA only), Pango 1.52 (PDF). No PostgreSQL server,
no Docker on the development machine.

Stack: Python 3.12 · FastAPI (server-rendered Jinja, ~2 KB of JS) · SQLAlchemy 2 + Alembic · SQLite (dev) /
PostgreSQL (prod) · database-backed job queue + worker process · httpx with SSRF-guarded transport ·
BeautifulSoup/lxml · Argon2 · WeasyPrint. See ARCHITECTURE.md for the reasoning.

## Done

| Area | State |
|---|---|
| URL validation & SSRF protection | Done; connection-time IP checks, redirect re-validation, DNS-rebinding safe |
| Crawler | robots.txt, Crawl-delay, sitemap (incl. index), page/depth/time/size limits, per-host politeness, parallel checks across hosts, dedupe, cancellation, retry of a transient first request |
| Analysis | 90 rules: 87 scored + 3 reported as "not determined"; isolated per rule |
| Scoring | Deterministic, documented (SCORING.md, /methodology) |
| Technology detection | 41 technologies (50 passive signatures), with confidence and evidence |
| Audit lifecycle | queued/running/completed/failed/cancelled, live stage and page counter, stale-audit recovery |
| Results page | Overall + 6 category scores, summary & priorities, severity counts, filters (category/severity/page), evidence per page, not-determined list, measurements, technologies, pages table |
| PDF report | Cover, executive summary, scores, priorities, findings, affected pages, methodology; summary edition for Free |
| Accounts | Register, login, logout, password reset by e-mail, password change, account deletion |
| Security | Argon2id, server-side sessions, CSRF, brute-force throttling, IDOR-safe lookups, strict CSP and headers, log redaction, open-redirect protection |
| Plans | Free / Pro / Agency limits enforced (monthly audits, pages, concurrency, report depth, retention) |
| Admin | Overview stats, worker status, failure reasons, users (plan / active), audits |
| AI (optional) | none / Ollama / OpenAI-compatible; summary only; fails safe |
| i18n | English and Portuguese (pt-PT), complete and parity-tested |
| Own SEO | titles, descriptions, canonical, Open Graph, Twitter cards, JSON-LD, robots.txt, sitemap.xml |
| Operations | `/health`, JSON logs, `siteaudit backup`, retention purge, systemd units, Caddy config |

## Verification (2026-10-08)

- `pytest`: 157 tests pass (unit, integration with a real local HTTP site, security, E2E, live uvicorn smoke).
- `pytest -m network`: 3 checks against example.com, github.com (HTTP→HTTPS) and developer.mozilla.org pass.
- `ruff check`, `ruff format --check`, `mypy src`: clean. Wheel builds with all templates/assets.
- `pip-audit`: no known vulnerabilities.
- Browser QA (Chrome, Playwright): 8 pages × 7 widths (320, 375, 390, 768, 1024, 1280, 1440) — no horizontal
  overflow, no console errors, no CSP violations.
- Real audits through the UI: example.com (1 page, 6 s), python.org (10 pages, ~60 s), info.cern.ch (9 pages),
  developer.mozilla.org (10 pages), gov.uk (500 pages, 5 min). Sampled findings were checked by hand against
  the live HTML (e.g. invalid `role="secondary"` on python.org, `http://` iframe on gov.uk) — true positives.
  neverssl.com timed out; a manual `curl` also timed out once, so the reported reason was accurate.

Bugs found and fixed during verification: commit happening after the response (login redirect raced the new
session), error pages touching expired ORM objects (500 instead of 404), robots.txt not applied to link checks,
HEAD-only failures reported as broken links, bearer tokens not redacted in logs, session not rotated on login,
interrupted audits counting toward quota, live page counter stuck at 0.

## Open — needs a decision from the product owner

1. **Prices** for Pro and Agency, and **payment provider** (architecture is ready: `subscriptions` table).
   Until then the pricing page shows plan limits and no prices; upgrades are done by an admin.
2. **Contact e-mail** (`CONTACT_EMAIL`): enables "Contact us" on pricing and the contact link in privacy/footer.
3. **Legal review** of the privacy policy and terms (factual drafts; operator identity not stated). Requires a
   lawyer — not legal advice.
4. **Domain, hosting and SMTP provider** (costs and accounts).
5. **Social proof**: no customers, logos or testimonials were invented; add real ones when they exist.

## Known limitations / next steps

- PostgreSQL, systemd units and Caddy config are written but **not tested** on a real server (no PostgreSQL
  available locally). Do a staging deploy first.
- No rendering engine: contrast from stylesheets, layout overflow and tap-target size are "not determined";
  no Core Web Vitals. A sandboxed headless-browser stage would be the next big feature.
- Burst rate limiter is per process; add a proxy limit when running several web processes.
- No e-mail verification on sign-up; no team/organisation accounts yet (see ARCHITECTURE.md for the path).
- No CI pipeline (no remote repository yet).
