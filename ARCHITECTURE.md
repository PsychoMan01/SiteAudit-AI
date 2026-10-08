# Architecture

SiteAudit is a server-rendered Python web application plus a background worker. Two processes, one database,
no message broker.

```
Browser ──HTTPS──> reverse proxy (Caddy/nginx) ──> web (FastAPI, Jinja)  ──┐
                                                                          ├──> database (PostgreSQL / SQLite)
                                       worker (siteaudit worker) ─────────┘
                                          │
                                          └──> audited websites (via the SSRF-guarded HTTP client)
```

## Request flow of an audit

1. **Validation** (`net/urlsafety.py`): scheme, credentials, port, host shape, IP literal, DNS answer.
2. **Quota** (`audits/service.py`): concurrent and monthly limits of the user's plan.
3. **Queue**: the audit row is inserted with status `queued`. Workers claim rows with an atomic
   `UPDATE … WHERE status='queued'`, so several workers can run safely.
4. **Crawl** (`crawler/crawler.py`): first page (one retry on transient errors) → robots.txt → sitemap →
   breadth-first crawl of same-site pages → link checks → asset checks → HTTP→HTTPS probe and TLS
   inspection. Each page's HTML is parsed once into a compact `PageDoc` (`crawler/extract.py`) and discarded.
5. **Analysis** (`analysis/`): rules are pure functions over the resulting `SiteSnapshot`. Each rule is
   isolated — an exception marks only that rule as errored. A rule may declare itself *not applicable* or
   *not determined*.
6. **Scoring** (`scoring.py`): deterministic formula, see SCORING.md.
7. **Persistence**: pages, findings (rule id + evidence parameters, not prose), scores, technologies and
   site facts. Text is rendered at display time from the i18n catalogue, so one audit reads correctly in
   English and Portuguese.
8. **Optional AI** (`ai/providers.py`): a short plain-language summary from rule titles and scores. Failures
   return `None`; nothing depends on it.

Progress is written to `audits.stage`; the results page polls `/audits/{id}/status`. Cancellation sets a
flag the crawler checks between requests. A worker heartbeat marks audits abandoned by a crashed worker as
`failed` after 10 minutes.

## Modules

| Area | Location |
|---|---|
| Settings | `config.py` (environment variables, `.env`) |
| Persistence | `models.py`, `db.py`, `migrations/` (Alembic) |
| Outbound HTTP / SSRF | `net/urlsafety.py`, `net/client.py`, `net/tls.py` |
| Crawling | `crawler/` |
| Analysis | `analysis/{seo,performance,accessibility,mobile,security,best_practices,technology}.py` |
| Scoring | `scoring.py` |
| Audit lifecycle | `audits/service.py`, `audits/summary.py`, `audits/retention.py`, `worker.py` |
| Authentication | `security/auth.py` (Argon2, sessions, reset tokens, throttling), `security/csrf.py` |
| Web | `web/app.py` (middleware, headers, errors), `web/deps.py`, `web/routes/`, `web/templates/` |
| Reports | `reports/pdf.py`, `reports/templates/` (WeasyPrint, local-only resource fetcher) |
| Plans / billing | `plans.py` (limits), `subscriptions` table (`provider='manual'` until a gateway is added) |
| i18n | `i18n/en.json`, `i18n/pt.json` |
| E-mail | `mailer.py` (SMTP, or files in `DATA_DIR/outbox` when SMTP is not configured) |

## Data model

| Table | Purpose |
|---|---|
| `users` | account, role (`user`/`admin`), locale, active flag |
| `subscriptions` | plan and billing status per user; source of truth for the plan |
| `sessions` | server-side sessions (SHA-256 of the token only) |
| `password_reset_tokens` | single-use, one-hour tokens (hashed) |
| `auth_events` | login/registration/reset attempts for throttling (keyed e-mail hash + IP), pruned after 2 days |
| `audits` | one audit: URL, status, stage, limits snapshot, overall score, technologies, site facts |
| `audit_pages` | pages fetched: status, response time, HTML size, title, error |
| `audit_issues` | findings: rule id, category, severity, page, evidence parameters (JSON) |
| `audit_scores` | per-category score, checks run and failed |
| `reports` | PDF exports (for usage statistics) |
| `usage` | audit creations, used for the monthly quota |
| `worker_heartbeats` | liveness of worker processes (used by `/health` and the admin page) |

All foreign keys cascade on user/audit deletion. Constraints enforce valid statuses, severities, categories,
plans and score ranges. Timestamps are stored in UTC.

## Multi-tenancy

Every audit query is scoped by `user_id`; audits are addressed by a random 128-bit `public_id`, and any
audit that does not belong to the requester returns 404. Teams/organisations can be added by introducing an
`organizations` table and moving ownership from `user_id` to `organization_id` with a membership table; the
single ownership helper (`_owned_audit`) is the place to change.

## Payments (not integrated)

Plans and limits are enforced from `subscriptions.plan`. A payment gateway (e.g. Stripe) would create/update
`subscriptions` rows from its webhooks (`provider`, `provider_ref`, `current_period_end`). Until then an
administrator assigns plans in the admin area.

## Design decisions

- **Server-rendered HTML, no frontend build.** Faster pages, strict CSP (`script-src 'self'`, no inline
  styles), works without JavaScript. ~2 KB of progressive-enhancement JS.
- **Database queue instead of Redis/Celery.** Audit volume per instance is small; one fewer service to run.
- **Facts first, prose later.** Findings store parameters; wording lives in translation catalogues.
- **No headless browser in the audit pipeline.** Keeps audits cheap and the attack surface small; checks that
  need rendering are reported as "not determined".
