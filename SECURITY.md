# Security

## Threat model (summary)

| Asset | Threat | Control | Verified by |
|---|---|---|---|
| Internal network, cloud metadata | SSRF via audit URL, redirects, links, sitemap, assets | URL validation + connection-time IP check on every request (see below) | `tests/test_urlsafety.py` |
| Audited websites | Crawler abuse / overload | robots.txt, per-host delay (≥0.5 s, Crawl-delay up to 5 s), page/depth/time limits, plan quotas, user-agent page `/bot` | `test_crawler_and_rules.py` |
| Accounts | Credential stuffing / brute force | Argon2id, 5 failures per e-mail and 20 per IP in 15 min, generic error messages, constant-time dummy hash for unknown e-mails | `test_web.py` |
| Sessions | Theft, fixation | Random 256-bit token, only SHA-256 stored, HttpOnly + SameSite=Lax (+ Secure on HTTPS), rotated on login and password change | `test_web.py`, `test_logging_and_session.py` |
| State-changing requests | CSRF | Signed double-submit token on every POST + Origin check + SameSite cookies | `test_web.py` |
| Other users' audits/reports | IDOR | Every lookup filtered by owner; random 128-bit ids; 404 for non-owners (no existence leak) | `test_users_cannot_access_each_others_audits` |
| Admin area | Privilege escalation | Role check on every route, 404 for non-admins | `test_web.py` |
| Rendered pages | XSS from audited content | Jinja autoescaping; strict CSP with nonce; no inline styles | `test_security_headers`, E2E filter test |
| PDF rendering | SSRF/file read via report | WeasyPrint fetcher allows only two bundled files | `reports/pdf.py` |
| Sitemap parsing | XXE / billion laughs | lxml with `resolve_entities=False`, `no_network=True`, size cap | `test_sitemap_xxe_is_not_expanded` |
| Logs | Secret leakage | Redacting filter on all handlers (passwords, tokens, cookies, API keys, bearer tokens); access log goes through it | `test_logging_and_session.py` |
| Database | SQL injection | SQLAlchemy parameterised queries only | — |
| Redirect parameters | Open redirect | `next` accepts only local absolute paths | `test_open_redirect_is_prevented` |
| Availability | Resource exhaustion | Response size cap (5 MB/page, 200 MB/audit), timeouts, bounded worker pool, per-user concurrency, per-IP request bursts | — |

## SSRF protection in detail

1. `normalize_target()` rejects non-HTTP schemes (including `javascript:`/`file:` without `//`), embedded
   credentials, non-standard ports (only 80/443), numeric/hex IP notations, single-label and internal host
   names (`localhost`, `.local`, `.internal`, …) and non-public IP literals.
2. `GuardedBackend.connect_tcp()` resolves the host **at connection time** and refuses the connection if
   *any* resolved address is loopback, private, link-local (incl. 169.254.169.254), CGNAT, multicast,
   reserved or unspecified — including IPv4-mapped, 6to4 and Teredo IPv6 forms. The socket connects to the
   exact address that was checked, which defeats DNS rebinding.
3. Redirects are followed manually (max 5) and each hop goes through steps 1–2.
4. Proxy environment variables are ignored.
5. `ALLOW_PRIVATE_TARGETS` exists only for tests and is refused when `APP_ENV=production`.

## What the audit does *not* do

No form submission, no login attempts, no path guessing, no payloads, no port scanning. Security checks only
read the headers, cookies and TLS certificate of responses the crawler already receives.

## HTTP security headers (application)

`Content-Security-Policy` (default-src 'self'; nonce-based scripts; frame-ancestors 'none'),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `Strict-Transport-Security` when `APP_URL` is HTTPS, `Cache-Control: no-store`
on authenticated pages.

## Secrets

All secrets come from environment variables (`.env` is git-ignored; `.env.example` has no values).
Production refuses to start without a 32+ character `SESSION_SECRET` and with a non-HTTPS `APP_URL`.

## Known limitations

- The burst limiter is in-memory per web process; with several processes or hosts, add a limit at the reverse
  proxy. Login throttling and quotas are in the database and are global.
- E-mail verification at sign-up is not implemented.
- No CI exists yet. `pip-audit` reported no known vulnerabilities on 2026-10-08; run it before every release.

## Reporting a vulnerability

Send details to the address configured in `CONTACT_EMAIL`. Please do not run intrusive tests against
production.
