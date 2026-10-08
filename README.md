# SiteAudit AI

Professional website audits that show you what needs fixing.

Enter a URL; SiteAudit crawls the site (respecting robots.txt), runs 87 deterministic checks across SEO,
performance, accessibility, mobile, security and best practices, scores each area with a published formula,
and produces a prioritised list of findings with evidence, plus a PDF report. AI is optional and only used to
write a plain-language summary.

## Requirements

- Python 3.12+
- System libraries for WeasyPrint (PDF): Pango ≥ 1.44 (`libpango-1.0-0 libpangoft2-1.0-0` on Debian/Ubuntu)
- SQLite (development) or PostgreSQL (production)

## Quick start (development)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp .env.example .env            # defaults work for local development
.venv/bin/siteaudit migrate
.venv/bin/siteaudit create-admin you@example.com   # prompts for a password
.venv/bin/siteaudit serve       # http://localhost:8000 (worker runs in-process in development)
```

Password-reset e-mails are written to `var/outbox/` unless SMTP is configured.

## Commands

| Command | Purpose |
|---|---|
| `siteaudit serve [--host --port --workers]` | Web server |
| `siteaudit worker` | Audit worker (separate process in production) |
| `siteaudit migrate` | Apply database migrations |
| `siteaudit create-admin EMAIL` | Create an administrator or promote an existing user |
| `siteaudit audit URL [--pages N] [--json]` | Run an audit from the terminal, without the database |
| `siteaudit backup [--dir D]` | Consistent copy of a SQLite database |
| `siteaudit purge` | Delete audits past their plan's retention (the worker also does this automatically) |

## Tests and quality checks

```bash
.venv/bin/pytest                 # unit, integration, security and end-to-end tests (offline)
.venv/bin/pytest -m network      # optional checks against real public websites
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
.venv/bin/mypy src
```

The test suite starts a real local HTTP server as the "website under audit" and a real uvicorn server for
the session smoke test; no network access is needed for the default run.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, data flow, data model
- [SCORING.md](SCORING.md) — scoring formula and every check
- [SECURITY.md](SECURITY.md) — threat model and controls
- [DEPLOYMENT.md](DEPLOYMENT.md) — production setup, backups, monitoring
- [PROJECT_STATUS.md](PROJECT_STATUS.md) — what is done, what is open, known limitations
