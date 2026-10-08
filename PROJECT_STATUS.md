# SiteAudit AI — Project status

## Phase 0 — discovery (2026-10-07)

**Starting point.** No SiteAudit code existed anywhere on the machine. The workspace the request was issued from
(`SoftwareCompany-v3`) is an unrelated orchestration tool and was intentionally left untouched. This repository was
created from scratch at `~/Projetos/siteaudit-ai`.

**Environment (verified).**

| Item | Found |
|---|---|
| OS | Linux (kernel 7.0), 8 cores, 31 GB RAM |
| Python | 3.12.3 (venv in `.venv/`) |
| Node | 22.23.1 (not used) |
| Databases | SQLite 3 available; no PostgreSQL server installed |
| Containers | no Docker / Podman |
| Browser | Google Chrome (used only for responsive screenshots in QA) |
| PDF | Pango 1.52 present → WeasyPrint works |

**Stack decision.** Python 3.12 · FastAPI (server-rendered Jinja templates, minimal vanilla JS) · SQLAlchemy 2 +
Alembic · SQLite in development, PostgreSQL through `DATABASE_URL` in production · database-backed job queue with a
separate worker process · httpx with a custom SSRF-guarded transport · BeautifulSoup/lxml for parsing · Argon2 for
passwords · WeasyPrint for PDF reports.

Reasoning: one runtime, no build step for the frontend, no Redis or message broker to operate, two processes in
production (web + worker). Crawling and HTML analysis are well served by the Python ecosystem.

See the sections below for the current state; they are updated at the end of every phase.
