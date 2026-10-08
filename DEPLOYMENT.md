# Deployment

Reference setup: one Linux VM (2 vCPU / 2 GB is enough to start), PostgreSQL, Caddy for TLS, two systemd
services. Files are in `deploy/`.

> Status: the application has been run and tested locally with SQLite. The PostgreSQL path, the systemd units
> and the Caddy configuration have **not** been exercised on a production host yet — validate them on a
> staging server first.

## 1. System packages

```bash
sudo apt install python3.12-venv libpango-1.0-0 libpangoft2-1.0-0 postgresql caddy
sudo useradd --system --home /opt/siteaudit --shell /usr/sbin/nologin siteaudit
sudo mkdir -p /opt/siteaudit /var/lib/siteaudit /etc/siteaudit
sudo chown siteaudit: /opt/siteaudit /var/lib/siteaudit
```

## 2. Application

```bash
sudo -u siteaudit git clone <repository> /opt/siteaudit
cd /opt/siteaudit
sudo -u siteaudit python3.12 -m venv .venv
sudo -u siteaudit .venv/bin/pip install ".[postgres]"
```

## 3. Database

```bash
sudo -u postgres createuser siteaudit --pwprompt
sudo -u postgres createdb siteaudit --owner siteaudit
```

## 4. Configuration — `/etc/siteaudit/siteaudit.env` (mode 600, owner root)

```ini
APP_ENV=production
APP_URL=https://siteaudit.example.com
DATABASE_URL=postgresql+psycopg://siteaudit:<password>@localhost/siteaudit
SESSION_SECRET=<python -c "import secrets; print(secrets.token_urlsafe(48))">
DATA_DIR=/var/lib/siteaudit
WORKER_EMBEDDED=false
WORKER_CONCURRENCY=2
TRUSTED_PROXIES=127.0.0.1
SMTP_HOST=… SMTP_USER=… SMTP_PASSWORD=… SMTP_FROM=SiteAudit <no-reply@siteaudit.example.com>
CONTACT_EMAIL=support@siteaudit.example.com
```

The application refuses to start in production without a strong `SESSION_SECRET`, with a non-HTTPS
`APP_URL`, or with `ALLOW_PRIVATE_TARGETS` enabled.

## 5. Services

```bash
sudo cp deploy/siteaudit-web.service deploy/siteaudit-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now siteaudit-web siteaudit-worker
sudo -u siteaudit env $(sudo cat /etc/siteaudit/siteaudit.env | xargs) .venv/bin/siteaudit create-admin you@example.com
```

`siteaudit-web` applies migrations before starting. Scale audits by raising `WORKER_CONCURRENCY` or by running
more worker processes (on the same or other hosts); claiming is atomic.

## 6. Reverse proxy

Copy `deploy/Caddyfile` to `/etc/caddy/Caddyfile`, set the domain, `sudo systemctl reload caddy`. Caddy obtains
the certificate. The app trusts `X-Forwarded-For` only from `TRUSTED_PROXIES`.

With several web processes, the in-memory burst limiter is per process; add a per-IP rate limit at the proxy.

## 7. Outbound network

The worker needs outbound HTTP/HTTPS to the internet. As defence in depth, block egress from the worker host
to private ranges and to the cloud metadata address with the host firewall, e.g.:

```bash
sudo iptables -A OUTPUT -m owner --uid-owner siteaudit -d 169.254.169.254 -j REJECT
sudo iptables -A OUTPUT -m owner --uid-owner siteaudit -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j REJECT
```

(Allow the database host explicitly if it lives in a private range.)

## 8. Backups

- PostgreSQL: nightly `pg_dump -Fc siteaudit > /var/backups/siteaudit-$(date +%F).dump`, kept off-host,
  with a restore test at least monthly (`pg_restore -d siteaudit_restore …`).
- SQLite (small installs only): `siteaudit backup --dir /var/backups/siteaudit` (online, consistent copy).

## 9. Monitoring

- `GET /health` → `200 {"status":"ok"}`; `"degraded"` when no worker heartbeat in 60 s (audits will queue);
  `503` when the database is unreachable. Point an uptime monitor at it and alert on `degraded` too.
- Logs are JSON lines on stdout (`journalctl -u siteaudit-web -u siteaudit-worker`), with secrets redacted.
  Useful events: `audit_finished` (with `status` and `duration_ms`), `audit_crashed`, `rule_error`,
  `login_failed`, `http_error`, `email_failed`.
- The admin page shows queue length, failure reasons and worker status.

## 10. Upgrades

```bash
cd /opt/siteaudit && sudo -u siteaudit git pull && sudo -u siteaudit .venv/bin/pip install ".[postgres]"
sudo systemctl restart siteaudit-web siteaudit-worker   # migrations run on web start
```

Running audits interrupted by a worker restart are marked failed after 10 minutes and do not count toward
the user's quota.
