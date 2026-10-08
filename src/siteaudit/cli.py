"""Command-line entry point: `siteaudit <command>`."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .config import get_settings


def cmd_migrate(_args: argparse.Namespace) -> int:
    from .migrations_config import upgrade

    upgrade()
    print("Database is up to date.")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "siteaudit.web.asgi:app",
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        log_config=None,
    )
    return 0


def cmd_worker(_args: argparse.Namespace) -> int:
    import signal

    from .db import init_engine
    from .logging_setup import configure_logging
    from .worker import Worker

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    init_engine(settings)
    worker = Worker(settings)

    def stop(*_: object) -> None:
        worker._stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    worker.run_forever()
    worker.stop()
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from .db import init_engine, session_scope
    from .models import User
    from .security.auth import AuthError, create_user, hash_password, validate_password

    init_engine()
    password = args.password or getpass.getpass("Password (min. 10 characters): ")
    with session_scope() as db:
        existing = db.scalar(select(User).where(User.email == args.email.strip().lower()))
        if existing is not None:
            problem = validate_password(password, existing.email)
            if problem:
                print(f"Error: {problem}", file=sys.stderr)
                return 1
            existing.role = "admin"
            existing.password_hash = hash_password(password)
            print(f"{existing.email} is now an administrator.")
            return 0
        try:
            user = create_user(db, args.email, password, name=args.name or "")
        except AuthError as exc:
            print(f"Error: {exc.code}", file=sys.stderr)
            return 1
        user.role = "admin"
        print(f"Administrator {user.email} created.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Run an audit directly (no database) and print the result. Useful for QA against real sites."""
    from .analysis.base import run_rules
    from .analysis.registry import CATEGORY_ORDER
    from .crawler.crawler import Crawler, CrawlError, CrawlLimits
    from .i18n import t
    from .net.client import SafeClient
    from .net.urlsafety import Policy, UnsafeURLError, normalize_target
    from .scoring import score

    settings = get_settings()
    policy = Policy(allow_private=settings.allow_private_targets)
    try:
        url = normalize_target(args.url, policy)
    except UnsafeURLError as exc:
        print(f"Invalid URL: {exc.code}", file=sys.stderr)
        return 2
    limits = CrawlLimits(
        max_pages=args.pages,
        max_depth=args.depth,
        delay=settings.crawl_delay,
        deadline_seconds=settings.crawl_audit_timeout,
    )
    with SafeClient(
        user_agent=settings.crawl_user_agent,
        timeout=settings.crawl_request_timeout,
        max_bytes=settings.crawl_max_response_bytes,
        policy=policy,
    ) as client:
        try:
            snap = Crawler(client, limits, progress=lambda s: print(f"… {s}", file=sys.stderr)).run(url)
        except CrawlError as exc:
            print(f"Audit failed: {exc.code}", file=sys.stderr)
            return 1
    result = None
    for _cat, partial in run_rules(snap, CATEGORY_ORDER):
        result = partial
    assert result is not None
    card = score(result)
    if args.json:
        print(
            json.dumps(
                {
                    "url": snap.start_url,
                    "pages": len(snap.html_pages),
                    "overall": card.overall,
                    "categories": {c: s.score for c, s in card.categories.items()},
                    "findings": [
                        {
                            "rule": f.rule_id,
                            "severity": f.severity,
                            "page": f.page_url,
                            "evidence": f.evidence,
                        }
                        for f in result.findings
                    ],
                    "undetermined": result.undetermined,
                    "errored": result.errored,
                },
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )
        return 0
    print(f"\n{snap.start_url} — {len(snap.html_pages)} page(s), overall {card.overall}")
    for cat, cs in card.categories.items():
        print(f"  {cat:15} {cs.score!s:>4}   ({cs.checks_failed}/{cs.checks_run} checks failed)")
    seen: set[str] = set()
    for f in sorted(
        result.findings, key=lambda f: ("critical", "high", "medium", "low", "info").index(f.severity)
    ):
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        n = sum(1 for x in result.findings if x.rule_id == f.rule_id)
        print(f"  [{f.severity:8}] {t('en', 'rules.' + f.rule_id + '.title')} ({n}×)")
    if result.errored:
        print(f"  rules with errors: {result.errored}")
    return 0


def cmd_purge(_args: argparse.Namespace) -> int:
    from .audits.retention import purge_expired
    from .db import init_engine, session_scope

    init_engine()
    with session_scope() as db:
        n = purge_expired(db)
    print(f"Deleted {n} expired audit(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="siteaudit", description="SiteAudit AI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("migrate", help="apply database migrations").set_defaults(fn=cmd_migrate)

    p = sub.add_parser("serve", help="run the web server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(fn=cmd_serve)

    sub.add_parser("worker", help="run the audit worker").set_defaults(fn=cmd_worker)

    p = sub.add_parser("create-admin", help="create an administrator (or promote an existing user)")
    p.add_argument("email")
    p.add_argument("--name", default="")
    p.add_argument("--password", default="", help="omit to be prompted (recommended)")
    p.set_defaults(fn=cmd_create_admin)

    p = sub.add_parser("audit", help="audit a URL from the command line (no database)")
    p.add_argument("url")
    p.add_argument("--pages", type=int, default=10)
    p.add_argument("--depth", type=int, default=3)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_audit)

    sub.add_parser("purge", help="delete audits past their plan's retention period").set_defaults(
        fn=cmd_purge
    )

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
