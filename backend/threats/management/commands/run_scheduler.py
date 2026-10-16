import logging
import signal
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from threats.management.commands.threat_maintenance import run_maintenance
from threats.services.exposure import scan_typosquats
from threats.services.feeds import due_feeds, ensure_default_feeds, pull_feed

logger = logging.getLogger("threats.scheduler")


class Command(BaseCommand):
    help = "Long-running worker: pulls due feeds every minute and runs maintenance on a fixed cadence."

    def add_arguments(self, parser):
        parser.add_argument("--maintenance-minutes", type=int, default=15)
        parser.add_argument("--typosquat-hours", type=int, default=24)
        parser.add_argument("--once", action="store_true", help="Run every job once and exit.")

    def handle(self, *args, **options):
        self.running = True
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        ensure_default_feeds()
        last_maintenance = last_typosquat = 0.0
        logger.info("Scheduler started")
        while self.running:
            close_old_connections()
            now = time.monotonic()
            for feed in due_feeds():
                try:
                    pull_feed(feed)
                    logger.info("Pulled feed %s: %s", feed.name, feed.last_status)
                except Exception:  # noqa: BLE001 - one bad feed must not stop the worker
                    logger.exception("Feed %s crashed", feed.name)
            if now - last_maintenance >= options["maintenance_minutes"] * 60 or options["once"]:
                try:
                    logger.info("Maintenance: %s", run_maintenance())
                except Exception:  # noqa: BLE001
                    logger.exception("Maintenance failed")
                last_maintenance = now
            if now - last_typosquat >= options["typosquat_hours"] * 3600 or options["once"]:
                try:
                    findings = scan_typosquats(resolve=True)
                    logger.info("Typosquat scan: %d finding(s)", len(findings))
                except Exception:  # noqa: BLE001
                    logger.exception("Typosquat scan failed")
                last_typosquat = now
            if options["once"]:
                break
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)
        logger.info("Scheduler stopped")

    def _stop(self, *args):
        self.running = False
