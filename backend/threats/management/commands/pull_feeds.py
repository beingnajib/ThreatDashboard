from django.core.management.base import BaseCommand, CommandError

from threats.models import ThreatFeed
from threats.services.feeds import due_feeds, ensure_default_feeds, pull_feed


class Command(BaseCommand):
    help = "Download and import threat feeds that are due (or a named feed with --feed)."

    def add_arguments(self, parser):
        parser.add_argument("--feed", help="Name of a single feed to pull now, enabled or not.")
        parser.add_argument("--all", action="store_true", help="Pull every enabled feed regardless of schedule.")

    def handle(self, *args, **options):
        ensure_default_feeds()
        if options["feed"]:
            feed = ThreatFeed.objects.filter(name=options["feed"]).first()
            if feed is None:
                raise CommandError(f"No feed named {options['feed']!r}.")
            targets = [feed]
        elif options["all"]:
            targets = list(ThreatFeed.objects.filter(enabled=True))
        else:
            targets = due_feeds()
        if not targets:
            self.stdout.write("No feeds are due.")
        for feed in targets:
            pull_feed(feed)
            self.stdout.write(f"{feed.name}: {feed.last_status}")
