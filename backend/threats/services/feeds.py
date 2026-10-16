"""Scheduled ingestion of remote indicator feeds."""
import logging
import urllib.error
import urllib.request
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..models import ImportJob, Source, ThreatFeed
from .importers import run_import
from .netsafety import UnsafeURLError, safe_urlopen

logger = logging.getLogger(__name__)

USER_AGENT = "ThreatDashboard-FeedFetcher/2.0"

# Public, free feeds. They are created disabled; enable the ones you want.
DEFAULT_FEEDS = [
    {"name": "abuse.ch URLhaus (recent URLs)", "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
     "file_format": "text", "default_threat_type": "malware", "default_severity": 3, "interval_minutes": 60},
    {"name": "abuse.ch Feodo Tracker (botnet C2 IPs)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "file_format": "text", "default_threat_type": "c2", "default_severity": 4, "interval_minutes": 60},
    {"name": "abuse.ch SSLBL (botnet C2 IPs)", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
     "file_format": "text", "default_threat_type": "c2", "default_severity": 3, "interval_minutes": 120},
    {"name": "OpenPhish community feed", "url": "https://openphish.com/feed.txt",
     "file_format": "text", "default_threat_type": "phishing", "default_severity": 3, "interval_minutes": 120},
    {"name": "CISA Known Exploited Vulnerabilities",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "file_format": "json", "default_threat_type": "exploit", "default_severity": 4, "interval_minutes": 720},
]


class FeedError(Exception):
    pass


def ensure_default_feeds():
    for spec in DEFAULT_FEEDS:
        ThreatFeed.objects.get_or_create(name=spec["name"], defaults=spec)


def fetch(feed):
    request = urllib.request.Request(feed.url, headers={"User-Agent": USER_AGENT})
    if feed.auth_header and ":" in feed.auth_header:
        name, _, value = feed.auth_header.partition(":")
        request.add_header(name.strip(), value.strip())
    limit = settings.THREATDASH_FEED_MAX_BYTES
    try:
        with safe_urlopen(request, timeout=settings.THREATDASH_FEED_TIMEOUT_SECONDS,
                          allow_private=settings.THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS) as response:
            body = response.read(limit + 1)
    except UnsafeURLError as exc:
        raise FeedError(f"Blocked: {exc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FeedError(f"Download failed: {exc}") from exc
    if len(body) > limit:
        raise FeedError(f"Feed is larger than the {limit // (1024 * 1024)} MB limit.")
    return body


def _cisa_kev_to_records(body):
    """CISA KEV publishes {"vulnerabilities": [...]}; map it to the importer's schema."""
    import json

    data = json.loads(body)
    records = [
        {"value": v.get("cveID"), "ioc_type": "cve", "description": f"{v.get('vendorProject', '')} "
         f"{v.get('product', '')}: {v.get('vulnerabilityName', '')}".strip(), "first_seen": v.get("dateAdded"),
         "tags": ["cisa-kev"] + (["ransomware"] if v.get("knownRansomwareCampaignUse") == "Known" else [])}
        for v in data.get("vulnerabilities", []) if v.get("cveID")
    ]
    return json.dumps(records).encode()


def pull_feed(feed):
    """Download and import one feed; returns the ImportJob."""
    source, _ = Source.objects.get_or_create(
        name=feed.name[:120], defaults={"kind": Source.Kind.FEED, "reliability": Source.Reliability.B, "url": feed.url}
    )
    job = ImportJob(filename=feed.url[-255:], file_format=feed.file_format or "", source=source)
    try:
        body = fetch(feed)
        if "known_exploited_vulnerabilities" in feed.url:
            body, job.file_format = _cisa_kev_to_records(body), ImportJob.Format.JSON
        job.save()
        run_import(job, body, source=source, defaults={
            "threat_type": feed.default_threat_type, "severity": feed.default_severity,
        })
        feed.last_status = f"{job.get_status_display()}: {job.created_count} new, {job.updated_count} updated, " \
                           f"{job.error_count} errors"
    except (FeedError, ValueError) as exc:
        feed.last_status = f"Failed: {exc}"[:300]
        if job.pk:
            job.status, job.message, job.finished_at = ImportJob.Status.FAILED, str(exc)[:1000], timezone.now()
            job.save()
        logger.warning("Feed %s failed: %s", feed.name, exc)
    feed.last_fetched_at = timezone.now()
    feed.last_import = job if job.pk else None
    feed.save(update_fields=["last_status", "last_fetched_at", "last_import"])
    return job


def due_feeds(now=None):
    now = now or timezone.now()
    return [
        feed for feed in ThreatFeed.objects.filter(enabled=True)
        if feed.last_fetched_at is None or feed.last_fetched_at + timedelta(minutes=feed.interval_minutes) <= now
    ]
