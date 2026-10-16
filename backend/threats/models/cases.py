from django.conf import settings
from django.db import models

from .intel import Indicator, Severity
from .telemetry import Asset


class ThreatActor(models.Model):
    """A known adversary (APT group, ransomware syndicate, crime crew)."""

    class ActorType(models.TextChoices):
        NATION_STATE = "nation_state", "Nation-state / APT"
        RANSOMWARE = "ransomware", "Ransomware syndicate"
        CYBERCRIME = "cybercrime", "Financially motivated"
        HACKTIVIST = "hacktivist", "Hacktivist"
        INSIDER = "insider", "Insider"
        UNKNOWN = "unknown", "Unknown"

    name = models.CharField(max_length=120, unique=True)
    aliases = models.JSONField(default=list, blank=True)
    actor_type = models.CharField(max_length=20, choices=ActorType.choices, default=ActorType.UNKNOWN)
    origin_country = models.CharField(max_length=2, blank=True)
    motivation = models.CharField(max_length=120, blank=True)
    description = models.TextField(blank=True)
    mitre_group_id = models.CharField(max_length=10, blank=True, help_text="ATT&CK group ID, e.g. G0007.")
    mitre_techniques = models.JSONField(default=list, blank=True)
    malware_families = models.JSONField(default=list, blank=True)
    target_sectors = models.JSONField(default=list, blank=True)
    indicators = models.ManyToManyField(Indicator, blank=True, related_name="actors")
    first_observed = models.DateField(null=True, blank=True)
    last_activity = models.DateField(null=True, blank=True)
    references = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Incident(models.Model):
    """A case that bundles related alerts so analysts work one story, not 300 alerts."""

    class Status(models.TextChoices):
        NEW = "new", "New"
        TRIAGE = "triage", "Triage"
        CONTAINED = "contained", "Contained"
        ERADICATED = "eradicated", "Eradicated"
        CLOSED = "closed", "Closed"

    OPEN_STATUSES = (Status.NEW, Status.TRIAGE, Status.CONTAINED, Status.ERADICATED)

    title = models.CharField(max_length=300)
    summary = models.TextField(blank=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.NEW, db_index=True)
    severity = models.PositiveSmallIntegerField(choices=Severity.choices, default=Severity.MEDIUM, db_index=True)
    priority_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="incidents"
    )
    assets = models.ManyToManyField(Asset, blank=True, related_name="incidents")
    attributed_actors = models.ManyToManyField(ThreatActor, blank=True, related_name="incidents")
    correlation_keys = models.JSONField(default=list, blank=True, editable=False)
    mitre_techniques = models.JSONField(default=list, blank=True)
    alert_count = models.PositiveIntegerField(default=0)
    first_activity = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True, db_index=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-priority_score", "-last_activity"]

    def __str__(self):
        return self.title


class ExternalExposure(models.Model):
    """Risk observed outside the perimeter: leaks, dark-web chatter, look-alike domains."""

    class Kind(models.TextChoices):
        LEAKED_CREDENTIAL = "leaked_credential", "Leaked credential"
        DARK_WEB_MENTION = "dark_web_mention", "Dark-web mention"
        TYPOSQUAT = "typosquat", "Typosquatted domain"
        EXPOSED_SERVICE = "exposed_service", "Exposed service"
        BRAND_ABUSE = "brand_abuse", "Brand impersonation"
        DATA_LEAK = "data_leak", "Data leak"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        INVESTIGATING = "investigating", "Investigating"
        REMEDIATED = "remediated", "Remediated"
        ACCEPTED = "accepted", "Risk accepted"
        FALSE_POSITIVE = "false_positive", "False positive"

    kind = models.CharField(max_length=20, choices=Kind.choices, db_index=True)
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True)
    severity = models.PositiveSmallIntegerField(choices=Severity.choices, default=Severity.MEDIUM, db_index=True)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.OPEN, db_index=True)
    source = models.CharField(max_length=120, blank=True)
    fingerprint = models.CharField(max_length=64, unique=True, help_text="De-duplication key.")
    data = models.JSONField(default=dict, blank=True, help_text="Never contains plaintext secrets.")
    observed_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-observed_at"]

    def __str__(self):
        return self.title


class ThreatFeed(models.Model):
    """A remote indicator feed pulled on a schedule by the `pull_feeds` command."""

    name = models.CharField(max_length=120, unique=True)
    url = models.URLField(max_length=1000)
    file_format = models.CharField(max_length=10, blank=True, help_text="csv/json/xml/stix/text; blank = auto-detect.")
    enabled = models.BooleanField(default=False)
    interval_minutes = models.PositiveIntegerField(default=60)
    default_threat_type = models.CharField(max_length=20, blank=True)
    default_severity = models.PositiveSmallIntegerField(choices=Severity.choices, null=True, blank=True)
    auth_header = models.CharField(
        max_length=500, blank=True, help_text='Optional "Header-Name: value" sent with each request.'
    )
    last_fetched_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=300, blank=True)
    last_import = models.ForeignKey("threats.ImportJob", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
