import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone

from .intel import Indicator, Severity


class TelemetryDomain(models.TextChoices):
    ENDPOINT = "endpoint", "Endpoint"
    CLOUD = "cloud", "Cloud"
    IDENTITY = "identity", "Identity"
    NETWORK = "network", "Network"
    EMAIL = "email", "Email"


class Asset(models.Model):
    """A device, workload or service discovered on the estate."""

    class AssetType(models.TextChoices):
        WORKSTATION = "workstation", "Workstation"
        LAPTOP = "laptop", "Laptop"
        SERVER = "server", "Server"
        MOBILE = "mobile", "Mobile device"
        NETWORK_DEVICE = "network_device", "Network device"
        IOT = "iot", "IoT / OT device"
        CLOUD_INSTANCE = "cloud_instance", "Cloud instance"
        CONTAINER = "container", "Container"
        SAAS = "saas", "SaaS application"
        UNKNOWN = "unknown", "Unknown"

    class DiscoveryMethod(models.TextChoices):
        AGENT = "agent", "Endpoint agent"
        TELEMETRY = "telemetry", "Passive telemetry"
        NETWORK_SCAN = "network_scan", "Network scan"
        CLOUD_API = "cloud_api", "Cloud inventory API"
        MANUAL = "manual", "Manual"

    hostname = models.CharField(max_length=255, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    mac_address = models.CharField(max_length=17, blank=True)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices, default=AssetType.UNKNOWN)
    operating_system = models.CharField(max_length=120, blank=True)
    owner = models.CharField(max_length=150, blank=True)
    department = models.CharField(max_length=100, blank=True, db_index=True)
    criticality = models.PositiveSmallIntegerField(choices=Severity.choices, default=Severity.MEDIUM)
    managed = models.BooleanField(
        default=False, help_text="Enrolled in management/EDR. Unmanaged assets are treated as shadow IT."
    )
    discovered_via = models.CharField(max_length=20, choices=DiscoveryMethod.choices, default=DiscoveryMethod.TELEMETRY)
    cloud_provider = models.CharField(max_length=20, blank=True)
    cloud_resource_id = models.CharField(max_length=500, blank=True)
    software = models.JSONField(default=list, blank=True, help_text='[{"name": "openssl", "version": "3.0.1"}]')
    vulnerabilities = models.JSONField(default=list, blank=True, help_text='[{"cve": "CVE-2024-3400", "cvss": 10.0}]')
    tags = models.JSONField(default=list, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    is_isolated = models.BooleanField(default=False, db_index=True)
    isolated_at = models.DateTimeField(null=True, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score", "hostname"]

    def __str__(self):
        return self.hostname or self.ip_address or f"asset-{self.pk}"

    @property
    def is_shadow_it(self):
        return not self.managed

    @property
    def max_cvss(self):
        scores = [float(v.get("cvss") or 0) for v in self.vulnerabilities or [] if isinstance(v, dict)]
        return max(scores, default=0.0)


class DataConnector(models.Model):
    """A log source that pushes telemetry with its own ingestion key."""

    class Provider(models.TextChoices):
        GENERIC = "generic", "Generic JSON"
        AWS_CLOUDTRAIL = "aws_cloudtrail", "AWS CloudTrail"
        AZURE_SIGNIN = "azure_signin", "Microsoft Entra ID sign-in logs"
        AZURE_ACTIVITY = "azure_activity", "Azure activity log"
        EDR = "edr", "EDR / endpoint agent"
        FIREWALL = "firewall", "Firewall / NDR"
        EMAIL_GATEWAY = "email_gateway", "Email security gateway"
        DARK_WEB = "dark_web", "Dark-web / external risk monitoring"

    name = models.CharField(max_length=120, unique=True)
    provider = models.CharField(max_length=20, choices=Provider.choices, default=Provider.GENERIC)
    domain = models.CharField(max_length=10, choices=TelemetryDomain.choices, default=TelemetryDomain.ENDPOINT)
    enabled = models.BooleanField(default=True)
    key_prefix = models.CharField(max_length=12, editable=False, db_index=True, blank=True)
    key_hash = models.CharField(max_length=64, editable=False, blank=True)
    events_received = models.PositiveBigIntegerField(default=0, editable=False)
    last_event_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @staticmethod
    def hash_key(key):
        return hashlib.sha256(key.encode()).hexdigest()

    def rotate_key(self):
        """Generate a new ingestion key; only its hash is stored, so return the plaintext once."""
        key = f"tdk_{secrets.token_urlsafe(32)}"
        self.key_prefix = key[:12]
        self.key_hash = self.hash_key(key)
        return key

    def check_key(self, key):
        return bool(self.key_hash) and secrets.compare_digest(self.key_hash, self.hash_key(key))


class TelemetryEvent(models.Model):
    """A normalised log event from any security domain."""

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    domain = models.CharField(max_length=10, choices=TelemetryDomain.choices, db_index=True)
    provider = models.CharField(max_length=30, blank=True, db_index=True)
    event_type = models.CharField(max_length=100, db_index=True)
    severity = models.PositiveSmallIntegerField(choices=Severity.choices, default=Severity.LOW, db_index=True)
    outcome = models.CharField(max_length=20, blank=True, help_text="success / failure / blocked / unknown")
    message = models.CharField(max_length=1000, blank=True)
    connector = models.ForeignKey(DataConnector, null=True, blank=True, on_delete=models.SET_NULL, related_name="events")
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL, related_name="events")
    target_asset = models.ForeignKey(
        Asset, null=True, blank=True, on_delete=models.SET_NULL, related_name="inbound_events",
        help_text="Destination asset, for lateral movement.",
    )
    username = models.CharField(max_length=255, blank=True, db_index=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    domain_name = models.CharField(max_length=255, blank=True, help_text="DNS name / sender domain observed.")
    url = models.CharField(max_length=2048, blank=True)
    file_hash = models.CharField(max_length=64, blank=True)
    process = models.CharField(max_length=500, blank=True)
    bytes_out = models.PositiveBigIntegerField(null=True, blank=True)
    country = models.CharField(max_length=2, blank=True)
    mitre_technique = models.CharField(max_length=12, blank=True)
    matched_indicators = models.ManyToManyField(Indicator, blank=True, related_name="sightings")
    raw = models.JSONField(default=dict, blank=True)
    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["domain", "timestamp"]), models.Index(fields=["username", "event_type"])]

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M} {self.domain}/{self.event_type}"
