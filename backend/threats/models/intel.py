from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class Severity(models.IntegerChoices):
    LOW = 1, "Low"
    MEDIUM = 2, "Medium"
    HIGH = 3, "High"
    CRITICAL = 4, "Critical"


class IOCType(models.TextChoices):
    IPV4 = "ipv4", "IPv4 address"
    IPV6 = "ipv6", "IPv6 address"
    DOMAIN = "domain", "Domain"
    URL = "url", "URL"
    MD5 = "md5", "MD5 hash"
    SHA1 = "sha1", "SHA-1 hash"
    SHA256 = "sha256", "SHA-256 hash"
    EMAIL = "email", "Email address"
    CVE = "cve", "CVE identifier"


class ThreatType(models.TextChoices):
    MALWARE = "malware", "Malware"
    RANSOMWARE = "ransomware", "Ransomware"
    PHISHING = "phishing", "Phishing"
    C2 = "c2", "Command & control"
    BOTNET = "botnet", "Botnet"
    APT = "apt", "APT / targeted"
    EXPLOIT = "exploit", "Exploit / vulnerability"
    SCANNER = "scanner", "Scanning / recon"
    BRUTE_FORCE = "brute_force", "Brute force"
    SPAM = "spam", "Spam"
    DATA_EXFIL = "data_exfiltration", "Data exfiltration"
    OTHER = "other", "Other"


class TLP(models.TextChoices):
    CLEAR = "clear", "TLP:CLEAR"
    GREEN = "green", "TLP:GREEN"
    AMBER = "amber", "TLP:AMBER"
    AMBER_STRICT = "amber_strict", "TLP:AMBER+STRICT"
    RED = "red", "TLP:RED"


class Source(models.Model):
    """A feed, tool or team that supplies indicators."""

    class Kind(models.TextChoices):
        FEED = "feed", "Threat feed"
        OSINT = "osint", "OSINT"
        INTERNAL = "internal", "Internal telemetry"
        MANUAL = "manual", "Manual entry"
        IMPORT = "import", "File import"

    class Reliability(models.TextChoices):
        # NATO Admiralty Code for source reliability.
        A = "A", "A - Completely reliable"
        B = "B", "B - Usually reliable"
        C = "C", "C - Fairly reliable"
        D = "D", "D - Not usually reliable"
        E = "E", "E - Unreliable"
        F = "F", "F - Reliability cannot be judged"

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=20, choices=Kind.choices, default=Kind.MANUAL)
    reliability = models.CharField(max_length=1, choices=Reliability.choices, default=Reliability.F)
    url = models.URLField(blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Indicator(models.Model):
    """An indicator of compromise (IOC) and the intelligence attached to it."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INVESTIGATING = "investigating", "Investigating"
        MITIGATED = "mitigated", "Mitigated"
        FALSE_POSITIVE = "false_positive", "False positive"
        EXPIRED = "expired", "Expired"

    value = models.CharField(max_length=2048)
    ioc_type = models.CharField(max_length=10, choices=IOCType.choices, db_index=True)
    threat_type = models.CharField(max_length=20, choices=ThreatType.choices, default=ThreatType.OTHER, db_index=True)
    severity = models.PositiveSmallIntegerField(choices=Severity.choices, default=Severity.MEDIUM, db_index=True)
    confidence = models.PositiveSmallIntegerField(default=50, help_text="Analyst confidence, 0-100.")
    risk_score = models.PositiveSmallIntegerField(default=0, db_index=True, editable=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE, db_index=True)
    tlp = models.CharField(max_length=15, choices=TLP.choices, default=TLP.AMBER)
    source = models.ForeignKey(Source, null=True, blank=True, on_delete=models.SET_NULL, related_name="indicators")
    tags = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    country = models.CharField(max_length=2, blank=True, help_text="ISO 3166-1 alpha-2 country code.")
    cvss_score = models.DecimalField(
        max_digits=3, decimal_places=1, null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)],
        help_text="CVSS v3/v4 base score, for CVE indicators.",
    )
    description = models.TextField(blank=True)
    enrichment = models.JSONField(default=dict, blank=True, editable=False)
    sighting_count = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(default=timezone.now, db_index=True)
    last_seen = models.DateTimeField(default=timezone.now, db_index=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score", "-last_seen"]
        constraints = [
            models.UniqueConstraint(fields=["ioc_type", "value"], name="unique_indicator_type_value"),
            models.CheckConstraint(condition=models.Q(confidence__lte=100), name="indicator_confidence_lte_100"),
        ]
        indexes = [models.Index(fields=["status", "severity"])]

    def __str__(self):
        return f"{self.ioc_type}:{self.value}"

    @property
    def is_actionable(self):
        return self.status in (self.Status.ACTIVE, self.Status.INVESTIGATING)

    def save(self, *args, **kwargs):
        from ..services.enrichment import enrich
        from ..services.scoring import compute_risk_score

        if not self.enrichment or self._value_changed():
            self.enrichment = enrich(self.ioc_type, self.value)
        if self.last_seen and self.first_seen and self.last_seen < self.first_seen:
            self.last_seen = self.first_seen
        self.risk_score = compute_risk_score(self)
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = set(update_fields) | {"risk_score", "enrichment", "updated_at"}
        super().save(*args, **kwargs)

    def _value_changed(self):
        if not self.pk:
            return True
        previous = Indicator.objects.filter(pk=self.pk).values_list("ioc_type", "value").first()
        return previous != (self.ioc_type, self.value)


class DetectionRule(models.Model):
    """A watchlist rule; indicators that match every set condition raise an alert."""

    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    ioc_types = models.JSONField(default=list, blank=True, help_text="Match any of these IOC types (empty = any).")
    threat_types = models.JSONField(default=list, blank=True, help_text="Match any of these threat types (empty = any).")
    tags = models.JSONField(default=list, blank=True, help_text="Match when the indicator has any of these tags.")
    mitre_techniques = models.JSONField(default=list, blank=True, help_text="Match any of these ATT&CK technique IDs.")
    min_severity = models.PositiveSmallIntegerField(choices=Severity.choices, null=True, blank=True)
    min_confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    min_risk_score = models.PositiveSmallIntegerField(null=True, blank=True)
    value_pattern = models.CharField(max_length=500, blank=True, help_text="Regular expression matched against the value.")
    countries = models.JSONField(default=list, blank=True)
    alert_severity = models.PositiveSmallIntegerField(
        choices=Severity.choices, null=True, blank=True, help_text="Leave empty to inherit the indicator's severity."
    )
    hit_count = models.PositiveIntegerField(default=0, editable=False)
    last_triggered_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Alert(models.Model):
    class DetectionType(models.TextChoices):
        RULE = "rule", "Detection rule"
        IOC_MATCH = "ioc_match", "IoC match in telemetry"
        BEHAVIORAL = "behavioral", "Behavioural analytics"
        EXTERNAL = "external", "External risk"
        TELEMETRY = "telemetry", "Source-reported detection"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        RESOLVED = "resolved", "Resolved"
        DISMISSED = "dismissed", "Dismissed"

    OPEN_STATUSES = (Status.OPEN, Status.ACKNOWLEDGED)

    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    detection_type = models.CharField(max_length=15, choices=DetectionType.choices, default=DetectionType.RULE)
    indicator = models.ForeignKey(Indicator, null=True, blank=True, on_delete=models.CASCADE, related_name="alerts")
    rule = models.ForeignKey(DetectionRule, null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts")
    asset = models.ForeignKey("threats.Asset", null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts")
    event = models.ForeignKey(
        "threats.TelemetryEvent", null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts"
    )
    incident = models.ForeignKey(
        "threats.Incident", null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts"
    )
    mitre_techniques = models.JSONField(default=list, blank=True)
    dedup_key = models.CharField(max_length=300, blank=True, db_index=True, editable=False)
    severity = models.PositiveSmallIntegerField(choices=Severity.choices, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN, db_index=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_alerts"
    )
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class ImportJob(models.Model):
    class Format(models.TextChoices):
        CSV = "csv", "CSV"
        JSON = "json", "JSON"
        XML = "xml", "XML"
        STIX = "stix", "STIX 2.1 bundle"
        TEXT = "text", "Plain text (one IOC per line)"

    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        COMPLETED_WITH_ERRORS = "completed_with_errors", "Completed with errors"
        FAILED = "failed", "Failed"

    filename = models.CharField(max_length=255)
    file_format = models.CharField(max_length=10, choices=Format.choices)
    status = models.CharField(max_length=25, choices=Status.choices, default=Status.RUNNING)
    source = models.ForeignKey(Source, null=True, blank=True, on_delete=models.SET_NULL, related_name="imports")
    total_rows = models.PositiveIntegerField(default=0)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    alert_count = models.PositiveIntegerField(default=0)
    errors = models.JSONField(default=list, blank=True)
    message = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.filename} ({self.status})"


class Report(models.Model):
    class Format(models.TextChoices):
        PDF = "pdf", "PDF"
        DOCX = "docx", "Word (DOCX)"
        XLSX = "xlsx", "Excel (XLSX)"
        CSV = "csv", "CSV"
        JSON = "json", "JSON"

    name = models.CharField(max_length=150)
    file_format = models.CharField(max_length=5, choices=Format.choices, default=Format.PDF)
    parameters = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True, editable=False)
    report_file = models.FileField(upload_to="reports/%Y/%m/", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.name
