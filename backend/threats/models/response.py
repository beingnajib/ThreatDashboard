from django.conf import settings
from django.db import models

from .telemetry import Asset


class Playbook(models.Model):
    """A SOAR playbook: an ordered list of response steps."""

    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    steps = models.JSONField(default=list, help_text='[{"action": "isolate_host", "parameters": {}}]')
    target_kind = models.CharField(
        max_length=10, default="asset", help_text="What the playbook runs against: asset, user, indicator or global."
    )
    enabled = models.BooleanField(default=True)
    run_count = models.PositiveIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class ResponseAction(models.Model):
    """A containment/remediation action and its outcome, executed via the response connector."""

    class ActionType(models.TextChoices):
        ISOLATE_HOST = "isolate_host", "Isolate host"
        RELEASE_HOST = "release_host", "Release host from isolation"
        COLLECT_FORENSICS = "collect_forensics", "Collect forensic package"
        KILL_PROCESS = "kill_process", "Kill process"
        BLOCK_INDICATOR = "block_indicator", "Block indicator"
        DISABLE_USER = "disable_user", "Disable user account"
        RESET_PASSWORD = "reset_password", "Force password reset"
        REVOKE_SESSIONS = "revoke_sessions", "Revoke sessions / tokens"
        RUN_PLAYBOOK = "run_playbook", "Run playbook"
        TERMINAL_COMMAND = "terminal_command", "Live response command"
        NOTIFY = "notify", "Notify"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    action_type = models.CharField(max_length=20, choices=ActionType.choices, db_index=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING, db_index=True)
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL, related_name="response_actions")
    incident = models.ForeignKey(
        "threats.Incident", null=True, blank=True, on_delete=models.SET_NULL, related_name="response_actions"
    )
    indicator = models.ForeignKey(
        "threats.Indicator", null=True, blank=True, on_delete=models.SET_NULL, related_name="response_actions"
    )
    playbook = models.ForeignKey(Playbook, null=True, blank=True, on_delete=models.SET_NULL, related_name="runs")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE, related_name="steps")
    target_user = models.CharField(max_length=255, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    connector = models.CharField(max_length=30, blank=True)
    output = models.TextField(blank=True)
    error = models.TextField(blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_action_type_display()} ({self.status})"


class AuditLog(models.Model):
    """Append-only record of security-relevant activity in the platform."""

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    actor_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=60, db_index=True)
    target = models.CharField(max_length=300, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.actor_name} {self.action} {self.target}"


class ComplianceControl(models.Model):
    """A framework control mapped to an automated platform check (or tracked manually)."""

    class Framework(models.TextChoices):
        NIST_CSF = "nist_csf", "NIST CSF 2.0"
        ISO_27001 = "iso27001", "ISO/IEC 27001:2022"
        SOC2 = "soc2", "SOC 2 (TSC 2017)"
        GDPR = "gdpr", "GDPR"

    class Status(models.TextChoices):
        PASS = "pass", "Pass"
        PARTIAL = "partial", "Partial"
        FAIL = "fail", "Fail"
        MANUAL = "manual", "Manual review"
        NOT_APPLICABLE = "not_applicable", "Not applicable"

    framework = models.CharField(max_length=10, choices=Framework.choices, db_index=True)
    control_id = models.CharField(max_length=30)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    check_key = models.CharField(max_length=40, blank=True, help_text="Automated check key; blank = manual control.")
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.MANUAL)
    score = models.PositiveSmallIntegerField(default=0, help_text="0-100 readiness for this control.")
    evidence = models.TextField(blank=True)
    manual_override = models.BooleanField(default=False, help_text="Keep the analyst-set status instead of the check.")
    last_evaluated = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["framework", "control_id"]
        constraints = [models.UniqueConstraint(fields=["framework", "control_id"], name="unique_framework_control")]

    def __str__(self):
        return f"{self.get_framework_display()} {self.control_id}"
