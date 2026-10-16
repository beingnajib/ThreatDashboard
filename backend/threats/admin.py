from django.contrib import admin

from . import models


@admin.register(models.Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ["name", "kind", "reliability", "created_at"]
    list_filter = ["kind", "reliability"]
    search_fields = ["name"]


@admin.register(models.Indicator)
class IndicatorAdmin(admin.ModelAdmin):
    list_display = ["value", "ioc_type", "threat_type", "severity", "risk_score", "status", "source", "last_seen"]
    list_filter = ["ioc_type", "threat_type", "severity", "status", "tlp", "source"]
    search_fields = ["value", "description"]
    readonly_fields = ["risk_score", "enrichment", "created_at", "updated_at"]
    date_hierarchy = "first_seen"


@admin.register(models.DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ["name", "enabled", "min_severity", "hit_count", "last_triggered_at"]
    list_filter = ["enabled"]
    search_fields = ["name"]


@admin.register(models.Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ["title", "severity", "status", "detection_type", "incident", "assigned_to", "created_at"]
    list_filter = ["status", "severity", "detection_type"]
    search_fields = ["title", "indicator__value"]
    raw_id_fields = ["indicator", "asset", "event", "incident"]


@admin.register(models.Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ["title", "severity", "status", "priority_score", "alert_count", "last_activity"]
    list_filter = ["status", "severity"]
    search_fields = ["title"]
    filter_horizontal = ["assets", "attributed_actors"]


@admin.register(models.Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ["hostname", "ip_address", "asset_type", "department", "managed", "is_isolated", "risk_score",
                    "last_seen"]
    list_filter = ["asset_type", "managed", "is_isolated", "department", "discovered_via"]
    search_fields = ["hostname", "ip_address", "owner"]


@admin.register(models.TelemetryEvent)
class TelemetryEventAdmin(admin.ModelAdmin):
    list_display = ["timestamp", "domain", "provider", "event_type", "severity", "username", "src_ip"]
    list_filter = ["domain", "provider", "severity", "outcome"]
    search_fields = ["event_type", "username", "message"]
    raw_id_fields = ["asset", "target_asset", "connector"]
    filter_horizontal = ["matched_indicators"]


@admin.register(models.DataConnector)
class DataConnectorAdmin(admin.ModelAdmin):
    list_display = ["name", "provider", "domain", "enabled", "key_prefix", "events_received", "last_event_at"]
    readonly_fields = ["key_prefix", "key_hash", "events_received", "last_event_at"]


@admin.register(models.ThreatActor)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display = ["name", "actor_type", "origin_country", "mitre_group_id", "last_activity"]
    list_filter = ["actor_type"]
    search_fields = ["name", "aliases"]
    filter_horizontal = ["indicators"]


@admin.register(models.ExternalExposure)
class ExternalExposureAdmin(admin.ModelAdmin):
    list_display = ["title", "kind", "severity", "status", "observed_at"]
    list_filter = ["kind", "severity", "status"]
    search_fields = ["title"]


@admin.register(models.ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    list_display = ["name", "enabled", "interval_minutes", "last_fetched_at", "last_status"]
    list_filter = ["enabled"]


@admin.register(models.Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ["name", "target_kind", "enabled", "run_count"]


@admin.register(models.ResponseAction)
class ResponseActionAdmin(admin.ModelAdmin):
    list_display = ["action_type", "status", "asset", "target_user", "requested_by", "created_at"]
    list_filter = ["action_type", "status"]
    readonly_fields = [f.name for f in models.ResponseAction._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(models.AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ["created_at", "actor_name", "action", "target", "ip_address"]
    list_filter = ["action"]
    search_fields = ["actor_name", "target"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(models.ComplianceControl)
class ComplianceControlAdmin(admin.ModelAdmin):
    list_display = ["framework", "control_id", "title", "status", "score", "last_evaluated"]
    list_filter = ["framework", "status"]


@admin.register(models.ImportJob)
class ImportJobAdmin(admin.ModelAdmin):
    list_display = ["filename", "file_format", "status", "created_count", "updated_count", "error_count",
                    "created_at"]
    list_filter = ["status", "file_format"]
    readonly_fields = [f.name for f in models.ImportJob._meta.fields]


@admin.register(models.Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["name", "file_format", "created_by", "created_at"]
    list_filter = ["file_format"]
