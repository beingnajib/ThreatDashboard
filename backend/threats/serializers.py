import re

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import (
    Alert,
    Asset,
    AuditLog,
    ComplianceControl,
    DataConnector,
    DetectionRule,
    ExternalExposure,
    ImportJob,
    Incident,
    Indicator,
    IOCType,
    Playbook,
    Report,
    ResponseAction,
    Source,
    TelemetryEvent,
    ThreatActor,
    ThreatFeed,
    ThreatType,
)
from .services.ioc import IOCError, normalize_mitre, normalize_tags, parse_indicator
from .services.scoring import risk_band, score_breakdown

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    groups = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")

    class Meta:
        model = User
        fields = ["id", "username", "first_name", "last_name", "email", "is_staff", "groups"]


class SourceSerializer(serializers.ModelSerializer):
    indicator_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Source
        fields = ["id", "name", "kind", "reliability", "url", "description", "created_at", "indicator_count"]


def _string_list(value, field):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise serializers.ValidationError(f"{field} must be a list of strings.")
    return value


class IndicatorSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default=None)
    risk_band = serializers.SerializerMethodField()
    ioc_type = serializers.ChoiceField(choices=IOCType.choices, required=False)
    open_alerts = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Indicator
        fields = [
            "id", "value", "ioc_type", "threat_type", "severity", "confidence", "risk_score", "risk_band", "status",
            "tlp", "source", "source_name", "tags", "mitre_techniques", "country", "cvss_score", "description",
            "enrichment", "sighting_count", "first_seen", "last_seen", "expires_at", "created_at", "updated_at",
            "open_alerts",
        ]
        read_only_fields = ["risk_score", "enrichment", "sighting_count", "created_at", "updated_at"]
        # Uniqueness is checked in validate() after the value is normalised; the
        # auto-generated UniqueTogetherValidator would wrongly require ioc_type.
        validators = []

    def get_risk_band(self, obj):
        return risk_band(obj.risk_score)

    def validate_tags(self, value):
        return normalize_tags(_string_list(value, "tags"))

    def validate_mitre_techniques(self, value):
        _string_list(value, "mitre_techniques")
        clean = normalize_mitre(value)
        invalid = [v for v in value if v.strip().upper() not in clean]
        if invalid:
            raise serializers.ValidationError(f"Invalid ATT&CK technique ID(s): {', '.join(invalid)}.")
        return clean

    def validate_country(self, value):
        if value and not re.fullmatch(r"[A-Za-z]{2}", value):
            raise serializers.ValidationError("Use an ISO 3166-1 alpha-2 country code.")
        return value.upper()

    def validate_confidence(self, value):
        if not 0 <= value <= 100:
            raise serializers.ValidationError("Confidence must be between 0 and 100.")
        return value

    def validate(self, attrs):
        instance = self.instance
        value = attrs.get("value", instance.value if instance else None)
        ioc_type = attrs.get("ioc_type", instance.ioc_type if instance else None)
        if "value" in attrs or "ioc_type" in attrs or instance is None:
            if not value:
                raise serializers.ValidationError({"value": "This field is required."})
            try:
                ioc_type, value = parse_indicator(value, ioc_type)
            except IOCError as exc:
                raise serializers.ValidationError({"value": str(exc)}) from exc
            duplicate = Indicator.objects.filter(ioc_type=ioc_type, value=value)
            if instance:
                duplicate = duplicate.exclude(pk=instance.pk)
            if duplicate.exists():
                raise serializers.ValidationError({"value": f"{ioc_type} indicator {value} already exists."})
            attrs["ioc_type"], attrs["value"] = ioc_type, value
        first_seen = attrs.get("first_seen", instance.first_seen if instance else None)
        last_seen = attrs.get("last_seen", instance.last_seen if instance else None)
        if first_seen and last_seen and last_seen < first_seen:
            raise serializers.ValidationError({"last_seen": "last_seen cannot be earlier than first_seen."})
        return attrs


class IndicatorDetailSerializer(IndicatorSerializer):
    score_breakdown = serializers.SerializerMethodField()
    actors = serializers.SerializerMethodField()

    class Meta(IndicatorSerializer.Meta):
        fields = IndicatorSerializer.Meta.fields + ["score_breakdown", "actors"]

    def get_score_breakdown(self, obj):
        return score_breakdown(obj)

    def get_actors(self, obj):
        return [{"id": a.pk, "name": a.name} for a in obj.actors.all()]


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = [
            "id", "name", "description", "enabled", "ioc_types", "threat_types", "tags", "mitre_techniques",
            "min_severity", "min_confidence", "min_risk_score", "value_pattern", "countries", "alert_severity",
            "hit_count", "last_triggered_at", "created_at", "updated_at",
        ]
        read_only_fields = ["hit_count", "last_triggered_at", "created_at", "updated_at"]

    def validate_ioc_types(self, value):
        bad = set(_string_list(value, "ioc_types")) - set(IOCType.values)
        if bad:
            raise serializers.ValidationError(f"Unknown IOC type(s): {', '.join(sorted(bad))}.")
        return value

    def validate_threat_types(self, value):
        bad = set(_string_list(value, "threat_types")) - set(ThreatType.values)
        if bad:
            raise serializers.ValidationError(f"Unknown threat type(s): {', '.join(sorted(bad))}.")
        return value

    def validate_tags(self, value):
        return normalize_tags(_string_list(value, "tags"))

    def validate_mitre_techniques(self, value):
        return normalize_mitre(_string_list(value, "mitre_techniques"))

    def validate_countries(self, value):
        return [c.upper() for c in _string_list(value, "countries") if re.fullmatch(r"[A-Za-z]{2}", c)]

    def validate_value_pattern(self, value):
        if value:
            try:
                re.compile(value)
            except re.error as exc:
                raise serializers.ValidationError(f"Invalid regular expression: {exc}") from exc
            # Guard against catastrophic backtracking from nested quantifiers.
            if re.search(r"\([^)]*[+*][^)]*\)[+*{]", value):
                raise serializers.ValidationError("Nested quantifiers are not allowed in rule patterns.")
        return value

    def validate(self, attrs):
        conditions = ("ioc_types", "threat_types", "tags", "mitre_techniques", "min_severity", "min_confidence",
                      "min_risk_score", "value_pattern", "countries")
        merged = {c: attrs.get(c, getattr(self.instance, c, None)) for c in conditions}
        if not any(v not in (None, "", []) for v in merged.values()):
            raise serializers.ValidationError("A rule needs at least one condition.")
        return attrs


class AlertSerializer(serializers.ModelSerializer):
    indicator_value = serializers.CharField(source="indicator.value", read_only=True, default=None)
    indicator_type = serializers.CharField(source="indicator.ioc_type", read_only=True, default=None)
    rule_name = serializers.CharField(source="rule.name", read_only=True, default=None)
    asset_name = serializers.SerializerMethodField()
    assigned_to_username = serializers.CharField(source="assigned_to.username", read_only=True, default=None)
    assigned_to = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), allow_null=True, required=False)

    class Meta:
        model = Alert
        fields = [
            "id", "title", "description", "detection_type", "indicator", "indicator_value", "indicator_type", "rule",
            "rule_name", "asset", "asset_name", "event", "incident", "mitre_techniques", "severity", "status",
            "assigned_to", "assigned_to_username", "notes", "created_at", "updated_at", "acknowledged_at",
            "resolved_at",
        ]
        read_only_fields = [
            "title", "description", "detection_type", "indicator", "rule", "asset", "event", "incident",
            "mitre_techniques", "created_at", "updated_at", "acknowledged_at", "resolved_at",
        ]

    def get_asset_name(self, obj):
        return str(obj.asset) if obj.asset_id else None


class AssetSerializer(serializers.ModelSerializer):
    is_shadow_it = serializers.BooleanField(read_only=True)
    max_cvss = serializers.FloatField(read_only=True)
    open_alerts = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Asset
        fields = [
            "id", "hostname", "ip_address", "mac_address", "asset_type", "operating_system", "owner", "department",
            "criticality", "managed", "is_shadow_it", "discovered_via", "cloud_provider", "cloud_resource_id",
            "software", "vulnerabilities", "max_cvss", "tags", "risk_score", "is_isolated", "isolated_at",
            "first_seen", "last_seen", "open_alerts", "created_at", "updated_at",
        ]
        read_only_fields = ["risk_score", "is_isolated", "isolated_at", "created_at", "updated_at"]

    def validate_vulnerabilities(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("vulnerabilities must be a list.")
        clean = []
        for item in value:
            if not isinstance(item, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(item.get("cve", "")).upper()):
                raise serializers.ValidationError('Each vulnerability needs {"cve": "CVE-YYYY-NNNN", "cvss": 0-10}.')
            try:
                cvss = float(item.get("cvss") or 0)
            except (TypeError, ValueError) as exc:
                raise serializers.ValidationError("cvss must be a number.") from exc
            if not 0 <= cvss <= 10:
                raise serializers.ValidationError("cvss must be between 0 and 10.")
            clean.append({"cve": str(item["cve"]).upper(), "cvss": cvss})
        return clean

    def validate_software(self, value):
        if not isinstance(value, list) or not all(isinstance(i, dict) for i in value):
            raise serializers.ValidationError('software must be a list of {"name", "version"} objects.')
        return value[:500]

    def validate_tags(self, value):
        return normalize_tags(_string_list(value, "tags"))

    def validate(self, attrs):
        hostname = attrs.get("hostname", getattr(self.instance, "hostname", ""))
        ip = attrs.get("ip_address", getattr(self.instance, "ip_address", None))
        if not hostname and not ip:
            raise serializers.ValidationError("An asset needs a hostname or an IP address.")
        if "hostname" in attrs:
            attrs["hostname"] = attrs["hostname"].lower()
        return attrs


class TelemetryEventSerializer(serializers.ModelSerializer):
    asset_name = serializers.SerializerMethodField()
    target_asset_name = serializers.SerializerMethodField()
    matched_indicators = serializers.SerializerMethodField()

    class Meta:
        model = TelemetryEvent
        fields = [
            "id", "timestamp", "domain", "provider", "event_type", "severity", "outcome", "message", "connector",
            "asset", "asset_name", "target_asset", "target_asset_name", "username", "src_ip", "dst_ip", "dst_port",
            "hostname", "domain_name", "url", "file_hash", "process", "bytes_out", "country", "mitre_technique",
            "matched_indicators", "ingested_at",
        ]

    def get_asset_name(self, obj):
        return str(obj.asset) if obj.asset_id else None

    def get_target_asset_name(self, obj):
        return str(obj.target_asset) if obj.target_asset_id else None

    def get_matched_indicators(self, obj):
        return [{"id": i.pk, "value": i.value, "severity": i.severity} for i in obj.matched_indicators.all()]


class TelemetryEventRawSerializer(TelemetryEventSerializer):
    class Meta(TelemetryEventSerializer.Meta):
        fields = TelemetryEventSerializer.Meta.fields + ["raw"]


class DataConnectorSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataConnector
        fields = ["id", "name", "provider", "domain", "enabled", "key_prefix", "events_received", "last_event_at",
                  "created_at"]
        read_only_fields = ["key_prefix", "events_received", "last_event_at", "created_at"]


class IncidentSerializer(serializers.ModelSerializer):
    assigned_to_username = serializers.CharField(source="assigned_to.username", read_only=True, default=None)
    assigned_to = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), allow_null=True, required=False)
    assets = serializers.SerializerMethodField()
    attributed_actors = serializers.SerializerMethodField()

    class Meta:
        model = Incident
        fields = [
            "id", "title", "summary", "status", "severity", "priority_score", "assigned_to", "assigned_to_username",
            "assets", "attributed_actors", "mitre_techniques", "alert_count", "first_activity", "last_activity",
            "notes", "created_at", "updated_at", "closed_at",
        ]
        read_only_fields = ["priority_score", "mitre_techniques", "alert_count", "first_activity", "last_activity",
                            "created_at", "updated_at", "closed_at"]

    def get_assets(self, obj):
        return [{"id": a.pk, "name": str(a), "criticality": a.criticality, "is_isolated": a.is_isolated,
                 "managed": a.managed} for a in obj.assets.all()]

    def get_attributed_actors(self, obj):
        return [{"id": a.pk, "name": a.name} for a in obj.attributed_actors.all()]


class ThreatActorSerializer(serializers.ModelSerializer):
    indicator_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = ThreatActor
        fields = [
            "id", "name", "aliases", "actor_type", "origin_country", "motivation", "description", "mitre_group_id",
            "mitre_techniques", "malware_families", "target_sectors", "first_observed", "last_activity", "references",
            "indicator_count", "created_at", "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]

    def validate_mitre_techniques(self, value):
        return normalize_mitre(_string_list(value, "mitre_techniques"))

    def validate_aliases(self, value):
        return _string_list(value, "aliases")

    def validate_malware_families(self, value):
        return [v.lower() for v in _string_list(value, "malware_families")]

    def validate_target_sectors(self, value):
        return _string_list(value, "target_sectors")

    def validate_references(self, value):
        # Rendered as links in the UI, so only plain web URLs are accepted
        # (blocks javascript:, data: and similar stored-XSS payloads).
        url = serializers.URLField(max_length=1000)
        clean = []
        for item in _string_list(value, "references"):
            if not item.lower().startswith(("https://", "http://")):
                raise serializers.ValidationError("References must be http(s) URLs.")
            clean.append(url.run_validation(item))
        return clean[:50]


class ExternalExposureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExternalExposure
        fields = ["id", "kind", "title", "detail", "severity", "status", "source", "data", "observed_at",
                  "created_at", "updated_at"]
        read_only_fields = ["kind", "title", "detail", "source", "data", "observed_at", "created_at", "updated_at"]


class ThreatFeedSerializer(serializers.ModelSerializer):
    auth_header = serializers.CharField(write_only=True, required=False, allow_blank=True)
    has_auth = serializers.SerializerMethodField()

    class Meta:
        model = ThreatFeed
        fields = ["id", "name", "url", "file_format", "enabled", "interval_minutes", "default_threat_type",
                  "default_severity", "auth_header", "has_auth", "last_fetched_at", "last_status", "last_import",
                  "created_at"]
        read_only_fields = ["last_fetched_at", "last_status", "last_import", "created_at"]

    def get_has_auth(self, obj):
        return bool(obj.auth_header)

    def validate_url(self, value):
        if not value.lower().startswith(("https://", "http://")):
            raise serializers.ValidationError("Feed URLs must use http or https.")
        return value

    def validate_file_format(self, value):
        if value and value not in ImportJob.Format.values:
            raise serializers.ValidationError(f"Use one of: {', '.join(ImportJob.Format.values)}.")
        return value

    def validate_interval_minutes(self, value):
        if value < 5:
            raise serializers.ValidationError("The minimum interval is 5 minutes.")
        return value

    def validate_default_threat_type(self, value):
        if value and value not in ThreatType.values:
            raise serializers.ValidationError("Unknown threat type.")
        return value


class PlaybookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Playbook
        fields = ["id", "name", "description", "steps", "target_kind", "enabled", "run_count", "created_at"]
        read_only_fields = ["run_count", "created_at"]

    def validate_steps(self, value):
        if not isinstance(value, list) or not value:
            raise serializers.ValidationError("A playbook needs at least one step.")
        for step in value:
            if not isinstance(step, dict) or step.get("action") not in ResponseAction.ActionType.values or \
                    step.get("action") in (ResponseAction.ActionType.RUN_PLAYBOOK,
                                           ResponseAction.ActionType.TERMINAL_COMMAND):
                raise serializers.ValidationError(
                    "Each step needs a valid 'action' (playbooks cannot nest playbooks or run terminal commands).")
        return value

    def validate_target_kind(self, value):
        if value not in ("asset", "user", "indicator", "global"):
            raise serializers.ValidationError("target_kind must be asset, user, indicator or global.")
        return value


class ResponseActionSerializer(serializers.ModelSerializer):
    asset_name = serializers.SerializerMethodField()
    playbook_name = serializers.CharField(source="playbook.name", read_only=True, default=None)
    requested_by_username = serializers.CharField(source="requested_by.username", read_only=True, default=None)
    indicator_value = serializers.CharField(source="indicator.value", read_only=True, default=None)

    class Meta:
        model = ResponseAction
        fields = ["id", "action_type", "status", "asset", "asset_name", "incident", "indicator", "indicator_value",
                  "playbook", "playbook_name", "parent", "target_user", "parameters", "connector", "output", "error",
                  "requested_by", "requested_by_username", "created_at", "completed_at"]
        read_only_fields = fields

    def get_asset_name(self, obj):
        return str(obj.asset) if obj.asset_id else None


class ResponseRequestSerializer(serializers.Serializer):
    action_type = serializers.ChoiceField(choices=[c for c in ResponseAction.ActionType.choices
                                                   if c[0] not in ("run_playbook", "terminal_command")])
    asset = serializers.PrimaryKeyRelatedField(queryset=Asset.objects.all(), required=False, allow_null=True)
    indicator = serializers.PrimaryKeyRelatedField(queryset=Indicator.objects.all(), required=False, allow_null=True)
    incident = serializers.PrimaryKeyRelatedField(queryset=Incident.objects.all(), required=False, allow_null=True)
    target_user = serializers.CharField(required=False, allow_blank=True, max_length=255)
    parameters = serializers.DictField(required=False)


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ["id", "actor", "actor_name", "action", "target", "detail", "ip_address", "created_at"]
        read_only_fields = fields


class ComplianceControlSerializer(serializers.ModelSerializer):
    framework_label = serializers.CharField(source="get_framework_display", read_only=True)

    class Meta:
        model = ComplianceControl
        fields = ["id", "framework", "framework_label", "control_id", "title", "description", "check_key", "status",
                  "score", "evidence", "manual_override", "last_evaluated"]
        read_only_fields = ["framework", "control_id", "title", "check_key", "last_evaluated"]

    def validate(self, attrs):
        if "status" in attrs and self.instance and self.instance.check_key and not attrs.get(
                "manual_override", self.instance.manual_override):
            raise serializers.ValidationError("Set manual_override to change the status of an automated control.")
        if "score" in attrs and not 0 <= attrs["score"] <= 100:
            raise serializers.ValidationError({"score": "Score must be 0-100."})
        return attrs


class ImportJobSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default=None)

    class Meta:
        model = ImportJob
        fields = [
            "id", "filename", "file_format", "status", "source", "source_name", "total_rows", "created_count",
            "updated_count", "error_count", "alert_count", "errors", "message", "created_at", "finished_at",
        ]
        read_only_fields = fields


class ImportUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    file_format = serializers.ChoiceField(choices=ImportJob.Format.choices, required=False, allow_blank=True)
    source_name = serializers.CharField(max_length=120, required=False, allow_blank=True)
    source_reliability = serializers.ChoiceField(choices=Source.Reliability.choices, required=False)


class ReportSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    date_from = serializers.DateField(write_only=True, required=False, allow_null=True)
    date_to = serializers.DateField(write_only=True, required=False, allow_null=True)
    min_severity = serializers.IntegerField(write_only=True, required=False, min_value=1, max_value=4)
    threat_types = serializers.ListField(
        child=serializers.ChoiceField(choices=ThreatType.choices), write_only=True, required=False
    )

    class Meta:
        model = Report
        fields = [
            "id", "name", "file_format", "parameters", "summary", "download_url", "created_at",
            "date_from", "date_to", "min_severity", "threat_types",
        ]
        read_only_fields = ["parameters", "summary", "created_at"]

    def get_download_url(self, obj):
        if not obj.report_file:
            return None
        return f"/api/reports/{obj.pk}/download/"

    def validate(self, attrs):
        if attrs.get("date_from") and attrs.get("date_to") and attrs["date_from"] > attrs["date_to"]:
            raise serializers.ValidationError({"date_to": "End date must be on or after the start date."})
        return attrs

    def create(self, validated_data):
        parameters = {
            "date_from": validated_data.pop("date_from", None),
            "date_to": validated_data.pop("date_to", None),
            "min_severity": validated_data.pop("min_severity", 1),
            "threat_types": validated_data.pop("threat_types", []),
        }
        parameters = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in parameters.items()}
        return Report.objects.create(parameters=parameters, **validated_data)
