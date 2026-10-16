import django_filters
from django.db import connection
from django.db.models import Q

from .models import Alert, Asset, ExternalExposure, Incident, Indicator, ResponseAction, TelemetryEvent


def _json_list_contains(queryset, field, value):
    if connection.features.supports_json_field_contains:
        return queryset.filter(**{f"{field}__contains": [value]})
    return queryset.filter(**{f"{field}__icontains": f'"{value}"'})


class IndicatorFilter(django_filters.FilterSet):
    severity_min = django_filters.NumberFilter(field_name="severity", lookup_expr="gte")
    risk_min = django_filters.NumberFilter(field_name="risk_score", lookup_expr="gte")
    first_seen_after = django_filters.IsoDateTimeFilter(field_name="first_seen", lookup_expr="gte")
    first_seen_before = django_filters.IsoDateTimeFilter(field_name="first_seen", lookup_expr="lte")
    last_seen_after = django_filters.IsoDateTimeFilter(field_name="last_seen", lookup_expr="gte")
    tag = django_filters.CharFilter(method="filter_tag")
    technique = django_filters.CharFilter(method="filter_technique")
    actionable = django_filters.BooleanFilter(method="filter_actionable")

    class Meta:
        model = Indicator
        fields = ["ioc_type", "threat_type", "severity", "status", "tlp", "source", "country"]

    def filter_tag(self, queryset, name, value):
        return _json_list_contains(queryset, "tags", value.strip().lower())

    def filter_technique(self, queryset, name, value):
        return _json_list_contains(queryset, "mitre_techniques", value.strip().upper())

    def filter_actionable(self, queryset, name, value):
        actionable = Q(status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING])
        return queryset.filter(actionable) if value else queryset.exclude(actionable)


class AlertFilter(django_filters.FilterSet):
    severity_min = django_filters.NumberFilter(field_name="severity", lookup_expr="gte")
    created_after = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    open = django_filters.BooleanFilter(method="filter_open")

    class Meta:
        model = Alert
        fields = ["status", "severity", "rule", "indicator", "assigned_to", "detection_type", "asset", "incident"]

    def filter_open(self, queryset, name, value):
        condition = Q(status__in=Alert.OPEN_STATUSES)
        return queryset.filter(condition) if value else queryset.exclude(condition)


class IncidentFilter(django_filters.FilterSet):
    severity_min = django_filters.NumberFilter(field_name="severity", lookup_expr="gte")
    open = django_filters.BooleanFilter(method="filter_open")

    class Meta:
        model = Incident
        fields = ["status", "severity", "assigned_to"]

    def filter_open(self, queryset, name, value):
        condition = Q(status__in=Incident.OPEN_STATUSES)
        return queryset.filter(condition) if value else queryset.exclude(condition)


class AssetFilter(django_filters.FilterSet):
    shadow_it = django_filters.BooleanFilter(field_name="managed", exclude=True)
    risk_min = django_filters.NumberFilter(field_name="risk_score", lookup_expr="gte")
    seen_after = django_filters.IsoDateTimeFilter(field_name="last_seen", lookup_expr="gte")

    class Meta:
        model = Asset
        fields = ["asset_type", "department", "managed", "is_isolated", "criticality", "discovered_via",
                  "cloud_provider"]


class TelemetryEventFilter(django_filters.FilterSet):
    since = django_filters.IsoDateTimeFilter(field_name="timestamp", lookup_expr="gte")
    until = django_filters.IsoDateTimeFilter(field_name="timestamp", lookup_expr="lte")
    severity_min = django_filters.NumberFilter(field_name="severity", lookup_expr="gte")
    matched = django_filters.BooleanFilter(method="filter_matched")
    ip = django_filters.CharFilter(method="filter_ip")

    class Meta:
        model = TelemetryEvent
        fields = ["domain", "provider", "event_type", "severity", "outcome", "asset", "username", "country",
                  "connector"]

    def filter_matched(self, queryset, name, value):
        return queryset.filter(matched_indicators__isnull=not value).distinct()

    def filter_ip(self, queryset, name, value):
        return queryset.filter(Q(src_ip=value) | Q(dst_ip=value))


class ExposureFilter(django_filters.FilterSet):
    severity_min = django_filters.NumberFilter(field_name="severity", lookup_expr="gte")

    class Meta:
        model = ExternalExposure
        fields = ["kind", "status", "severity", "source"]


class ResponseActionFilter(django_filters.FilterSet):
    top_level = django_filters.BooleanFilter(field_name="parent", lookup_expr="isnull")

    class Meta:
        model = ResponseAction
        fields = ["action_type", "status", "asset", "incident", "playbook", "parent"]
