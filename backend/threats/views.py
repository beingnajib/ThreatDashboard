import json
import logging
import os
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Count, Prefetch, Q
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import mixins, parsers, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action, api_view, permission_classes, throttle_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from . import filters, serializers
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
)
from .permissions import (
    CanRespond,
    CanUseTerminal,
    ConnectorKeyAuthentication,
    IngestRateThrottle,
    IsAuthenticatedOrConnector,
    IsAuthenticatedStaffDelete,
    IsStaff,
    IsStaffOrReadOnly,
    token_expired,
)
from .services import analytics, attribution, compliance, executive, exports, exposure, feeds, incidents, nlq
from .services import reports as report_service
from .services import response as response_service
from .services import rules as rule_service
from .services import telemetry
from .services.assets import asset_risk_breakdown, refresh_asset_risk
from .services.audit import audit, client_ip
from .services.correlation import related_indicators
from .services.importers import RecordError, run_import
from .services.ioc import IOCError, parse_indicator

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Health and authentication
# --------------------------------------------------------------------------- #

@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([])
def health(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        database = "ok"
    except Exception:  # noqa: BLE001 - report, don't raise
        database = "unavailable"
    healthy = database == "ok"
    return Response({"status": "ok" if healthy else "degraded", "database": database,
                     "time": timezone.now().isoformat()},
                    status=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE)


class LoginView(ObtainAuthToken):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        if not serializer.is_valid():
            AuditLog.objects.create(actor_name=str(request.data.get("username", ""))[:150], action="auth.login_failed",
                                    ip_address=client_ip(request))
            raise ValidationError(serializer.errors)
        user = serializer.validated_data["user"]
        token, _ = Token.objects.get_or_create(user=user)
        if token_expired(token):
            token.delete()
            token = Token.objects.create(user=user)
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])
        audit(user, "auth.login")
        return Response({"token": token.key, "user": serializers.UserSerializer(user).data})


@api_view(["GET"])
def me(request):
    return Response(serializers.UserSerializer(request.user).data)


@api_view(["POST"])
def logout(request):
    Token.objects.filter(user=request.user).delete()
    audit(request, "auth.logout")
    return Response(status=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# Threat intelligence
# --------------------------------------------------------------------------- #

class SourceViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.SourceSerializer
    permission_classes = [IsAuthenticatedStaffDelete]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at", "indicator_count"]

    def get_queryset(self):
        return Source.objects.annotate(indicator_count=Count("indicators"))


class IndicatorViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticatedStaffDelete]
    filterset_class = filters.IndicatorFilter
    search_fields = ["value", "description", "source__name"]
    ordering_fields = ["risk_score", "severity", "confidence", "first_seen", "last_seen", "sighting_count", "value"]

    def get_queryset(self):
        return Indicator.objects.select_related("source").annotate(
            open_alerts=Count("alerts", filter=Q(alerts__status__in=Alert.OPEN_STATUSES))
        )

    def get_serializer_class(self):
        if self.action == "retrieve":
            return serializers.IndicatorDetailSerializer
        return serializers.IndicatorSerializer

    def perform_create(self, serializer):
        indicator = serializer.save(created_by=self.request.user)
        rule_service.evaluate_indicators([indicator])

    def perform_update(self, serializer):
        indicator = serializer.save()
        rule_service.evaluate_indicators([indicator])

    def perform_destroy(self, instance):
        audit(self.request, "indicator.delete", target=instance)
        instance.delete()

    @action(detail=True, methods=["get"])
    def related(self, request, pk=None):
        indicator = self.get_object()
        results = [
            {**serializers.IndicatorSerializer(other, context={"request": request}).data, "reasons": reasons}
            for other, reasons in related_indicators(indicator)
        ]
        return Response({"count": len(results), "results": results})

    @action(detail=True, methods=["get"])
    def attribution(self, request, pk=None):
        return Response({"results": attribution.attribute_indicator(self.get_object())})

    @action(detail=True, methods=["get"])
    def sightings(self, request, pk=None):
        events = self.get_object().sightings.select_related("asset", "target_asset").prefetch_related(
            "matched_indicators").order_by("-timestamp")[:100]
        return Response(serializers.TelemetryEventSerializer(events, many=True).data)

    @action(detail=False, methods=["get"])
    def export(self, request):
        fmt = request.query_params.get("export_format", "csv").lower()
        queryset = self.filter_queryset(self.get_queryset())[:50000]
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        if fmt == "csv":
            body, content_type, ext = exports.to_csv(queryset), "text/csv", "csv"
        elif fmt == "json":
            body, content_type, ext = exports.to_json(queryset), "application/json", "json"
        elif fmt == "stix":
            body, content_type, ext = exports.to_stix(queryset), "application/stix+json;version=2.1", "stix.json"
        else:
            raise ValidationError({"export_format": "Use csv, json or stix."})
        audit(request, "indicator.export", target=fmt, count=len(queryset))
        response = HttpResponse(body, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="indicators-{stamp}.{ext}"'
        return response

    @action(detail=False, methods=["get"], authentication_classes=[ConnectorKeyAuthentication] + [
        cls for cls in viewsets.ModelViewSet.authentication_classes], permission_classes=[IsAuthenticatedOrConnector])
    def blocklist(self, request):
        """Plain-text blocklist (one value per line) for firewalls, proxies and DNS sinkholes (EDL format)."""
        kind = request.query_params.get("type", "ipv4")
        types = {"ip": [IOCType.IPV4, IOCType.IPV6], "ipv4": [IOCType.IPV4], "ipv6": [IOCType.IPV6],
                 "domain": [IOCType.DOMAIN], "url": [IOCType.URL],
                 "hash": [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]}.get(kind)
        if types is None:
            raise ValidationError({"type": "Use ip, ipv4, ipv6, domain, url or hash."})
        try:
            min_risk = int(request.query_params.get("min_risk", 60))
        except ValueError as exc:
            raise ValidationError({"min_risk": "Must be an integer."}) from exc
        values = Indicator.objects.filter(
            ioc_type__in=types, status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING]
        ).filter(Q(risk_score__gte=min_risk) | Q(tags__icontains='"blocked"')).order_by("-risk_score").values_list(
            "value", flat=True)[:150000]
        if kind == "url":
            values = [v.split("://", 1)[-1] for v in values]  # EDL URL lists omit the scheme
        body = f"# ThreatDashboard {kind} blocklist generated {timezone.now().isoformat()}\n" + "\n".join(values) + "\n"
        return HttpResponse(body, content_type="text/plain; charset=utf-8")

    @action(detail=False, methods=["post"])
    def lookup(self, request):
        """Check a batch of observables (defanged values welcome) against the intelligence database."""
        raw_values = request.data.get("values")
        if isinstance(raw_values, str):
            raw_values = raw_values.split()
        if not isinstance(raw_values, list) or not raw_values:
            raise ValidationError({"values": "Provide a list (or whitespace-separated string) of values."})
        if len(raw_values) > 1000:
            raise ValidationError({"values": "At most 1000 values per lookup."})
        parsed, results = {}, []
        for raw in raw_values:
            try:
                parsed[str(raw)] = parse_indicator(str(raw))
            except IOCError as exc:
                results.append({"input": raw, "valid": False, "error": str(exc), "match": None})
        lookups = Q()
        for ioc_type, value in parsed.values():
            lookups |= Q(ioc_type=ioc_type, value=value)
        found = {}
        if parsed:
            for indicator in Indicator.objects.select_related("source").filter(lookups):
                found[(indicator.ioc_type, indicator.value)] = indicator
        for raw, key in parsed.items():
            match = found.get(key)
            results.append({
                "input": raw, "valid": True, "ioc_type": key[0], "value": key[1],
                "match": serializers.IndicatorSerializer(match, context={"request": request}).data if match else None,
            })
        return Response({"count": len(results), "matches": sum(1 for r in results if r.get("match")),
                         "results": results})

    @action(detail=False, methods=["post"])
    def bulk_status(self, request):
        ids = request.data.get("ids")
        new_status = request.data.get("status")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids):
            raise ValidationError({"ids": "Provide a non-empty list of indicator IDs."})
        if new_status not in Indicator.Status.values:
            raise ValidationError({"status": f"Use one of: {', '.join(Indicator.Status.values)}."})
        updated = 0
        with transaction.atomic():
            for indicator in Indicator.objects.select_related("source").filter(pk__in=ids[:1000]):
                indicator.status = new_status
                indicator.save(update_fields=["status"])
                updated += 1
        audit(request, "indicator.bulk_status", target=new_status, count=updated)
        return Response({"updated": updated})


class DetectionRuleViewSet(viewsets.ModelViewSet):
    queryset = DetectionRule.objects.all()
    serializer_class = serializers.DetectionRuleSerializer
    permission_classes = [IsAuthenticatedStaffDelete]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "hit_count", "last_triggered_at", "created_at"]
    filterset_fields = ["enabled"]

    def perform_create(self, serializer):
        rule = serializer.save(created_by=self.request.user)
        audit(self.request, "rule.create", target=rule)

    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        rule = self.get_object()
        if not rule.enabled:
            raise ValidationError("Enable the rule before running it.")
        alerts = rule_service.run_rule(rule)
        return Response({"alerts_created": len(alerts)})

    @action(detail=False, methods=["post"])
    def test(self, request):
        serializer = self.get_serializer(data={**request.data, "name": request.data.get("name") or "dry-run"})
        serializer.is_valid(raise_exception=True)
        rule = DetectionRule(**serializer.validated_data)
        return Response({"matches": rule_service.count_matches(rule)})


class AlertViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    serializer_class = serializers.AlertSerializer
    filterset_class = filters.AlertFilter
    search_fields = ["title", "description", "indicator__value", "notes", "asset__hostname"]
    ordering_fields = ["created_at", "severity", "status"]

    def get_queryset(self):
        return Alert.objects.select_related("indicator", "rule", "assigned_to", "asset")

    def _transition(self, request, new_status):
        alert = self.get_object()
        now = timezone.now()
        alert.status = new_status
        if new_status == Alert.Status.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = now
            alert.assigned_to = alert.assigned_to or request.user
        if new_status in (Alert.Status.RESOLVED, Alert.Status.DISMISSED):
            alert.resolved_at = now
            alert.acknowledged_at = alert.acknowledged_at or now
        if new_status == Alert.Status.OPEN:
            alert.resolved_at = None
        notes = request.data.get("notes")
        if notes:
            alert.notes = (alert.notes + "\n" if alert.notes else "") + str(notes)[:2000]
        alert.save()
        if alert.incident_id:
            incidents.recompute_incident(alert.incident)
        audit(request, f"alert.{new_status}", target=alert)
        return Response(self.get_serializer(alert).data)

    def perform_update(self, serializer):
        alert = serializer.save()
        if alert.status in (Alert.Status.RESOLVED, Alert.Status.DISMISSED) and not alert.resolved_at:
            alert.resolved_at = timezone.now()
            alert.save(update_fields=["resolved_at"])
        elif alert.status in Alert.OPEN_STATUSES and alert.resolved_at:
            alert.resolved_at = None
            alert.save(update_fields=["resolved_at"])
        if alert.status == Alert.Status.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = timezone.now()
            alert.save(update_fields=["acknowledged_at"])

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        return self._transition(request, Alert.Status.ACKNOWLEDGED)

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        return self._transition(request, Alert.Status.RESOLVED)

    @action(detail=True, methods=["post"])
    def dismiss(self, request, pk=None):
        return self._transition(request, Alert.Status.DISMISSED)

    @action(detail=True, methods=["post"])
    def reopen(self, request, pk=None):
        return self._transition(request, Alert.Status.OPEN)


class ImportJobViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = ImportJob.objects.select_related("source")
    serializer_class = serializers.ImportJobSerializer
    parser_classes = [parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser]
    filterset_fields = ["status", "file_format"]
    ordering_fields = ["created_at"]

    def create(self, request):
        upload = serializers.ImportUploadSerializer(data=request.data)
        upload.is_valid(raise_exception=True)
        uploaded = upload.validated_data["file"]
        if uploaded.size > settings.THREATDASH_MAX_IMPORT_BYTES:
            raise ValidationError({"file": f"Files are limited to {settings.THREATDASH_MAX_IMPORT_BYTES // 1048576} MB."})
        source_name = (upload.validated_data.get("source_name") or "").strip()
        source = None
        if source_name:
            source, _ = Source.objects.get_or_create(
                name=source_name,
                defaults={"kind": Source.Kind.IMPORT,
                          "reliability": upload.validated_data.get("source_reliability") or Source.Reliability.F},
            )
        job = ImportJob.objects.create(
            filename=os.path.basename(uploaded.name)[:255],
            file_format=upload.validated_data.get("file_format") or "",
            source=source, created_by=request.user,
        )
        try:
            run_import(job, uploaded.read(), source=source, user=request.user)
        except Exception:
            logger.exception("Import %s crashed", job.pk)
            job.status, job.message, job.finished_at = ImportJob.Status.FAILED, "Unexpected error while importing.", \
                timezone.now()
            job.save()
        audit(request, "import.run", target=job.filename, job=job.pk, status=job.status)
        code = status.HTTP_201_CREATED if job.status != ImportJob.Status.FAILED else status.HTTP_400_BAD_REQUEST
        return Response(self.get_serializer(job).data, status=code)


class ReportViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin,
                    mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Report.objects.all()
    serializer_class = serializers.ReportSerializer
    permission_classes = [IsAuthenticatedStaffDelete]
    filterset_fields = ["file_format"]
    search_fields = ["name"]
    ordering_fields = ["created_at", "name"]

    def perform_create(self, serializer):
        report = serializer.save(created_by=self.request.user)
        try:
            report_service.generate_report(report)
        except ValueError as exc:
            report.delete()
            raise ValidationError(str(exc)) from exc
        except Exception:
            logger.exception("Report %s failed", report.pk)
            report.delete()
            raise
        audit(self.request, "report.generate", target=report, format=report.file_format)

    def perform_destroy(self, instance):
        if instance.report_file:
            instance.report_file.delete(save=False)
        instance.delete()

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        report = self.get_object()
        if not report.report_file:
            raise ValidationError("This report has no file.")
        try:
            handle = report.report_file.open("rb")
        except FileNotFoundError as exc:
            raise ValidationError("The report file is missing; regenerate the report.") from exc
        return FileResponse(handle, as_attachment=True, filename=os.path.basename(report.report_file.name),
                            content_type=report_service.CONTENT_TYPES.get(report.file_format))


# --------------------------------------------------------------------------- #
# Telemetry, assets and incidents
# --------------------------------------------------------------------------- #

class DataConnectorViewSet(viewsets.ModelViewSet):
    queryset = DataConnector.objects.all()
    serializer_class = serializers.DataConnectorSerializer
    permission_classes = [IsStaffOrReadOnly]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        connector = DataConnector(**serializer.validated_data, created_by=request.user)
        key = connector.rotate_key()
        connector.save()
        audit(request, "connector.create", target=connector)
        return Response({**self.get_serializer(connector).data, "ingest_key": key}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def rotate_key(self, request, pk=None):
        connector = self.get_object()
        key = connector.rotate_key()
        connector.save(update_fields=["key_prefix", "key_hash"])
        audit(request, "connector.rotate_key", target=connector)
        return Response({**self.get_serializer(connector).data, "ingest_key": key})


class TelemetryEventViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    filterset_class = filters.TelemetryEventFilter
    search_fields = ["message", "event_type", "username", "hostname", "domain_name", "url", "process"]
    ordering_fields = ["timestamp", "severity"]

    def get_queryset(self):
        return TelemetryEvent.objects.select_related("asset", "target_asset").prefetch_related(
            Prefetch("matched_indicators", queryset=Indicator.objects.only("id", "value", "severity")))

    def get_serializer_class(self):
        return serializers.TelemetryEventRawSerializer if self.action == "retrieve" else \
            serializers.TelemetryEventSerializer

    @action(detail=False, methods=["post"], authentication_classes=[ConnectorKeyAuthentication] + [
        cls for cls in viewsets.GenericViewSet.authentication_classes], permission_classes=[IsAuthenticatedOrConnector],
        throttle_classes=[IngestRateThrottle])
    def ingest(self, request):
        """Push events. Log shippers authenticate with their connector's ``X-Ingest-Key``."""
        connector = request.auth if isinstance(request.auth, DataConnector) else None
        provider = connector.provider if connector else request.query_params.get("provider", "generic")
        if provider not in DataConnector.Provider.values:
            raise ValidationError({"provider": f"Use one of: {', '.join(DataConnector.Provider.values)}."})
        if provider == DataConnector.Provider.DARK_WEB:
            records = telemetry.unwrap_records(request.data)
            return Response(exposure.ingest_dark_web(records, source=connector.name if connector else "api"))
        try:
            result = telemetry.ingest_events(request.data, provider=provider, connector=connector,
                                             default_domain=request.query_params.get("domain"))
        except RecordError as exc:
            raise ValidationError(str(exc)) from exc
        code = status.HTTP_202_ACCEPTED if result["ingested"] else status.HTTP_400_BAD_REQUEST
        return Response(result, status=code)

    @action(detail=False, methods=["get"])
    def stats(self, request):
        since = timezone.now() - timedelta(hours=24)
        recent = TelemetryEvent.objects.filter(timestamp__gte=since)
        return Response({
            "last_24h": recent.count(),
            "by_domain": list(recent.values("domain").annotate(count=Count("id")).order_by("-count")),
            "by_provider": list(recent.values("provider").annotate(count=Count("id")).order_by("-count")[:10]),
            "matched_last_24h": recent.filter(matched_indicators__isnull=False).distinct().count(),
            "connectors": serializers.DataConnectorSerializer(DataConnector.objects.all(), many=True).data,
        })


class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.AssetSerializer
    permission_classes = [IsAuthenticatedStaffDelete]
    filterset_class = filters.AssetFilter
    search_fields = ["hostname", "ip_address", "owner", "operating_system", "mac_address", "cloud_resource_id"]
    ordering_fields = ["risk_score", "hostname", "last_seen", "criticality", "first_seen"]

    def get_queryset(self):
        return Asset.objects.annotate(
            open_alerts=Count("alerts", filter=Q(alerts__status__in=Alert.OPEN_STATUSES), distinct=True))

    def perform_create(self, serializer):
        asset = serializer.save(discovered_via=serializer.validated_data.get("discovered_via") or
                                Asset.DiscoveryMethod.MANUAL)
        refresh_asset_risk(Asset.objects.filter(pk=asset.pk))

    def perform_update(self, serializer):
        asset = serializer.save()
        refresh_asset_risk(Asset.objects.filter(pk=asset.pk))

    @action(detail=True, methods=["get"])
    def risk(self, request, pk=None):
        return Response(asset_risk_breakdown(self.get_object()))

    @action(detail=True, methods=["get"])
    def timeline(self, request, pk=None):
        asset = self.get_object()
        events = TelemetryEvent.objects.filter(Q(asset=asset) | Q(target_asset=asset)).select_related(
            "asset", "target_asset").prefetch_related("matched_indicators").order_by("-timestamp")[:200]
        return Response(serializers.TelemetryEventSerializer(events, many=True).data)

    @action(detail=False, methods=["get"])
    def discovery(self, request):
        """Inventory overview: managed vs. shadow IT, newly discovered devices, coverage by type."""
        now = timezone.now()
        queryset = Asset.objects.all()
        return Response({
            "total": queryset.count(),
            "managed": queryset.filter(managed=True).count(),
            "shadow_it": queryset.filter(managed=False).count(),
            "isolated": queryset.filter(is_isolated=True).count(),
            "active_24h": queryset.filter(last_seen__gte=now - timedelta(hours=24)).count(),
            "new_7d": queryset.filter(first_seen__gte=now - timedelta(days=7)).count(),
            "by_type": list(queryset.values("asset_type").annotate(
                count=Count("id"), unmanaged=Count("id", filter=Q(managed=False))).order_by("-count")),
            "by_discovery": list(queryset.values("discovered_via").annotate(count=Count("id")).order_by("-count")),
            "recent_shadow_it": serializers.AssetSerializer(
                queryset.filter(managed=False).order_by("-first_seen")[:10], many=True).data,
        })


class IncidentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin,
                      viewsets.GenericViewSet):
    serializer_class = serializers.IncidentSerializer
    filterset_class = filters.IncidentFilter
    search_fields = ["title", "summary", "notes"]
    ordering_fields = ["priority_score", "last_activity", "created_at", "severity", "alert_count"]

    def get_queryset(self):
        return Incident.objects.select_related("assigned_to").prefetch_related("assets", "attributed_actors")

    def perform_update(self, serializer):
        previous = serializer.instance.status
        incident = serializer.save()
        if incident.status == Incident.Status.CLOSED and previous != Incident.Status.CLOSED:
            incident.closed_at = timezone.now()
            incident.save(update_fields=["closed_at"])
            now = timezone.now()
            incident.alerts.filter(status__in=Alert.OPEN_STATUSES).update(
                status=Alert.Status.RESOLVED, resolved_at=now)
        elif incident.status != Incident.Status.CLOSED and incident.closed_at:
            incident.closed_at = None
            incident.save(update_fields=["closed_at"])
        if previous != incident.status:
            audit(self.request, "incident.status", target=incident, previous=previous, status=incident.status)

    @action(detail=True, methods=["get"])
    def alerts(self, request, pk=None):
        alerts = self.get_object().alerts.select_related("indicator", "rule", "asset", "assigned_to").order_by(
            "created_at")
        return Response(serializers.AlertSerializer(alerts, many=True).data)

    @action(detail=True, methods=["get"], url_path="attack-path")
    def attack_path(self, request, pk=None):
        return Response(incidents.attack_path(self.get_object()))

    @action(detail=True, methods=["get", "post"])
    def attribution(self, request, pk=None):
        incident = self.get_object()
        results = attribution.attribute_incident(incident)
        if request.method == "POST":
            threshold = int(request.data.get("min_confidence", 50))
            chosen = [r["actor_id"] for r in results if r["confidence"] >= threshold]
            incident.attributed_actors.set(chosen)
            incidents.recompute_incident(incident)
            audit(request, "incident.attribute", target=incident, actors=chosen)
        return Response({"results": results})

    @action(detail=True, methods=["get"])
    def actions(self, request, pk=None):
        actions = self.get_object().response_actions.select_related("asset", "playbook", "requested_by",
                                                                     "indicator").order_by("-created_at")
        return Response(serializers.ResponseActionSerializer(actions, many=True).data)


class ThreatActorViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ThreatActorSerializer
    permission_classes = [IsAuthenticatedStaffDelete]
    filterset_fields = ["actor_type", "origin_country"]
    search_fields = ["name", "description", "mitre_group_id"]
    ordering_fields = ["name", "last_activity", "indicator_count"]

    def get_queryset(self):
        return ThreatActor.objects.annotate(indicator_count=Count("indicators"))

    @action(detail=True, methods=["get", "post"])
    def indicators(self, request, pk=None):
        actor = self.get_object()
        if request.method == "POST":
            ids = request.data.get("indicator_ids")
            if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
                raise ValidationError({"indicator_ids": "Provide a list of indicator IDs."})
            actor.indicators.add(*Indicator.objects.filter(pk__in=ids))
        queryset = actor.indicators.select_related("source")[:500]
        return Response(serializers.IndicatorSerializer(queryset, many=True).data)


class ExternalExposureViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin,
                              viewsets.GenericViewSet):
    queryset = ExternalExposure.objects.all()
    serializer_class = serializers.ExternalExposureSerializer
    filterset_class = filters.ExposureFilter
    search_fields = ["title", "detail", "source"]
    ordering_fields = ["observed_at", "severity", "created_at"]

    @action(detail=False, methods=["get"], url_path="typosquat-candidates")
    def typosquat_candidates(self, request):
        domain = request.query_params.get("domain") or (settings.THREATDASH_ORG_DOMAINS or [""])[0]
        candidates = exposure.typosquat_candidates(domain)
        return Response({"domain": domain, "count": len(candidates), "results": candidates})

    @action(detail=False, methods=["post"], url_path="scan-typosquats")
    def scan_typosquats(self, request):
        domains = request.data.get("domains") or settings.THREATDASH_ORG_DOMAINS
        if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains) or len(domains) > 10:
            raise ValidationError({"domains": "Provide up to 10 domains."})
        findings = exposure.scan_typosquats(domains, resolve=bool(request.data.get("resolve")))
        audit(request, "exposure.typosquat_scan", target=",".join(domains), findings=len(findings))
        return Response({"findings": findings, "count": len(findings)})

    @action(detail=False, methods=["post"], url_path="ingest-credentials",
            parser_classes=[parsers.MultiPartParser, parsers.JSONParser])
    def ingest_credentials(self, request):
        if "file" in request.FILES:
            upload = request.FILES["file"]
            if upload.size > settings.THREATDASH_MAX_IMPORT_BYTES:
                raise ValidationError({"file": "File too large."})
            text = upload.read().decode("utf-8", "replace")
        else:
            text = request.data.get("records")
            text = json.dumps(text) if isinstance(text, list) else str(text or "")
        try:
            records = exposure.parse_credential_dump(text)
        except RecordError as exc:
            raise ValidationError(str(exc)) from exc
        result = exposure.ingest_leaked_credentials(records, breach_name=str(request.data.get("breach", ""))[:120],
                                                    source=str(request.data.get("source", ""))[:120])
        audit(request, "exposure.credentials_ingest", target=request.data.get("breach", ""),
              matched=result["matched_org"])
        return Response(result)

    @action(detail=False, methods=["post"], url_path="ingest-dark-web")
    def ingest_dark_web(self, request):
        records = request.data if isinstance(request.data, list) else request.data.get("records", [])
        if not isinstance(records, list):
            raise ValidationError({"records": "Provide a list of records."})
        return Response(exposure.ingest_dark_web(records, source=str(request.data.get("source", "api"))
                                                 if isinstance(request.data, dict) else "api"))


class ThreatFeedViewSet(viewsets.ModelViewSet):
    queryset = ThreatFeed.objects.select_related("last_import")
    serializer_class = serializers.ThreatFeedSerializer
    permission_classes = [IsStaffOrReadOnly]

    def list(self, request, *args, **kwargs):
        feeds.ensure_default_feeds()
        return super().list(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def pull(self, request, pk=None):
        feed = self.get_object()
        job = feeds.pull_feed(feed)
        audit(request, "feed.pull", target=feed, status=feed.last_status)
        return Response({"feed": self.get_serializer(feed).data,
                         "import": serializers.ImportJobSerializer(job).data if job.pk else None})


# --------------------------------------------------------------------------- #
# Response and automation
# --------------------------------------------------------------------------- #

class PlaybookViewSet(viewsets.ModelViewSet):
    queryset = Playbook.objects.all()
    serializer_class = serializers.PlaybookSerializer
    permission_classes = [IsStaffOrReadOnly]

    def list(self, request, *args, **kwargs):
        response_service.ensure_default_playbooks()
        return super().list(request, *args, **kwargs)

    @action(detail=True, methods=["post"], permission_classes=[CanRespond])
    def run(self, request, pk=None):
        playbook = self.get_object()
        asset = get_object_or_404(Asset, pk=request.data["asset"]) if request.data.get("asset") else None
        indicator = get_object_or_404(Indicator, pk=request.data["indicator"]) if request.data.get("indicator") else None
        incident = get_object_or_404(Incident, pk=request.data["incident"]) if request.data.get("incident") else None
        target_user = str(request.data.get("target_user") or "")[:255]
        if playbook.target_kind == "asset" and asset is None:
            raise ValidationError({"asset": "This playbook runs against an asset."})
        if playbook.target_kind == "indicator" and indicator is None:
            raise ValidationError({"indicator": "This playbook runs against an indicator."})
        if playbook.target_kind == "user" and not target_user:
            raise ValidationError({"target_user": "This playbook runs against a user account."})
        if playbook.target_kind == "global" and request.data.get("confirm") is not True:
            raise ValidationError({"confirm": "Global playbooks affect every user; send confirm=true."})
        try:
            run = response_service.run_playbook(playbook, request.user, request=request, asset=asset,
                                                indicator=indicator, incident=incident, target_user=target_user)
        except response_service.ResponseError as exc:
            raise ValidationError(str(exc)) from exc
        return Response(serializers.ResponseActionSerializer(run).data, status=status.HTTP_201_CREATED)


class ResponseActionViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = serializers.ResponseActionSerializer
    filterset_class = filters.ResponseActionFilter
    ordering_fields = ["created_at"]

    def get_queryset(self):
        return ResponseAction.objects.select_related("asset", "playbook", "requested_by", "indicator")

    def get_permissions(self):
        if self.action == "create":
            return [CanRespond()]
        if self.action == "terminal":
            return [CanUseTerminal()]
        return super().get_permissions()

    def create(self, request):
        """Run a single response action, e.g. one-click host isolation."""
        payload = serializers.ResponseRequestSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        data = payload.validated_data
        try:
            result = response_service.create_and_execute(
                data["action_type"], request.user, request=request, asset=data.get("asset"),
                indicator=data.get("indicator"), incident=data.get("incident"),
                target_user=data.get("target_user", ""), parameters=data.get("parameters") or {},
            )
        except response_service.ResponseError as exc:
            raise ValidationError(str(exc)) from exc
        if result.asset_id:
            refresh_asset_risk(Asset.objects.filter(pk=result.asset_id))
        return Response(self.get_serializer(result).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"])
    def terminal(self, request):
        """Live-response console: run one allow-listed forensic command on a managed endpoint."""
        asset = get_object_or_404(Asset, pk=request.data.get("asset"))
        command = str(request.data.get("command", "")).strip()
        try:
            result = response_service.create_and_execute(
                ResponseAction.ActionType.TERMINAL_COMMAND, request.user, request=request, asset=asset,
                incident=Incident.objects.filter(pk=request.data.get("incident")).first()
                if request.data.get("incident") else None,
                parameters={"command": command},
            )
        except response_service.ResponseError as exc:
            raise ValidationError({"command": str(exc)}) from exc
        return Response(self.get_serializer(result).data)

    @action(detail=False, methods=["get"])
    def capabilities(self, request):
        return Response({
            "connector": response_service.get_connector().name,
            "terminal_commands": response_service.TERMINAL_COMMANDS,
            "can_respond": CanRespond().has_permission(request, self),
            "can_use_terminal": CanUseTerminal().has_permission(request, self),
        })


class AuditLogViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = serializers.AuditLogSerializer
    permission_classes = [IsStaff]
    filterset_fields = ["action", "actor"]
    search_fields = ["action", "target", "actor_name"]


# --------------------------------------------------------------------------- #
# Analytics, executive, compliance and query
# --------------------------------------------------------------------------- #

class ComplianceControlViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.UpdateModelMixin,
                               viewsets.GenericViewSet):
    queryset = ComplianceControl.objects.all()
    serializer_class = serializers.ComplianceControlSerializer
    filterset_fields = ["framework", "status"]
    search_fields = ["control_id", "title"]
    pagination_class = None

    def list(self, request, *args, **kwargs):
        if not ComplianceControl.objects.exists():
            compliance.evaluate_controls()
        return super().list(request, *args, **kwargs)

    @action(detail=False, methods=["post"])
    def evaluate(self, request):
        compliance.evaluate_controls()
        audit(request, "compliance.evaluate")
        return Response({"frameworks": compliance.framework_summary()})

    @action(detail=False, methods=["get"])
    def summary(self, request):
        if not ComplianceControl.objects.exists():
            compliance.evaluate_controls()
        return Response({"frameworks": compliance.framework_summary()})


def _days_param(request, default=30):
    try:
        days = int(request.query_params.get("days", default))
    except (TypeError, ValueError) as exc:
        raise ValidationError({"days": "Must be an integer."}) from exc
    if not 1 <= days <= 365:
        raise ValidationError({"days": "Must be between 1 and 365."})
    return days


@api_view(["GET"])
def analytics_summary(request):
    return Response(analytics.summary(days=_days_param(request)))


@api_view(["GET"])
def executive_summary(request):
    return Response(executive.executive_summary())


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def natural_language_query(request):
    try:
        return Response(nlq.answer(request.data.get("question", "")))
    except ValueError as exc:
        raise ValidationError({"question": str(exc)}) from exc
