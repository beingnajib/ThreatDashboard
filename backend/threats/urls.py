from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("indicators", views.IndicatorViewSet, basename="indicator")
router.register("sources", views.SourceViewSet, basename="source")
router.register("rules", views.DetectionRuleViewSet, basename="rule")
router.register("alerts", views.AlertViewSet, basename="alert")
router.register("incidents", views.IncidentViewSet, basename="incident")
router.register("imports", views.ImportJobViewSet, basename="import")
router.register("reports", views.ReportViewSet, basename="report")
router.register("assets", views.AssetViewSet, basename="asset")
router.register("events", views.TelemetryEventViewSet, basename="event")
router.register("connectors", views.DataConnectorViewSet, basename="connector")
router.register("actors", views.ThreatActorViewSet, basename="actor")
router.register("exposures", views.ExternalExposureViewSet, basename="exposure")
router.register("feeds", views.ThreatFeedViewSet, basename="feed")
router.register("playbooks", views.PlaybookViewSet, basename="playbook")
router.register("response-actions", views.ResponseActionViewSet, basename="response-action")
router.register("audit-log", views.AuditLogViewSet, basename="audit-log")
router.register("compliance", views.ComplianceControlViewSet, basename="compliance")

urlpatterns = [
    path("health/", views.health, name="health"),
    path("auth/token/", views.LoginView.as_view(), name="auth-token"),
    path("auth/me/", views.me, name="auth-me"),
    path("auth/logout/", views.logout, name="auth-logout"),
    path("analytics/summary/", views.analytics_summary, name="analytics-summary"),
    path("executive/summary/", views.executive_summary, name="executive-summary"),
    path("query/", views.natural_language_query, name="nl-query"),
    path("cron/run/", views.cron_run, name="cron-run"),
    path("", include(router.urls)),
]
