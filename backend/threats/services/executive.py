"""Executive view: business-level posture, risk heatmap and plain-language findings."""
import math
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone

from ..models import Alert, Asset, ExternalExposure, Incident, Severity, TelemetryDomain
from .analytics import threat_posture
from .compliance import framework_summary

SEVERITY_POINTS = {1: 1, 2: 3, 3: 8, 4: 20}
DOMAIN_FOR_DETECTION = {
    Alert.DetectionType.EXTERNAL: TelemetryDomain.IDENTITY,
}


def _saturate(points, scale=25):
    return round(100 * (1 - math.exp(-points / scale)))


def risk_heatmap(now=None):
    """Business unit × security domain matrix of open-alert risk (0-100)."""
    alerts = Alert.objects.filter(status__in=Alert.OPEN_STATUSES).select_related("asset", "event")
    departments = sorted({d or "Unassigned" for d in Asset.objects.values_list("department", flat=True)}) or \
        ["Unassigned"]
    domains = [d.value for d in TelemetryDomain]
    points = {(dept, dom): 0 for dept in departments for dom in domains}
    counts = {(dept, dom): 0 for dept in departments for dom in domains}
    for alert in alerts.iterator(chunk_size=1000):
        dept = (alert.asset.department if alert.asset_id and alert.asset else "") or "Unassigned"
        domain = alert.event.domain if alert.event_id and alert.event else DOMAIN_FOR_DETECTION.get(
            alert.detection_type, TelemetryDomain.NETWORK)
        key = (dept, domain)
        if key not in points:
            departments.append(dept)
            for dom in domains:
                points.setdefault((dept, dom), 0)
                counts.setdefault((dept, dom), 0)
        points[key] += SEVERITY_POINTS.get(alert.severity, 3)
        counts[key] += 1
    return {
        "rows": departments,
        "columns": [{"key": d.value, "label": d.label} for d in TelemetryDomain],
        "cells": [
            {"row": dept, "column": dom, "score": _saturate(points[(dept, dom)]), "alerts": counts[(dept, dom)]}
            for dept in departments for dom in domains
        ],
    }


def posture_trend(days=30, now=None):
    now = now or timezone.now()
    start = now - timedelta(days=days)
    # Resolved and dismissed alerts both carry resolved_at, so "open on day X"
    # is simply created before the end of X and not closed by then.
    alerts = list(Alert.objects.filter(Q(resolved_at__isnull=True) | Q(resolved_at__gte=start),
                                       created_at__lte=now).values_list("created_at", "resolved_at", "severity"))
    trend = []
    for offset in range(days - 1, -1, -1):
        day_end = (now - timedelta(days=offset)).replace(hour=23, minute=59, second=59)
        open_by_sev = {}
        for created, resolved, severity in alerts:
            if created <= day_end and (resolved is None or resolved > day_end):
                open_by_sev[severity] = open_by_sev.get(severity, 0) + 1
        trend.append({"date": day_end.date().isoformat(), "score": threat_posture({}, open_by_sev)["score"]})
    return trend


def executive_summary(now=None):
    from .analytics import ACTIONABLE
    from ..models import Indicator

    now = now or timezone.now()
    active = dict(Indicator.objects.filter(status__in=ACTIONABLE).values_list("severity").annotate(n=Count("id")))
    open_alerts = dict(Alert.objects.filter(status__in=Alert.OPEN_STATUSES).values_list("severity")
                       .annotate(n=Count("id")))
    posture = threat_posture(active, open_alerts)
    incidents = Incident.objects.filter(status__in=Incident.OPEN_STATUSES)
    critical_incidents = incidents.filter(severity=Severity.CRITICAL).count()
    assets = Asset.objects.all()
    total_assets = assets.count()
    shadow = assets.filter(managed=False).count()
    isolated = assets.filter(is_isolated=True).count()
    leaks = ExternalExposure.objects.filter(kind=ExternalExposure.Kind.LEAKED_CREDENTIAL,
                                            status__in=["open", "investigating"]).count()
    typos = ExternalExposure.objects.filter(kind=ExternalExposure.Kind.TYPOSQUAT,
                                            status__in=["open", "investigating"]).count()
    vulnerable = sum(1 for a in assets.exclude(vulnerabilities=[]).only("vulnerabilities") if a.max_cvss >= 9)
    compliance = framework_summary()

    findings = []
    if critical_incidents:
        findings.append({"level": "critical", "text": f"{critical_incidents} critical incident(s) are open and "
                                                      f"being worked by the SOC."})
    if total_assets and shadow:
        findings.append({"level": "high" if shadow / total_assets > 0.1 else "medium",
                         "text": f"{round(100 * shadow / total_assets)}% of devices ({shadow}) are unmanaged "
                                 f"shadow IT without endpoint protection."})
    if vulnerable:
        findings.append({"level": "high", "text": f"{vulnerable} system(s) carry critical vulnerabilities "
                                                  f"(CVSS 9+) that attackers actively target."})
    if leaks:
        findings.append({"level": "high", "text": f"{leaks} employee credential(s) were found in breach data and "
                                                  f"need a password reset."})
    if typos:
        findings.append({"level": "medium", "text": f"{typos} look-alike domain(s) could be used to phish "
                                                    f"customers or staff."})
    if isolated:
        findings.append({"level": "info", "text": f"{isolated} device(s) are currently isolated from the network "
                                                  f"for containment."})
    weakest = min(compliance, key=lambda f: f["readiness"]) if compliance else None
    if weakest and weakest["controls"]:
        findings.append({"level": "medium" if weakest["readiness"] >= 50 else "high",
                         "text": f"Lowest audit readiness: {weakest['label']} at {weakest['readiness']}%."})
    if not findings:
        findings.append({"level": "info", "text": "No material security risks are outstanding."})

    return {
        "generated_at": now.isoformat(),
        "posture": posture,
        "kpis": {
            "open_incidents": incidents.count(),
            "critical_incidents": critical_incidents,
            "assets": total_assets,
            "shadow_it": shadow,
            "isolated_assets": isolated,
            "leaked_credentials": leaks,
            "typosquats": typos,
            "critical_vulnerable_assets": vulnerable,
        },
        "findings": findings,
        "heatmap": risk_heatmap(now),
        "trend": posture_trend(30, now),
        "compliance": compliance,
    }
