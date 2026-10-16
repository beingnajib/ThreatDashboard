"""Asset risk: criticality, open alerts, vulnerabilities, shadow IT and behavioural drift."""
import statistics
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from ..models import Alert, Asset, TelemetryEvent

CRITICALITY_BASE = {1: 10, 2: 20, 3: 32, 4: 45}
ALERT_WEIGHT = {1: 2, 2: 5, 3: 10, 4: 18}
BASELINE_DAYS = 14


def behaviour_anomaly(asset, now=None):
    """Z-score of today's event volume against the asset's own 14-day baseline."""
    now = now or timezone.now()
    start = (now - timedelta(days=BASELINE_DAYS)).date()
    rows = dict(
        TelemetryEvent.objects.filter(asset=asset, timestamp__date__gte=start)
        .annotate(day=TruncDate("timestamp")).values_list("day").annotate(n=Count("id"))
    )
    today = rows.pop(now.date(), 0)
    history = [rows.get(start + timedelta(days=i), 0) for i in range(BASELINE_DAYS)]
    observed = [v for v in history if v]
    if len(observed) < 3:
        return None
    mean = statistics.fmean(history)
    stdev = statistics.pstdev(history) or 1.0
    return round((today - mean) / stdev, 2)


def asset_risk_breakdown(asset, now=None):
    open_alerts = dict(
        Alert.objects.filter(asset=asset, status__in=Alert.OPEN_STATUSES).values_list("severity").annotate(n=Count("id"))
    )
    alert_points = min(sum(ALERT_WEIGHT.get(sev, 5) * n for sev, n in open_alerts.items()), 30)
    cvss_points = min(asset.max_cvss * 2, 20)
    shadow_points = 10 if not asset.managed else 0
    anomaly = behaviour_anomaly(asset, now) if asset.pk else None
    anomaly_points = 10 if anomaly is not None and anomaly >= 3 else 0
    score = CRITICALITY_BASE.get(asset.criticality, 20) + alert_points + cvss_points + shadow_points + anomaly_points
    if asset.is_isolated:
        score *= 0.5  # contained
    return {
        "score": int(min(round(score), 100)),
        "criticality_base": CRITICALITY_BASE.get(asset.criticality, 20),
        "open_alerts": sum(open_alerts.values()),
        "alert_points": alert_points,
        "max_cvss": asset.max_cvss,
        "cvss_points": cvss_points,
        "shadow_it_points": shadow_points,
        "behaviour_zscore": anomaly,
        "behaviour_points": anomaly_points,
        "isolated": asset.is_isolated,
    }


def refresh_asset_risk(queryset=None):
    queryset = queryset if queryset is not None else Asset.objects.all()
    updated = 0
    for asset in queryset.iterator(chunk_size=500):
        score = asset_risk_breakdown(asset)["score"]
        if score != asset.risk_score:
            Asset.objects.filter(pk=asset.pk).update(risk_score=score)
            updated += 1
    return updated
