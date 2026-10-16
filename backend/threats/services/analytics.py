"""Aggregations that power the dashboard and reports."""
import math
import statistics
from collections import Counter
from datetime import timedelta

from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from ..models import Alert, Indicator, IOCType, Severity, ThreatType

ACTIONABLE = [Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING]
ANOMALY_Z_THRESHOLD = 3.0
ANOMALY_MIN_COUNT = 5
BASELINE_DAYS = 7

POSTURE_LEVELS = [
    (80, "severe"),
    (60, "high"),
    (40, "elevated"),
    (20, "guarded"),
    (0, "low"),
]


def _daily_counts(queryset, field, start, days):
    rows = (
        queryset.filter(**{f"{field}__gte": start})
        .annotate(day=TruncDate(field))
        .values("day")
        .annotate(count=Count("id"))
    )
    by_day = {row["day"]: row["count"] for row in rows}
    first = start.date() if hasattr(start, "date") else start
    return [{"date": (first + timedelta(days=i)).isoformat(), "count": by_day.get(first + timedelta(days=i), 0)}
            for i in range(days)]


def detect_anomalies(series, z_threshold=ANOMALY_Z_THRESHOLD, min_count=ANOMALY_MIN_COUNT, baseline_days=BASELINE_DAYS):
    """Flag days whose volume is a statistical outlier against the preceding baseline.

    Uses a rolling z-score; when the baseline has no variance a jump to at
    least three times the mean (and ``min_count``) is treated as anomalous.
    """
    anomalies = []
    counts = [point["count"] for point in series]
    for index in range(len(counts)):
        window = counts[max(0, index - baseline_days):index]
        if len(window) < 3 or counts[index] < min_count:
            continue
        mean = statistics.fmean(window)
        stdev = statistics.pstdev(window)
        if stdev > 0:
            z = (counts[index] - mean) / stdev
            if z < z_threshold:
                continue
        else:
            if counts[index] < max(mean * 3, min_count):
                continue
            z = None
        anomalies.append({
            "date": series[index]["date"],
            "count": counts[index],
            "baseline": round(mean, 2),
            "zscore": round(z, 2) if z is not None else None,
        })
    return anomalies


def trending_threats(now=None, limit=5):
    """Threat types whose last-24h volume is well above their 7-day daily average."""
    now = now or timezone.now()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=8)
    recent = Counter(dict(
        Indicator.objects.filter(first_seen__gte=day_ago).values_list("threat_type").annotate(n=Count("id"))
    ))
    baseline = Counter(dict(
        Indicator.objects.filter(first_seen__gte=week_ago, first_seen__lt=day_ago)
        .values_list("threat_type").annotate(n=Count("id"))
    ))
    trends = []
    for threat_type, count in recent.items():
        daily_avg = baseline.get(threat_type, 0) / 7
        ratio = count / daily_avg if daily_avg else None
        if count >= 3 and (ratio is None or ratio >= 2):
            trends.append({
                "threat_type": threat_type,
                "label": ThreatType(threat_type).label if threat_type in ThreatType.values else threat_type,
                "last_24h": count,
                "daily_average": round(daily_avg, 2),
                "change_ratio": round(ratio, 2) if ratio is not None else None,
            })
    trends.sort(key=lambda t: (t["change_ratio"] is None, t["change_ratio"] or 0, t["last_24h"]), reverse=True)
    return trends[:limit]


def threat_posture(active_by_severity, open_alerts_by_severity):
    """A 0-100 situational score combining live critical/high indicators and open alerts."""
    def weight(counts):
        return (counts.get(Severity.CRITICAL, 0) * 10 + counts.get(Severity.HIGH, 0) * 4
                + counts.get(Severity.MEDIUM, 0) * 1 + counts.get(Severity.LOW, 0) * 0.2)

    raw = weight(active_by_severity) * 0.4 + weight(open_alerts_by_severity) * 1.0
    # Saturating curve: 150 weighted points ~= 63, 450 ~= 95, so the score keeps
    # moving as the SOC works the queue instead of pinning at 100.
    score = round(100 * (1 - math.exp(-raw / 150)))
    level = next(name for threshold, name in POSTURE_LEVELS if score >= threshold)
    return {"score": score, "level": level}


def _label_rows(rows, key, choices):
    labels = dict(choices)
    return [{"key": row[key], "label": str(labels.get(row[key], row[key])), "count": row["count"]} for row in rows]


def summary(days=30, now=None):
    days = min(max(int(days), 1), 365)
    now = now or timezone.now()
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    indicators = Indicator.objects.all()
    actionable = indicators.filter(status__in=ACTIONABLE)
    alerts = Alert.objects.all()
    open_alerts = alerts.filter(status__in=Alert.OPEN_STATUSES)

    totals = indicators.aggregate(
        total=Count("id"),
        actionable=Count("id", filter=Q(status__in=ACTIONABLE)),
        critical=Count("id", filter=Q(status__in=ACTIONABLE, severity=Severity.CRITICAL)),
        new_24h=Count("id", filter=Q(first_seen__gte=now - timedelta(hours=24))),
        avg_risk=Avg("risk_score", filter=Q(status__in=ACTIONABLE)),
        high_risk=Count("id", filter=Q(status__in=ACTIONABLE, risk_score__gte=80)),
    )
    alert_totals = alerts.aggregate(
        open=Count("id", filter=Q(status=Alert.Status.OPEN)),
        acknowledged=Count("id", filter=Q(status=Alert.Status.ACKNOWLEDGED)),
        new_24h=Count("id", filter=Q(created_at__gte=now - timedelta(hours=24))),
    )
    resolved = alerts.filter(status=Alert.Status.RESOLVED, resolved_at__isnull=False).annotate(
        duration=ExpressionWrapper(F("resolved_at") - F("created_at"), output_field=DurationField())
    )
    mttr = resolved.aggregate(avg=Avg("duration"))["avg"]

    active_by_severity = dict(actionable.values_list("severity").annotate(n=Count("id")))
    open_by_severity = dict(open_alerts.values_list("severity").annotate(n=Count("id")))

    tag_counts = Counter()
    technique_counts = Counter()
    for tags, techniques in actionable.values_list("tags", "mitre_techniques").iterator(chunk_size=2000):
        tag_counts.update(tags or [])
        technique_counts.update(techniques or [])

    indicator_timeline = _daily_counts(indicators, "first_seen", start, days)
    alert_timeline = _daily_counts(alerts, "created_at", start, days)

    return {
        "generated_at": now.isoformat(),
        "window_days": days,
        "totals": {
            "indicators": totals["total"],
            "actionable": totals["actionable"],
            "critical_active": totals["critical"],
            "high_risk": totals["high_risk"],
            "new_24h": totals["new_24h"],
            "average_risk": round(totals["avg_risk"] or 0, 1),
            "open_alerts": alert_totals["open"],
            "acknowledged_alerts": alert_totals["acknowledged"],
            "alerts_24h": alert_totals["new_24h"],
            "mttr_hours": round(mttr.total_seconds() / 3600, 2) if mttr else None,
        },
        "posture": threat_posture(active_by_severity, open_by_severity),
        "by_severity": [
            {"key": level.value, "label": level.label, "count": active_by_severity.get(level.value, 0)}
            for level in Severity
        ],
        "by_threat_type": _label_rows(
            actionable.values("threat_type").annotate(count=Count("id")).order_by("-count"), "threat_type", ThreatType.choices
        ),
        "by_ioc_type": _label_rows(
            actionable.values("ioc_type").annotate(count=Count("id")).order_by("-count"), "ioc_type", IOCType.choices
        ),
        "by_status": _label_rows(
            indicators.values("status").annotate(count=Count("id")).order_by("-count"), "status", Indicator.Status.choices
        ),
        "by_source": [
            {"key": row["source__name"] or "Unattributed", "label": row["source__name"] or "Unattributed",
             "count": row["count"]}
            for row in actionable.values("source__name").annotate(count=Count("id")).order_by("-count")[:10]
        ],
        "top_countries": [
            {"key": row["country"], "label": row["country"], "count": row["count"]}
            for row in actionable.exclude(country="").values("country").annotate(count=Count("id")).order_by("-count")[:10]
        ],
        "top_tags": [{"key": k, "label": k, "count": v} for k, v in tag_counts.most_common(15)],
        "mitre_techniques": [{"key": k, "label": k, "count": v} for k, v in technique_counts.most_common(20)],
        "timeline": {"indicators": indicator_timeline, "alerts": alert_timeline},
        "anomalies": detect_anomalies(indicator_timeline),
        "trending": trending_threats(now),
        "top_risky": list(
            actionable.order_by("-risk_score", "-last_seen").values(
                "id", "value", "ioc_type", "threat_type", "severity", "risk_score", "last_seen"
            )[:10]
        ),
    }
