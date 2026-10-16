"""Detection rule evaluation: turn matching indicators into alerts."""
import logging
import re

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from ..models import Alert, DetectionRule, Indicator, Severity
from .incidents import correlate_alerts

logger = logging.getLogger(__name__)


def compile_pattern(pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        logger.warning("Ignoring invalid detection rule pattern %r", pattern)
        return None


def rule_matches(rule, indicator, compiled_pattern=None):
    """True when ``indicator`` satisfies every condition configured on ``rule``."""
    if not indicator.is_actionable:
        return False
    if rule.ioc_types and indicator.ioc_type not in rule.ioc_types:
        return False
    if rule.threat_types and indicator.threat_type not in rule.threat_types:
        return False
    if rule.min_severity and indicator.severity < rule.min_severity:
        return False
    if rule.min_confidence is not None and indicator.confidence < rule.min_confidence:
        return False
    if rule.min_risk_score is not None and indicator.risk_score < rule.min_risk_score:
        return False
    if rule.countries and (indicator.country or "").upper() not in {c.upper() for c in rule.countries}:
        return False
    if rule.tags and not set(t.lower() for t in rule.tags) & set(indicator.tags or []):
        return False
    if rule.mitre_techniques:
        wanted = {t.upper() for t in rule.mitre_techniques}
        # A parent technique (T1059) also matches its sub-techniques (T1059.001).
        have = set(indicator.mitre_techniques or [])
        have |= {t.split(".")[0] for t in have}
        if not wanted & have:
            return False
    if rule.value_pattern:
        compiled = compiled_pattern or compile_pattern(rule.value_pattern)
        if compiled is None or not compiled.search(indicator.value):
            return False
    return True


def _alert_title(rule, indicator):
    return f"{rule.name}: {indicator.get_ioc_type_display()} {indicator.value}"[:300]


def evaluate_indicators(indicators, rules=None):
    """Evaluate indicators against enabled rules; returns the newly created alerts.

    Only one open (or acknowledged) alert exists per rule/indicator pair, so
    re-importing the same feed does not flood the queue.
    """
    rules = list(rules if rules is not None else DetectionRule.objects.filter(enabled=True))
    if not rules:
        return []
    compiled = {rule.pk: compile_pattern(rule.value_pattern) for rule in rules}
    indicators = list(indicators)
    if not indicators:
        return []

    existing = set(
        Alert.objects.filter(
            indicator__in=[i.pk for i in indicators],
            rule__in=[r.pk for r in rules],
            status__in=Alert.OPEN_STATUSES,
        ).values_list("rule_id", "indicator_id")
    )
    new_alerts = []
    hits = {}
    for indicator in indicators:
        for rule in rules:
            if (rule.pk, indicator.pk) in existing:
                continue
            if rule.value_pattern and compiled[rule.pk] is None:
                continue
            if not rule_matches(rule, indicator, compiled[rule.pk]):
                continue
            new_alerts.append(
                Alert(
                    title=_alert_title(rule, indicator),
                    description=rule.description,
                    detection_type=Alert.DetectionType.RULE,
                    dedup_key=f"rule:{rule.pk}:{indicator.pk}",
                    indicator=indicator,
                    rule=rule,
                    severity=rule.alert_severity or indicator.severity or Severity.MEDIUM,
                    mitre_techniques=list(indicator.mitre_techniques or []),
                )
            )
            existing.add((rule.pk, indicator.pk))
            hits[rule.pk] = hits.get(rule.pk, 0) + 1

    if new_alerts:
        now = timezone.now()
        with transaction.atomic():
            Alert.objects.bulk_create(new_alerts, batch_size=500)
            correlate_alerts(new_alerts)
            for rule_id, count in hits.items():
                DetectionRule.objects.filter(pk=rule_id).update(
                    hit_count=F("hit_count") + count, last_triggered_at=now
                )
        logger.info("Detection rules raised %d alert(s)", len(new_alerts))
    return new_alerts


def run_rule(rule):
    """Retro-hunt: evaluate one rule against every actionable indicator."""
    queryset = Indicator.objects.filter(status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING])
    created = []
    batch = []
    for indicator in queryset.select_related("source").iterator(chunk_size=1000):
        batch.append(indicator)
        if len(batch) >= 1000:
            created += evaluate_indicators(batch, [rule])
            batch = []
    if batch:
        created += evaluate_indicators(batch, [rule])
    return created


def count_matches(rule):
    """Dry-run a rule and return how many indicators it would currently match."""
    compiled = compile_pattern(rule.value_pattern)
    if rule.value_pattern and compiled is None:
        return 0
    queryset = Indicator.objects.filter(status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING])
    if rule.ioc_types:
        queryset = queryset.filter(ioc_type__in=rule.ioc_types)
    if rule.threat_types:
        queryset = queryset.filter(threat_type__in=rule.threat_types)
    if rule.min_severity:
        queryset = queryset.filter(severity__gte=rule.min_severity)
    if rule.min_confidence is not None:
        queryset = queryset.filter(confidence__gte=rule.min_confidence)
    if rule.min_risk_score is not None:
        queryset = queryset.filter(risk_score__gte=rule.min_risk_score)
    return sum(1 for ind in queryset.iterator(chunk_size=1000) if rule_matches(rule, ind, compiled))
