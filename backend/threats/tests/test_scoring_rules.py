from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from threats.models import Alert, DetectionRule, Incident
from threats.services.rules import count_matches, evaluate_indicators, run_rule
from threats.services.scoring import score_breakdown

from .base import make_indicator, make_source


class ScoringTests(TestCase):
    def test_score_bounds_and_ordering(self):
        critical = make_indicator("203.0.113.1", severity=4, confidence=95, source=make_source("A", "A"))
        low = make_indicator("203.0.113.2", severity=1, confidence=10, source=make_source("E", "E"))
        self.assertTrue(0 <= low.risk_score < critical.risk_score <= 100)

    def test_false_positive_scores_zero(self):
        indicator = make_indicator(status="false_positive", severity=4)
        self.assertEqual(indicator.risk_score, 0)

    def test_recency_decay(self):
        fresh = make_indicator("203.0.113.3", severity=3)
        stale_time = timezone.now() - timedelta(days=120)
        stale = make_indicator("203.0.113.4", severity=3, first_seen=stale_time, last_seen=stale_time)
        self.assertLess(stale.risk_score, fresh.risk_score)

    def test_cvss_raises_base(self):
        plain = make_indicator("CVE-2024-0001", "cve", severity=1, threat_type="exploit")
        cvss = make_indicator("CVE-2024-0002", "cve", severity=1, threat_type="exploit", cvss_score=9.8)
        self.assertGreater(cvss.risk_score, plain.risk_score)
        self.assertEqual(score_breakdown(cvss)["cvss_score"], 9.8)


class RuleEngineTests(TestCase):
    def test_matching_rule_creates_alert_and_incident_once(self):
        rule = DetectionRule.objects.create(name="C2", threat_types=["c2"], min_severity=3)
        indicator = make_indicator()
        self.assertEqual(len(evaluate_indicators([indicator])), 1)
        self.assertEqual(len(evaluate_indicators([indicator])), 0, "open alert must not be duplicated")
        alert = Alert.objects.get()
        self.assertIsNotNone(alert.incident)
        self.assertEqual(Incident.objects.count(), 1)
        rule.refresh_from_db()
        self.assertEqual(rule.hit_count, 1)

    def test_conditions_are_anded(self):
        DetectionRule.objects.create(name="Phish", threat_types=["phishing"], min_severity=3)
        self.assertEqual(evaluate_indicators([make_indicator(threat_type="phishing", severity=2)]), [])

    def test_tags_techniques_and_pattern(self):
        rule = DetectionRule.objects.create(name="T", tags=["apt29"], mitre_techniques=["T1059"],
                                            value_pattern=r"\.example$")
        hit = make_indicator("bad.example", "domain", tags=["apt29"], mitre_techniques=["T1059.001"])
        miss = make_indicator("bad.test", "domain", tags=["apt29"], mitre_techniques=["T1059"])
        self.assertEqual(len(evaluate_indicators([hit, miss], [rule])), 1)

    def test_inactive_indicators_ignored(self):
        DetectionRule.objects.create(name="Any high", min_severity=1)
        self.assertEqual(evaluate_indicators([make_indicator(status="mitigated")]), [])

    def test_dry_run_and_retro_hunt(self):
        make_indicator("203.0.113.20")
        make_indicator("203.0.113.21", threat_type="spam")
        rule = DetectionRule.objects.create(name="C2 only", threat_types=["c2"])
        self.assertEqual(count_matches(rule), 1)
        self.assertEqual(len(run_rule(rule)), 1)
