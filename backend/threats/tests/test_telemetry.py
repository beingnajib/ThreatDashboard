from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from threats.models import Alert, Asset, Incident, TelemetryEvent, ThreatActor
from threats.services.attribution import attribute_incident
from threats.services.incidents import attack_path
from threats.services.telemetry import ingest_events

from .base import make_indicator


class TelemetryTests(TestCase):
    def test_generic_ingest_discovers_assets_and_shadow_it(self):
        result = ingest_events([
            {"domain": "endpoint", "event_type": "process_start", "hostname": "WS-01", "asset_ip": "10.0.0.5"},
            {"domain": "network", "event_type": "dhcp_lease", "src_ip": "10.0.0.99"},
        ], provider="edr")
        self.assertEqual(result["ingested"], 2)
        self.assertEqual(result["assets_discovered"], 2)
        self.assertTrue(Asset.objects.get(hostname="ws-01").managed)
        self.assertFalse(Asset.objects.get(ip_address="10.0.0.99").managed)

    def test_ip_only_traffic_reuses_known_asset(self):
        ingest_events([{"domain": "endpoint", "event_type": "x", "hostname": "srv", "asset_ip": "10.0.0.7"}],
                      provider="edr")
        ingest_events([{"domain": "network", "event_type": "conn", "src_ip": "10.0.0.7"}], provider="firewall")
        self.assertEqual(Asset.objects.count(), 1)

    def test_invalid_events_reported(self):
        result = ingest_events([{"event_type": "x"}, "nope", {"domain": "cloud"}])
        self.assertEqual(result["ingested"], 0)
        self.assertEqual(len(result["errors"]), 3)

    def test_ioc_match_raises_alert_and_records_sighting(self):
        indicator = make_indicator("203.0.113.66", sighting_count=1)
        result = ingest_events([{"domain": "network", "event_type": "conn", "src_ip": "10.0.0.8",
                                 "dst_ip": "203.0.113.66"}], provider="firewall")
        self.assertEqual(result["ioc_matches"], 1)
        alert = Alert.objects.get(detection_type="ioc_match")
        self.assertEqual(alert.indicator, indicator)
        indicator.refresh_from_db()
        self.assertEqual(indicator.sighting_count, 2)
        self.assertEqual(TelemetryEvent.objects.get().matched_indicators.get(), indicator)

    def test_brute_force_detection(self):
        now = timezone.now()
        events = [{"createdDateTime": (now - timedelta(minutes=i)).isoformat(), "userPrincipalName": "a@x.example",
                   "ipAddress": "203.0.113.1", "status": {"errorCode": 50126}} for i in range(10)]
        ingest_events(events, provider="azure_signin")
        self.assertTrue(Alert.objects.filter(mitre_techniques__icontains="T1110").exists())

    def test_impossible_travel(self):
        now = timezone.now()
        ingest_events([
            {"createdDateTime": now.isoformat(), "userPrincipalName": "b@x.example", "ipAddress": "203.0.113.2",
             "status": {"errorCode": 0}, "location": {"countryOrRegion": "US"}},
            {"createdDateTime": (now + timedelta(minutes=20)).isoformat(), "userPrincipalName": "b@x.example",
             "ipAddress": "198.51.100.2", "status": {"errorCode": 0}, "location": {"countryOrRegion": "RU"}},
        ], provider="azure_signin")
        self.assertTrue(Alert.objects.filter(title__icontains="Impossible travel").exists())

    def test_cloudtrail_tampering_detected(self):
        ingest_events({"Records": [{"eventTime": timezone.now().isoformat(), "eventName": "StopLogging",
                                    "sourceIPAddress": "203.0.113.3", "userIdentity": {"userName": "eve"}}]},
                      provider="aws_cloudtrail")
        event = TelemetryEvent.objects.get()
        self.assertEqual((event.domain, event.severity, event.mitre_technique), ("cloud", 4, "T1562.008"))
        self.assertEqual(Alert.objects.get().detection_type, "telemetry")

    def test_azure_activity_vm(self):
        ingest_events([{"eventTimestamp": timezone.now().isoformat(),
                        "operationName": {"value": "Microsoft.Compute/virtualMachines/runCommand/action"},
                        "caller": "x@y.example", "resourceId": "/subscriptions/1/virtualMachines/VM-APP-1"}],
                      provider="azure_activity")
        self.assertEqual(Asset.objects.get().hostname, "vm-app-1")

    def test_exfiltration_detection(self):
        ingest_events([{"domain": "network", "event_type": "upload", "hostname": "db1", "src_ip": "10.0.0.3",
                        "dst_ip": "198.51.100.9", "bytes_out": 700 * 1024 * 1024}], provider="firewall")
        self.assertTrue(Alert.objects.filter(mitre_techniques__icontains="T1048").exists())


class IncidentTests(TestCase):
    def setUp(self):
        self.c2 = make_indicator("203.0.113.66", tags=["apt29"], mitre_techniques=["T1071"])
        self.actor = ThreatActor.objects.create(name="APT29", mitre_techniques=["T1071", "T1003", "T1021"])
        self.actor.indicators.add(self.c2)
        now = timezone.now()
        ingest_events([
            {"domain": "endpoint", "event_type": "beacon", "hostname": "lt-1", "dst_ip": "203.0.113.66",
             "timestamp": now.isoformat()},
            {"domain": "endpoint", "event_type": "lsass_access", "hostname": "lt-1", "severity": "critical",
             "mitre_technique": "T1003.001", "timestamp": (now + timedelta(minutes=5)).isoformat()},
            {"domain": "endpoint", "event_type": "lateral_psexec", "hostname": "lt-1", "target_hostname": "srv-1",
             "severity": "high", "mitre_technique": "T1021.002", "timestamp": (now + timedelta(minutes=9)).isoformat()},
        ], provider="edr")

    def test_related_alerts_bundle_into_one_incident(self):
        self.assertEqual(Alert.objects.count(), 3)
        self.assertEqual(Incident.objects.count(), 1)
        incident = Incident.objects.get()
        self.assertEqual(incident.alert_count, 3)
        self.assertEqual(incident.severity, 4)
        self.assertEqual(set(incident.assets.values_list("hostname", flat=True)), {"lt-1", "srv-1"})
        self.assertGreater(incident.priority_score, 80)

    def test_attack_path(self):
        graph = attack_path(Incident.objects.get())
        stages = [s["key"] for s in graph["stages"]]
        self.assertIn("lateral_movement", stages)
        self.assertIn("command_and_control", stages)
        ids = {n["id"] for n in graph["nodes"]}
        self.assertIn("ip:203.0.113.66", ids)
        self.assertTrue(any(e["stage"] == "lateral_movement" and e["target"].startswith("asset:")
                            for e in graph["edges"]))

    def test_attribution(self):
        results = attribute_incident(Incident.objects.get())
        self.assertEqual(results[0]["name"], "APT29")
        self.assertGreaterEqual(results[0]["confidence"], 50)
        self.assertIn(self.c2.pk, results[0]["evidence"]["shared_indicators"])
