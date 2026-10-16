import io
import json

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse

from threats.models import Alert, Asset, AuditLog, DataConnector, DetectionRule, Incident, Indicator, Report

from .base import APIBase, make_indicator


class AuthTests(APIBase):
    def test_requires_authentication(self):
        self.client.force_authenticate(None)
        self.assertEqual(self.client.get("/api/indicators/").status_code, 401)
        self.assertEqual(self.client.get("/api/health/").status_code, 200)

    def test_login_logout(self):
        self.client.force_authenticate(None)
        response = self.client.post("/api/auth/token/", {"username": "analyst", "password": "Analyst-pass-123"})
        self.assertEqual(response.status_code, 200)
        token = response.data["token"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        self.assertEqual(self.client.get("/api/auth/me/").data["username"], "analyst")
        self.assertEqual(self.client.post("/api/auth/logout/").status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 401)

    def test_failed_login_audited(self):
        self.client.force_authenticate(None)
        self.assertEqual(self.client.post("/api/auth/token/", {"username": "analyst", "password": "x"}).status_code,
                         400)
        self.assertTrue(AuditLog.objects.filter(action="auth.login_failed").exists())


class IndicatorAPITests(APIBase):
    def test_create_normalises_and_triggers_rules(self):
        DetectionRule.objects.create(name="Phish", threat_types=["phishing"])
        response = self.client.post("/api/indicators/", {"value": "hxxps://Bad[.]Example/login",
                                                         "threat_type": "phishing", "severity": 3,
                                                         "tags": ["Kit", "kit"], "mitre_techniques": ["t1566"]},
                                    format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["ioc_type"], "url")
        self.assertEqual(response.data["value"], "https://bad.example/login")
        self.assertEqual(response.data["tags"], ["kit"])
        self.assertEqual(Alert.objects.count(), 1)

    def test_validation_errors(self):
        self.assertEqual(self.client.post("/api/indicators/", {"value": "???"}, format="json").status_code, 400)
        make_indicator("203.0.113.10")
        dup = self.client.post("/api/indicators/", {"value": "203.0.113.10"}, format="json")
        self.assertEqual(dup.status_code, 400)
        bad = self.client.post("/api/indicators/", {"value": "203.0.113.11", "mitre_techniques": ["X1"]},
                               format="json")
        self.assertEqual(bad.status_code, 400)

    def test_filters_search_and_detail(self):
        a = make_indicator("203.0.113.1", severity=4, tags=["apt"])
        make_indicator("evil.example", "domain", severity=1)
        self.assertEqual(self.client.get("/api/indicators/?severity_min=4").data["count"], 1)
        self.assertEqual(self.client.get("/api/indicators/?search=evil").data["count"], 1)
        self.assertEqual(self.client.get("/api/indicators/?tag=apt").data["count"], 1)
        detail = self.client.get(f"/api/indicators/{a.pk}/").data
        self.assertIn("score_breakdown", detail)

    def test_delete_requires_staff(self):
        indicator = make_indicator()
        self.assertEqual(self.client.delete(f"/api/indicators/{indicator.pk}/").status_code, 403)
        self.as_user(self.staff)
        self.assertEqual(self.client.delete(f"/api/indicators/{indicator.pk}/").status_code, 204)

    def test_lookup_and_related(self):
        a = make_indicator("203.0.113.1", tags=["x"])
        make_indicator("203.0.113.2", tags=["x"])
        response = self.client.post("/api/indicators/lookup/", {"values": "203.0.113[.]1 8.8.8.8 junk"},
                                    format="json")
        self.assertEqual(response.data["matches"], 1)
        related = self.client.get(f"/api/indicators/{a.pk}/related/").data
        self.assertEqual(related["count"], 1)
        self.assertTrue(any("/24" in r for r in related["results"][0]["reasons"]))

    def test_exports(self):
        make_indicator("evil.example", "domain", description="=HYPERLINK(1)")
        csv_body = self.client.get("/api/indicators/export/?export_format=csv").content.decode()
        self.assertIn("'=HYPERLINK", csv_body)
        stix = json.loads(self.client.get("/api/indicators/export/?export_format=stix").content)
        self.assertEqual(stix["type"], "bundle")
        self.assertIn("[domain-name:value = 'evil.example']", [o.get("pattern") for o in stix["objects"]])
        self.assertEqual(self.client.get("/api/indicators/export/?export_format=xls").status_code, 400)

    def test_blocklist_with_connector_key(self):
        make_indicator("203.0.113.9", severity=4, confidence=100)
        connector = DataConnector(name="fw", provider="firewall", domain="network")
        key = connector.rotate_key()
        connector.save()
        self.client.force_authenticate(None)
        response = self.client.get("/api/indicators/blocklist/?type=ip&min_risk=10", HTTP_X_INGEST_KEY=key)
        self.assertEqual(response.status_code, 200)
        self.assertIn("203.0.113.9", response.content.decode())
        self.assertEqual(self.client.get("/api/indicators/blocklist/", HTTP_X_INGEST_KEY="tdk_wrong").status_code,
                         401)

    def test_bulk_status(self):
        a, b = make_indicator("203.0.113.1"), make_indicator("203.0.113.2")
        response = self.client.post("/api/indicators/bulk_status/", {"ids": [a.pk, b.pk], "status": "mitigated"},
                                    format="json")
        self.assertEqual(response.data["updated"], 2)
        self.assertEqual(Indicator.objects.filter(status="mitigated").count(), 2)


class ImportAndReportAPITests(APIBase):
    def test_upload(self):
        upload = SimpleUploadedFile("f.csv", b"value,severity\n203.0.113.1,high\n", content_type="text/csv")
        response = self.client.post("/api/imports/", {"file": upload, "source_name": "Partner"}, format="multipart")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["created_count"], 1)
        self.assertEqual(response.data["source_name"], "Partner")

    @override_settings(THREATDASH_MAX_IMPORT_BYTES=10)
    def test_upload_size_limit(self):
        upload = SimpleUploadedFile("f.csv", b"value\n203.0.113.1\n203.0.113.2\n")
        self.assertEqual(self.client.post("/api/imports/", {"file": upload}, format="multipart").status_code, 400)

    def test_reports_all_formats(self):
        make_indicator("203.0.113.1", severity=4, description="<b>&amp;</b>")
        for fmt in ("pdf", "docx", "xlsx", "csv", "json"):
            with self.subTest(fmt=fmt):
                response = self.client.post("/api/reports/", {"name": f"Weekly {fmt}", "file_format": fmt,
                                                              "min_severity": 2}, format="json")
                self.assertEqual(response.status_code, 201, response.data)
                download = self.client.get(response.data["download_url"])
                self.assertEqual(download.status_code, 200)
                content = b"".join(download.streaming_content)
                self.assertGreater(len(content), 50)
                if fmt == "pdf":
                    self.assertTrue(content.startswith(b"%PDF"))
        self.assertEqual(Report.objects.count(), 5)

    def test_report_date_validation(self):
        response = self.client.post("/api/reports/", {"name": "x", "date_from": "2026-02-01",
                                                      "date_to": "2026-01-01"}, format="json")
        self.assertEqual(response.status_code, 400)


class SocAPITests(APIBase):
    def _connector(self, provider="generic", domain="endpoint"):
        self.as_user(self.staff)
        response = self.client.post("/api/connectors/", {"name": f"c-{provider}", "provider": provider,
                                                         "domain": domain}, format="json")
        self.assertEqual(response.status_code, 201)
        self.client.force_authenticate(None)
        return response.data["ingest_key"]

    def test_connector_ingest_and_alert_flow(self):
        make_indicator("203.0.113.66", severity=4)
        key = self._connector("edr")
        response = self.client.post("/api/events/ingest/", [
            {"domain": "endpoint", "event_type": "beacon", "hostname": "lt-9", "dst_ip": "203.0.113.66"}],
            format="json", HTTP_X_INGEST_KEY=key)
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(response.data["ioc_matches"], 1)
        self.as_user(self.analyst)
        incident = self.client.get("/api/incidents/").data["results"][0]
        self.assertEqual(incident["alert_count"], 1)
        path = self.client.get(f"/api/incidents/{incident['id']}/attack-path/").data
        self.assertTrue(path["nodes"])
        alert = Alert.objects.get()
        self.assertEqual(self.client.post(f"/api/alerts/{alert.pk}/acknowledge/").data["status"], "acknowledged")
        self.assertEqual(self.client.post(f"/api/alerts/{alert.pk}/resolve/", {"notes": "blocked"}).data["status"],
                         "resolved")
        alert.refresh_from_db()
        self.assertIsNotNone(alert.resolved_at)

    def test_connector_writes_require_staff(self):
        self.assertEqual(self.client.post("/api/connectors/", {"name": "x"}, format="json").status_code, 403)

    def test_ingest_without_credentials_rejected(self):
        self.client.force_authenticate(None)
        self.assertEqual(self.client.post("/api/events/ingest/", [], format="json").status_code, 401)

    def test_response_permissions_and_isolation(self):
        asset = Asset.objects.create(hostname="lt-1", managed=True)
        payload = {"action_type": "isolate_host", "asset": asset.pk}
        self.assertEqual(self.client.post("/api/response-actions/", payload, format="json").status_code, 403)
        self.as_user(self.responder)
        response = self.client.post("/api/response-actions/", payload, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["status"], "succeeded")
        self.assertTrue(Asset.objects.get(pk=asset.pk).is_isolated)
        self.assertTrue(AuditLog.objects.filter(action="response.isolate_host").exists())
        again = self.client.post("/api/response-actions/", payload, format="json")
        self.assertEqual(again.status_code, 400)

    def test_terminal(self):
        asset = Asset.objects.create(hostname="lt-1", managed=True)
        self.assertEqual(self.client.post("/api/response-actions/terminal/", {"asset": asset.pk, "command": "ps"},
                                          format="json").status_code, 403)
        self.as_user(self.responder)
        ok = self.client.post("/api/response-actions/terminal/", {"asset": asset.pk, "command": "netstat"},
                              format="json")
        self.assertEqual(ok.status_code, 200, ok.data)
        bad = self.client.post("/api/response-actions/terminal/", {"asset": asset.pk, "command": "cat /etc/shadow"},
                               format="json")
        self.assertEqual(bad.status_code, 400)

    def test_global_playbook_needs_confirmation(self):
        self.as_user(self.responder)
        playbooks = self.client.get("/api/playbooks/").data["results"]
        reset = next(p for p in playbooks if p["name"] == "Force global password reset")
        self.assertEqual(self.client.post(f"/api/playbooks/{reset['id']}/run/", {}, format="json").status_code, 400)
        run = self.client.post(f"/api/playbooks/{reset['id']}/run/", {"confirm": True}, format="json")
        self.assertEqual(run.status_code, 201, run.data)
        self.assertEqual(run.data["status"], "succeeded")

    def test_dashboards(self):
        make_indicator("203.0.113.1", severity=4)
        for url in ("/api/analytics/summary/?days=14", "/api/executive/summary/", "/api/compliance/summary/",
                    "/api/assets/discovery/", "/api/events/stats/", "/api/feeds/", "/api/compliance/"):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(self.client.get("/api/analytics/summary/?days=0").status_code, 400)

    def test_nl_query_endpoint(self):
        make_indicator("203.0.113.1", severity=4, country="RU")
        response = self.client.post("/api/query/", {"question": "critical indicators by country"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["series"][0]["label"], "RU")
        self.assertEqual(self.client.post("/api/query/", {"question": ""}, format="json").status_code, 400)

    def test_exposure_endpoints(self):
        response = self.client.post("/api/exposures/ingest-credentials/",
                                    {"records": "it@example.com:pw\n", "breach": "Test"}, format="json")
        self.assertEqual(response.data["created"], 1)
        candidates = self.client.get("/api/exposures/typosquat-candidates/?domain=example.com").data
        self.assertGreater(candidates["count"], 50)

    def test_incident_close_resolves_alerts(self):
        make_indicator("203.0.113.66", severity=4)
        DetectionRule.objects.create(name="r", min_severity=1)
        from threats.services.rules import evaluate_indicators
        evaluate_indicators(Indicator.objects.all())
        incident = Incident.objects.get()
        response = self.client.patch(f"/api/incidents/{incident.pk}/", {"status": "closed"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Alert.objects.filter(status__in=Alert.OPEN_STATUSES).exists())

    def test_audit_log_staff_only(self):
        self.assertEqual(self.client.get("/api/audit-log/").status_code, 403)
        self.as_user(self.staff)
        self.assertEqual(self.client.get("/api/audit-log/").status_code, 200)


class SeedCommandTests(APIBase):
    def test_seed_demo_runs(self):
        from django.core.management import call_command

        out = io.StringIO()
        call_command("seed_demo", "--indicators", "40", stdout=out)
        self.assertIn("Demo data ready", out.getvalue())
        self.assertTrue(Incident.objects.filter(alert_count__gte=5).exists())
        call_command("threat_maintenance", stdout=out)
        self.assertEqual(self.client.get(reverse("executive-summary")).status_code, 200)
