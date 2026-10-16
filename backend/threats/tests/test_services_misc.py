from django.test import TestCase, override_settings

from threats.models import Asset, ComplianceControl, ExternalExposure, Incident, Indicator, Playbook, ResponseAction
from threats.services import compliance, nlq
from threats.services.exposure import (
    ingest_dark_web,
    ingest_leaked_credentials,
    parse_credential_dump,
    scan_typosquats,
    typosquat_candidates,
)
from threats.services.response import (
    ResponseError,
    create_and_execute,
    ensure_default_playbooks,
    parse_terminal_command,
    run_playbook,
)
from threats.services.telemetry import ingest_events

from .base import make_indicator


class ExposureTests(TestCase):
    def test_typosquat_generation(self):
        names = {c["domain"] for c in typosquat_candidates("example.com")}
        self.assertIn("exmple.com", names)        # omission
        self.assertIn("examp1e.com", names)       # homoglyph
        self.assertIn("example.net", names)       # tld swap
        self.assertNotIn("example.com", names)

    def test_typosquat_scan_uses_traffic(self):
        ingest_events([{"domain": "network", "event_type": "dns_query", "domain_name": "examp1e.com"}])
        findings = scan_typosquats(["example.com"])
        self.assertEqual(len(findings), 1)
        exposure = ExternalExposure.objects.get()
        self.assertEqual((exposure.kind, exposure.severity), ("typosquat", 3))
        self.assertEqual(len(scan_typosquats(["example.com"])), 1)
        self.assertEqual(ExternalExposure.objects.count(), 1, "re-scan must de-duplicate")

    def test_leaked_credentials_never_store_passwords(self):
        records = parse_credential_dump("ceo@example.com:Hunter2!\nother@else.example:x\nhr@example.com\n")
        result = ingest_leaked_credentials(records, breach_name="Dump", domains=["example.com"])
        self.assertEqual((result["matched_org"], result["created"], result["skipped"]), (2, 2, 1))
        exposure = ExternalExposure.objects.get(data__email="ceo@example.com")
        self.assertEqual(exposure.severity, 4)
        self.assertNotIn("Hunter2", str(exposure.data) + exposure.title + exposure.detail)
        self.assertEqual(len(exposure.data["password_sha1_prefix"]), 5)

    def test_dark_web_ingest(self):
        result = ingest_dark_web([{"title": "Access for sale", "severity": "critical"}, {"no": "title"}])
        self.assertEqual((result["created"], result["errors"]), (1, 1))


class ResponseTests(TestCase):
    def setUp(self):
        self.asset = Asset.objects.create(hostname="lt-1", managed=True, ip_address="10.0.0.4")
        self.shadow = Asset.objects.create(hostname="", ip_address="10.0.0.99", managed=False)

    def test_isolate_and_release(self):
        action = create_and_execute("isolate_host", None, asset=self.asset)
        self.assertEqual(action.status, ResponseAction.Status.SUCCEEDED)
        self.asset.refresh_from_db()
        self.assertTrue(self.asset.is_isolated)
        with self.assertRaises(ResponseError):
            create_and_execute("isolate_host", None, asset=self.asset)
        create_and_execute("release_host", None, asset=self.asset)
        self.asset.refresh_from_db()
        self.assertFalse(self.asset.is_isolated)

    def test_terminal_allowlist(self):
        self.assertEqual(parse_terminal_command("hash 'C:/Users/a b/x.exe'"), ("hash", ["C:/Users/a b/x.exe"]))
        for bad in ("rm -rf /", "ps; whoami", "ls $(id)", "kill abc", "ls", "x" * 600):
            with self.subTest(bad=bad), self.assertRaises(ResponseError):
                parse_terminal_command(bad)
        action = create_and_execute("terminal_command", None, asset=self.asset, parameters={"command": "help"})
        self.assertIn("memdump", action.output)

    def test_terminal_requires_agent(self):
        with self.assertRaises(ResponseError):
            create_and_execute("terminal_command", None, asset=self.shadow, parameters={"command": "ps"})

    def test_playbook_continues_past_optional_failure(self):
        ensure_default_playbooks()
        playbook = Playbook.objects.get(name="Contain compromised host")
        run = run_playbook(playbook, None, asset=self.shadow)
        self.assertEqual(run.status, ResponseAction.Status.SUCCEEDED, run.output)
        self.shadow.refresh_from_db()
        self.assertTrue(self.shadow.is_isolated)
        self.assertEqual(run.steps.count(), 2)  # forensics fails validation, isolate + notify run

    def test_block_indicator_feeds_blocklist_tag(self):
        indicator = make_indicator()
        create_and_execute("block_indicator", None, indicator=indicator)
        indicator.refresh_from_db()
        self.assertIn("blocked", indicator.tags)

    def test_disable_everyone_refused(self):
        with self.assertRaises(ResponseError):
            create_and_execute("disable_user", None, target_user="*")

    @override_settings(THREATDASH_RESPONSE_CONNECTOR="webhook", THREATDASH_RESPONSE_WEBHOOK_URL="",
                       THREATDASH_RESPONSE_WEBHOOK_SECRET="")
    def test_unconfigured_webhook_fails_safely(self):
        action = create_and_execute("isolate_host", None, asset=self.asset)
        self.assertEqual(action.status, ResponseAction.Status.FAILED)
        self.asset.refresh_from_db()
        self.assertFalse(self.asset.is_isolated, "a failed connector must not mark the host isolated")


class ComplianceTests(TestCase):
    def test_controls_evaluated_and_summarised(self):
        Asset.objects.create(hostname="a", managed=True, asset_type="laptop")
        Asset.objects.create(hostname="b", managed=False, asset_type="laptop")
        compliance.evaluate_controls()
        control = ComplianceControl.objects.get(framework="nist_csf", control_id="ID.AM-01")
        self.assertEqual(control.score, 50)
        self.assertEqual(control.status, "partial")
        frameworks = {f["framework"]: f for f in compliance.framework_summary()}
        self.assertEqual(set(frameworks), {"nist_csf", "iso27001", "soc2", "gdpr"})
        self.assertTrue(ComplianceControl.objects.filter(check_key="", status="manual").exists())

    def test_manual_override_kept(self):
        compliance.evaluate_controls()
        control = ComplianceControl.objects.filter(check_key="edr_coverage").first()
        control.manual_override, control.status = True, "not_applicable"
        control.save()
        compliance.evaluate_controls()
        control.refresh_from_db()
        self.assertEqual(control.status, "not_applicable")


class NaturalLanguageQueryTests(TestCase):
    def setUp(self):
        make_indicator("203.0.113.1", severity=4, country="RU")
        make_indicator("203.0.113.2", severity=4, country="RU")
        make_indicator("203.0.113.3", severity=4, country="CN")
        make_indicator("evil.example", "domain", severity=2, threat_type="phishing")

    def test_group_by_country(self):
        result = nlq.answer("top 5 countries with critical indicators in the last 7 days")
        self.assertEqual(result["spec"]["entity"], "indicators")
        self.assertEqual(result["spec"]["filters"]["severity_min"], 4)
        self.assertEqual(result["spec"]["group_by"], "country")
        self.assertEqual(result["series"][0], {"label": "RU", "value": 2})
        self.assertEqual(result["engine"], "keyword")

    def test_filters_and_table(self):
        result = nlq.answer("show phishing domains")
        self.assertEqual(result["chart"], "table")
        self.assertEqual(result["total"], 1)

    def test_events_and_assets(self):
        ingest_events([{"domain": "identity", "event_type": "signin_failure", "outcome": "failure",
                        "username": "a@x.example", "country": "RU"}])
        spec = nlq.parse_question("failed sign-ins by country in the last 24 hours")
        self.assertEqual((spec["entity"], spec["group_by"], spec["since_hours"]), ("events", "country", 24))
        self.assertEqual(nlq.answer("failed sign-ins by country")["series"][0]["label"], "RU")
        self.assertEqual(nlq.parse_question("list shadow IT devices")["filters"], {"managed": False})

    def test_validation_drops_unknown_fields(self):
        spec = nlq.validate_spec({"entity": "indicators; DROP TABLE", "filters": {"value__regex": ".*"},
                                  "group_by": "password", "limit": 10_000})
        self.assertEqual(spec, {"entity": "alerts", "filters": {}, "since_hours": None, "group_by": None,
                                "limit": None})

    def test_empty_question(self):
        with self.assertRaises(ValueError):
            nlq.answer("  ")

    def test_trend(self):
        self.assertEqual(nlq.answer("indicator trend over time")["chart"], "line")
        self.assertEqual(Incident.objects.count() + Indicator.objects.count(), 4)


class LLMTranslationTests(TestCase):
    def _response(self, text, stop_reason="end_turn"):
        from types import SimpleNamespace

        return SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)])

    def test_claude_spec_is_validated_and_used(self):
        import json
        from unittest import mock

        make_indicator("203.0.113.1", severity=4, country="RU")
        spec = {"entity": "indicators", "since_hours": None, "group_by": "country", "limit": 5,
                "filters": {"severity_min": 4, "status": None, "value__regex": ".*"}}
        with override_settings(ANTHROPIC_API_KEY="test-key"), mock.patch("anthropic.Anthropic") as client_cls:
            client_cls.return_value.beta.messages.create.return_value = self._response(json.dumps(spec))
            result = nlq.answer("where do critical indicators come from?")
        self.assertEqual(result["engine"], "claude")
        self.assertEqual(result["spec"]["filters"], {"severity_min": 4})
        self.assertEqual(result["series"][0]["label"], "RU")
        kwargs = client_cls.return_value.beta.messages.create.call_args.kwargs
        self.assertEqual(kwargs["output_config"]["format"]["type"], "json_schema")

    def test_refusal_or_error_falls_back_to_keywords(self):
        from unittest import mock

        with override_settings(ANTHROPIC_API_KEY="test-key"), mock.patch("anthropic.Anthropic") as client_cls:
            client_cls.return_value.beta.messages.create.return_value = self._response("", "refusal")
            self.assertEqual(nlq.answer("open alerts by severity")["engine"], "keyword")
            client_cls.return_value.beta.messages.create.side_effect = TypeError("old SDK")
            self.assertEqual(nlq.answer("open alerts by severity")["engine"], "keyword")
