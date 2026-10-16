import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from threats import bootstrap
from threats.models import Report

from .base import APIBase, make_indicator


class CronEndpointTests(APIBase):
    def setUp(self):
        super().setUp()
        self.client.force_authenticate(None)

    @override_settings(CRON_SECRET="")
    def test_disabled_without_secret(self):
        self.assertEqual(self.client.get("/api/cron/run/", HTTP_AUTHORIZATION="Bearer ").status_code, 404)

    @override_settings(CRON_SECRET="s3cret")
    def test_rejects_wrong_secret_and_runs_with_right_one(self):
        self.assertEqual(self.client.get("/api/cron/run/").status_code, 404)
        self.assertEqual(self.client.get("/api/cron/run/", HTTP_AUTHORIZATION="Bearer nope").status_code, 404)
        response = self.client.get("/api/cron/run/", HTTP_AUTHORIZATION="Bearer s3cret")
        self.assertEqual(response.status_code, 200)
        self.assertIn("maintenance", response.data)
        self.assertEqual(response.data["feeds"], [])  # feeds ship disabled


@override_settings(THREATDASH_STORE_REPORTS_IN_DB=True)
class DatabaseReportStorageTests(APIBase):
    def test_report_bytes_stored_in_database_and_downloadable(self):
        make_indicator("203.0.113.1", severity=4)
        response = self.client.post("/api/reports/", {"name": "Serverless", "file_format": "pdf"}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        report = Report.objects.get()
        self.assertFalse(report.report_file)
        self.assertTrue(report.content_filename.endswith(".pdf"))
        download = self.client.get(response.data["download_url"])
        self.assertEqual(download.status_code, 200)
        self.assertTrue(download.content.startswith(b"%PDF"))
        self.assertIn(report.content_filename, download["Content-Disposition"])
        listing = self.client.get("/api/reports/")
        self.assertEqual(listing.data["results"][0]["download_url"], response.data["download_url"])


class BootstrapTests(TestCase):
    def setUp(self):
        bootstrap._done = False

    def test_creates_superuser_once_and_never_resets_password(self):
        env = {"DJANGO_SUPERUSER_USERNAME": "boss", "DJANGO_SUPERUSER_PASSWORD": "First-pass-123"}
        with mock.patch.dict(os.environ, env):
            user = bootstrap.ensure_superuser()
        self.assertTrue(user.is_superuser)
        self.assertEqual(set(user.groups.values_list("name", flat=True)), {"responders", "forensics"})
        with mock.patch.dict(os.environ, {**env, "DJANGO_SUPERUSER_PASSWORD": "Changed-pass-456"}):
            self.assertIsNone(bootstrap.ensure_superuser())
        self.assertTrue(get_user_model().objects.get(username="boss").check_password("First-pass-123"))

    def test_no_env_no_user(self):
        with mock.patch.dict(os.environ, {"DJANGO_SUPERUSER_USERNAME": "", "DJANGO_SUPERUSER_PASSWORD": ""}):
            self.assertIsNone(bootstrap.ensure_superuser())

    @override_settings(THREATDASH_AUTO_MIGRATE=True)
    def test_bootstrap_runs_migrate_once(self):
        with mock.patch.object(bootstrap, "call_command") as call:
            bootstrap.bootstrap()
            bootstrap.bootstrap()
        call.assert_called_once_with("migrate", interactive=False, verbosity=0)

    @override_settings(THREATDASH_AUTO_MIGRATE=True)
    def test_bootstrap_failure_does_not_raise(self):
        with mock.patch.object(bootstrap, "call_command", side_effect=RuntimeError("db down")):
            bootstrap.bootstrap()
        self.assertFalse(bootstrap._done)

    @override_settings(THREATDASH_AUTO_MIGRATE=False)
    def test_disabled_by_default_off_serverless(self):
        with mock.patch.object(bootstrap, "call_command") as call:
            bootstrap.bootstrap()
        call.assert_not_called()
