import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token

from threats.models import Asset, TelemetryEvent, ThreatFeed
from threats.services.feeds import pull_feed
from threats.services.netsafety import UnsafeURLError, safe_urlopen, validate_outbound_url
from threats.services.response import create_and_execute
from threats.services.telemetry import ingest_events

from .base import APIBase


class _RedirectHandler(BaseHTTPRequestHandler):
    target = "file:///etc/passwd"

    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


class LocalRedirectServer:
    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}/"

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class OutboundURLTests(SimpleTestCase):
    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x"):
            with self.subTest(url=url), self.assertRaises(UnsafeURLError):
                validate_outbound_url(url, allow_private=True)

    def test_rejects_internal_destinations_by_default(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/",
                    "http://[::1]/", "http://localhost/"):
            with self.subTest(url=url), self.assertRaises(UnsafeURLError):
                validate_outbound_url(url)
        validate_outbound_url("http://127.0.0.1/", allow_private=True)

    def test_redirect_to_file_scheme_blocked(self):
        with LocalRedirectServer() as url:
            with self.assertRaisesRegex(urllib.error.HTTPError, "not allowed|Blocked redirect"):
                safe_urlopen(urllib.request.Request(url), timeout=5, allow_private=True)

    def test_redirect_to_metadata_service_blocked(self):
        """A public-looking feed that redirects into the cloud metadata service is refused."""
        from unittest import mock

        from threats.services import netsafety

        real = netsafety.validate_outbound_url

        def validate(url, allow_private=False):
            # Treat the local test server as "public" so only the redirect hop is judged.
            return None if url.startswith("http://127.0.0.1:") else real(url, allow_private)

        _RedirectHandler.target = "http://169.254.169.254/latest/meta-data/"
        try:
            with LocalRedirectServer() as url, mock.patch.object(netsafety, "validate_outbound_url", validate):
                with self.assertRaisesRegex(urllib.error.HTTPError, "Blocked redirect.*169.254.169.254"):
                    safe_urlopen(urllib.request.Request(url), timeout=5)
        finally:
            _RedirectHandler.target = "file:///etc/passwd"

    def test_redirects_can_be_disabled(self):
        _RedirectHandler.target = "http://127.0.0.1/elsewhere"
        try:
            with LocalRedirectServer() as url:
                with self.assertRaisesRegex(Exception, "Redirects are not allowed"):
                    safe_urlopen(urllib.request.Request(url), timeout=5, allow_private=True, max_redirects=0)
        finally:
            _RedirectHandler.target = "file:///etc/passwd"


class FeedSSRFTests(TestCase):
    def test_feed_pointing_at_metadata_service_is_blocked(self):
        feed = ThreatFeed.objects.create(name="evil", url="http://169.254.169.254/latest/meta-data/", enabled=True)
        pull_feed(feed)
        feed.refresh_from_db()
        self.assertTrue(feed.last_status.startswith("Failed: Blocked"), feed.last_status)


class WebhookTests(TestCase):
    def test_webhook_refuses_redirects_and_leaves_host_unisolated(self):
        asset = Asset.objects.create(hostname="lt-1", managed=True)
        _RedirectHandler.target = "http://127.0.0.1/other"
        try:
            with LocalRedirectServer() as url, override_settings(
                THREATDASH_RESPONSE_CONNECTOR="webhook", THREATDASH_RESPONSE_WEBHOOK_URL=url,
                THREATDASH_RESPONSE_WEBHOOK_SECRET="s3cret",
            ):
                action = create_and_execute("isolate_host", None, asset=asset)
        finally:
            _RedirectHandler.target = "file:///etc/passwd"
        self.assertEqual(action.status, "failed")
        asset.refresh_from_db()
        self.assertFalse(asset.is_isolated)


class TokenExpiryTests(APIBase):
    def test_expired_token_rejected_and_login_rotates_it(self):
        self.client.force_authenticate(None)
        token = Token.objects.create(user=self.analyst)
        Token.objects.filter(pk=token.pk).update(created=timezone.now() - timedelta(hours=13))
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 401)
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())
        self.client.credentials()
        response = self.client.post("/api/auth/token/", {"username": "analyst", "password": "Analyst-pass-123"})
        self.assertNotEqual(response.data["token"], token.key)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {response.data['token']}")
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 200)

    def test_fresh_token_accepted(self):
        self.client.force_authenticate(None)
        token = Token.objects.create(user=self.analyst)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(self.client.get("/api/auth/me/").status_code, 200)


class InputValidationTests(APIBase):
    def test_actor_references_must_be_web_urls(self):
        bad = self.client.post("/api/actors/", {"name": "X", "references": ["javascript:alert(1)"]}, format="json")
        self.assertEqual(bad.status_code, 400)
        good = self.client.post("/api/actors/", {"name": "Y", "references": ["https://attack.mitre.org/groups/G0016/"]},
                                format="json")
        self.assertEqual(good.status_code, 201, good.data)

    def test_ingested_technique_ids_are_validated(self):
        ingest_events([{"domain": "endpoint", "event_type": "x", "mitre_technique": "<script>"},
                       {"domain": "endpoint", "event_type": "y", "mitre_technique": "t1059.001"}])
        self.assertEqual(sorted(TelemetryEvent.objects.values_list("mitre_technique", flat=True)), ["", "T1059.001"])


class ClientIPTests(APIBase):
    """The login throttle and audit log must key on the proxy-observed IP, not on client-set headers."""

    def setUp(self):
        super().setUp()
        from django.core.cache import cache

        cache.clear()
        self.client.force_authenticate(None)

    def _behind_proxy(self, num_proxies=1):
        from django.conf import settings

        return override_settings(REST_FRAMEWORK={**settings.REST_FRAMEWORK, "NUM_PROXIES": num_proxies})

    def test_spoofed_forwarded_for_does_not_bypass_login_throttle(self):
        from threats.models import AuditLog

        with self._behind_proxy():
            codes = []
            for i in range(12):
                # nginx appends the address it saw (198.51.100.7) after whatever the client sent.
                response = self.client.post("/api/auth/token/", {"username": "analyst", "password": "wrong"},
                                            HTTP_X_FORWARDED_FOR=f"203.0.113.{i}, 198.51.100.7")
                codes.append(response.status_code)
        self.assertIn(429, codes)
        ips = set(AuditLog.objects.filter(action="auth.login_failed").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"198.51.100.7"})

    def test_forwarded_for_ignored_when_not_behind_proxy(self):
        from django.test import RequestFactory

        from threats.services.audit import client_ip

        request = RequestFactory().get("/", HTTP_X_FORWARDED_FOR="203.0.113.9", REMOTE_ADDR="192.0.2.1")
        with self._behind_proxy(0):
            self.assertEqual(client_ip(request), "192.0.2.1")
        with self._behind_proxy(2):
            request.META["HTTP_X_FORWARDED_FOR"] = "6.6.6.6, 203.0.113.9, 10.0.0.2"
            self.assertEqual(client_ip(request), "203.0.113.9")
