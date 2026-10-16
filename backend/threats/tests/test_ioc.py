from django.test import SimpleTestCase

from threats.services.enrichment import dga_score, enrich
from threats.services.ioc import IOCError, defang, detect_type, is_internal_ip, normalize, parse_indicator, refang


class IOCParsingTests(SimpleTestCase):
    def test_refang_common_styles(self):
        self.assertEqual(refang("hxxps://evil[.]example/path"), "https://evil.example/path")
        self.assertEqual(refang("evil(.)example"), "evil.example")
        self.assertEqual(refang("bad[@]mail[.]example"), "bad@mail.example")
        self.assertEqual(refang("1.2.3[.]4"), "1.2.3.4")

    def test_detect_types(self):
        cases = {
            "203.0.113.5": "ipv4", "2001:db8::1": "ipv6", "evil.example": "domain",
            "https://evil.example/a": "url", "d41d8cd98f00b204e9800998ecf8427e": "md5",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1", "a" * 64: "sha256",
            "phish@evil.example": "email", "cve-2024-3400": "cve",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(detect_type(value), expected)

    def test_unknown_value_raises(self):
        with self.assertRaises(IOCError):
            detect_type("not an indicator")

    def test_normalization(self):
        self.assertEqual(normalize("domain", "EVIL.Example."), "evil.example")
        self.assertEqual(normalize("sha256", "A" * 64), "a" * 64)
        self.assertEqual(normalize("cve", "cve-2024-3400"), "CVE-2024-3400")
        self.assertEqual(normalize("ipv6", "2001:0db8:0000::0001"), "2001:db8::1")
        self.assertEqual(normalize("url", "HTTPS://Evil.Example/Path"), "https://evil.example/Path")

    def test_type_mismatch_rejected(self):
        with self.assertRaises(IOCError):
            normalize("ipv4", "2001:db8::1")
        with self.assertRaises(IOCError):
            normalize("md5", "abc")

    def test_type_aliases(self):
        self.assertEqual(parse_indicator("10.0.0.1", "ip-dst"), ("ipv4", "10.0.0.1"))
        self.assertEqual(parse_indicator("evil.example", "domain-name"), ("domain", "evil.example"))

    def test_defang(self):
        self.assertEqual(defang("url", "http://evil.example"), "hxxp://evil[.]example")

    def test_internal_ip_excludes_documentation_ranges(self):
        self.assertTrue(is_internal_ip("10.1.2.3"))
        self.assertTrue(is_internal_ip("fd00::1"))
        self.assertFalse(is_internal_ip("203.0.113.5"))
        self.assertFalse(is_internal_ip("8.8.8.8"))


class EnrichmentTests(SimpleTestCase):
    def test_dga_heuristic_separates_random_from_dictionary_names(self):
        self.assertGreaterEqual(dga_score("xkqzjwvbtrplmn7q.example"), 0.6)
        self.assertLess(dga_score("google.com"), 0.3)
        self.assertEqual(dga_score("abc.com"), 0.0)

    def test_ip_enrichment(self):
        data = enrich("ipv4", "10.1.2.3")
        self.assertEqual(data["network"], "10.1.2.0/24")
        self.assertTrue(data["is_private"])

    def test_url_enrichment_flags(self):
        data = enrich("url", "http://203.0.113.9/login/invoice.exe")
        self.assertTrue(data["host_is_ip"])
        self.assertTrue(data["executable_download"])
        self.assertTrue(data["credential_lure"])
