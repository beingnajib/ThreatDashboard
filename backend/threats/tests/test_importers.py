import json

from django.test import TestCase

from threats.models import ImportJob, Indicator
from threats.services.importers import detect_format, normalize_record, parse_timestamp, run_import


def run(content, filename="feed.csv", fmt="", **kwargs):
    job = ImportJob.objects.create(filename=filename, file_format=fmt)
    return run_import(job, content.encode() if isinstance(content, str) else content, **kwargs)


class ImporterTests(TestCase):
    def test_csv_with_aliases_and_legacy_columns(self):
        csv = ("indicator,threat_type,threat_level,date_detected,tags\n"
               "203.0.113.9,c2,9,2026-09-01,cobalt;beacon\n"
               "hxxp://evil[.]example/x,phishing,5,2026-09-02 10:00,\n")
        job = run(csv)
        self.assertEqual(job.status, ImportJob.Status.COMPLETED, job.errors)
        self.assertEqual(job.created_count, 2)
        ip = Indicator.objects.get(value="203.0.113.9")
        self.assertEqual(ip.severity, 4)
        self.assertEqual(ip.tags, ["cobalt", "beacon"])
        self.assertTrue(Indicator.objects.filter(ioc_type="url", value="http://evil.example/x").exists())

    def test_bad_rows_are_reported_not_fatal(self):
        job = run("value,severity\n203.0.113.1,high\nnot-an-ioc,low\n203.0.113.2,bogus\n")
        self.assertEqual(job.status, ImportJob.Status.COMPLETED_WITH_ERRORS)
        self.assertEqual(job.created_count, 1)
        self.assertEqual(job.error_count, 2)
        self.assertEqual({e["row"] for e in job.errors}, {2, 3})

    def test_reimport_merges_sightings(self):
        run("value,severity,tags\nevil.example,medium,a\n")
        job = run("value,severity,tags\nevil.example,critical,b\n")
        self.assertEqual(job.updated_count, 1)
        indicator = Indicator.objects.get(value="evil.example")
        self.assertEqual(indicator.sighting_count, 2)
        self.assertEqual(indicator.severity, 4)
        self.assertEqual(indicator.tags, ["a", "b"])

    def test_json_wrapped_list(self):
        data = {"indicators": [{"value": "a" * 64, "type": "sha256", "confidence": 0.9}, "evil.test"]}
        job = run(json.dumps(data), "x.json")
        self.assertEqual(job.created_count, 2, job.errors)
        self.assertEqual(Indicator.objects.get(ioc_type="sha256").confidence, 90)

    def test_json_lines(self):
        job = run('{"value": "203.0.113.5"}\n{"value": "203.0.113.6"}\n', "x.jsonl")
        self.assertEqual(job.created_count, 2)

    def test_stix_bundle(self):
        bundle = {"type": "bundle", "id": "bundle--1", "objects": [
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.7']",
             "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z", "labels": ["botnet"],
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}]},
            {"type": "indicator", "id": "indicator--2",
             "pattern": "[file:hashes.'SHA-256' = '" + "b" * 64 + "']", "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "malware", "id": "malware--1", "name": "ignored"},
        ]}
        job = run(json.dumps(bundle), "bundle.json")
        self.assertEqual(job.file_format, ImportJob.Format.STIX)
        self.assertEqual(job.created_count, 2, job.errors)
        self.assertEqual(Indicator.objects.get(value="198.51.100.7").mitre_techniques, ["T1071"])

    def test_xml(self):
        xml = ("<feed><indicators><indicator><value>evil.example</value><threat>phishing</threat>"
               "<severity>high</severity></indicator><indicator type='ipv4'><value>203.0.113.77</value>"
               "</indicator></indicators></feed>")
        job = run(xml, "f.xml")
        self.assertEqual(job.created_count, 2, job.errors)
        self.assertEqual(Indicator.objects.get(value="evil.example").threat_type, "phishing")

    def test_xml_entity_expansion_blocked(self):
        xml = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feed><indicator>&a;</indicator></feed>'
        job = run(xml, "bomb.xml")
        self.assertEqual(job.status, ImportJob.Status.FAILED)

    def test_plain_text_with_comments_and_defaults(self):
        text = "# comment\n203.0.113.50\nevil[.]example # trailing note\n\n"
        job = run(text, "list.txt", defaults={"threat_type": "botnet", "severity": 3})
        self.assertEqual(job.created_count, 2, job.errors)
        self.assertTrue(all(i.threat_type == "botnet" and i.severity == 3 for i in Indicator.objects.all()))

    def test_invalid_json_fails_cleanly(self):
        job = run("[{bad json", "x.json")
        self.assertEqual(job.status, ImportJob.Status.FAILED)
        self.assertEqual(Indicator.objects.count(), 0)

    def test_empty_file(self):
        self.assertEqual(run("", "x.txt").status, ImportJob.Status.FAILED)

    def test_detect_format(self):
        self.assertEqual(detect_format("a.csv", "x,y"), "csv")
        self.assertEqual(detect_format("upload", '{"type": "bundle", "objects": []}'), "stix")
        self.assertEqual(detect_format("upload", "<root/>"), "xml")
        self.assertEqual(detect_format("upload", "1.2.3.4\n"), "text")

    def test_type_column_naming_a_threat(self):
        data = normalize_record({"indicator": "203.0.113.4", "type": "malware"})
        self.assertEqual((data["ioc_type"], data["threat_type"]), ("ipv4", "malware"))

    def test_timestamps(self):
        self.assertEqual(parse_timestamp("1700000000").year, 2023)
        self.assertEqual(parse_timestamp("2026-03-04").day, 4)
        self.assertEqual(parse_timestamp("04/03/2026").month, 3)
