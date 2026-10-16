"""Indicator exports: CSV, JSON and STIX 2.1."""
import csv
import io
import json
import uuid

from django.utils import timezone

from ..models import IOCType

EXPORT_FIELDS = [
    "value", "ioc_type", "threat_type", "severity", "confidence", "risk_score", "status", "tlp",
    "source", "tags", "mitre_techniques", "country", "first_seen", "last_seen", "sighting_count", "description",
]
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
STIX_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL namespace
TLP_MARKINGS = {
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber_strict": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


def safe_cell(value):
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def indicator_row(indicator):
    return {
        "value": indicator.value,
        "ioc_type": indicator.ioc_type,
        "threat_type": indicator.threat_type,
        "severity": indicator.get_severity_display(),
        "confidence": indicator.confidence,
        "risk_score": indicator.risk_score,
        "status": indicator.status,
        "tlp": indicator.tlp,
        "source": indicator.source.name if indicator.source_id else "",
        "tags": ", ".join(indicator.tags or []),
        "mitre_techniques": ", ".join(indicator.mitre_techniques or []),
        "country": indicator.country,
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else "",
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else "",
        "sighting_count": indicator.sighting_count,
        "description": indicator.description,
    }


def to_csv(indicators):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_FIELDS)
    writer.writeheader()
    for indicator in indicators:
        writer.writerow({k: safe_cell(v) for k, v in indicator_row(indicator).items()})
    return buffer.getvalue()


def to_json(indicators):
    rows = []
    for indicator in indicators:
        row = indicator_row(indicator)
        row["tags"] = indicator.tags
        row["mitre_techniques"] = indicator.mitre_techniques
        row["severity"] = indicator.severity
        rows.append(row)
    return json.dumps({"generated_at": timezone.now().isoformat(), "count": len(rows), "indicators": rows}, indent=2)


def _stix_escape(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(indicator):
    value = _stix_escape(indicator.value)
    patterns = {
        IOCType.IPV4: f"[ipv4-addr:value = '{value}']",
        IOCType.IPV6: f"[ipv6-addr:value = '{value}']",
        IOCType.DOMAIN: f"[domain-name:value = '{value}']",
        IOCType.URL: f"[url:value = '{value}']",
        IOCType.EMAIL: f"[email-addr:value = '{value}']",
        IOCType.MD5: f"[file:hashes.MD5 = '{value}']",
        IOCType.SHA1: f"[file:hashes.'SHA-1' = '{value}']",
        IOCType.SHA256: f"[file:hashes.'SHA-256' = '{value}']",
    }
    return patterns.get(indicator.ioc_type)


def _stix_time(dt):
    return dt.astimezone(timezone.get_fixed_timezone(0)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_stix(indicators, identity_name="ThreatDashboard"):
    now = _stix_time(timezone.now())
    identity_id = f"identity--{uuid.uuid5(STIX_NAMESPACE, 'threatdashboard:' + identity_name)}"
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": identity_name, "identity_class": "system",
    }]
    for indicator in indicators:
        if indicator.ioc_type == IOCType.CVE:
            stix_object = {
                "type": "vulnerability", "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid5(STIX_NAMESPACE, 'cve:' + indicator.value)}",
                "created": _stix_time(indicator.created_at), "modified": _stix_time(indicator.updated_at),
                "name": indicator.value, "created_by_ref": identity_id,
                "external_references": [{"source_name": "cve", "external_id": indicator.value}],
            }
        else:
            stix_object = {
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, f'{indicator.ioc_type}:{indicator.value}')}",
                "created": _stix_time(indicator.created_at), "modified": _stix_time(indicator.updated_at),
                "created_by_ref": identity_id,
                "name": f"{indicator.get_threat_type_display()} {indicator.get_ioc_type_display()}",
                "description": indicator.description or "",
                "indicator_types": ["malicious-activity"],
                "pattern": stix_pattern(indicator), "pattern_type": "stix",
                "valid_from": _stix_time(indicator.first_seen),
                "confidence": indicator.confidence,
                "labels": list(indicator.tags or []) + [indicator.threat_type],
            }
            if indicator.expires_at and indicator.expires_at > indicator.first_seen:
                stix_object["valid_until"] = _stix_time(indicator.expires_at)
            if indicator.mitre_techniques:
                stix_object["external_references"] = [
                    {"source_name": "mitre-attack", "external_id": technique,
                     "url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"}
                    for technique in indicator.mitre_techniques
                ]
        if indicator.tlp in TLP_MARKINGS:
            stix_object["object_marking_refs"] = [TLP_MARKINGS[indicator.tlp]]
        objects.append(stix_object)
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2)
