"""Parsing and ingestion of threat intelligence files.

Supported formats: CSV, JSON (list, ``{"indicators": [...]}`` or JSON Lines),
XML, STIX 2.1 bundles and plain text (one indicator per line, defanged
values are accepted). Column names are matched against a list of common
aliases so exports from most feeds and SIEMs import without remapping.
"""
import csv
import io
import json
import logging
import re
from datetime import datetime, time, timedelta
from datetime import timezone as dt_timezone

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from ..models import TLP, ImportJob, Indicator, IOCType, Severity, Source, ThreatType
from .ioc import IOCError, normalize_mitre, normalize_tags, parse_indicator, resolve_type_alias
from .rules import evaluate_indicators

logger = logging.getLogger(__name__)

MAX_STORED_ERRORS = 100

FIELD_ALIASES = {
    "value": ("value", "indicator", "ioc", "observable", "ioc_value", "indicator_value", "artifact"),
    "ioc_type": ("ioc_type", "type", "indicator_type", "observable_type", "kind"),
    "threat_type": ("threat_type", "category", "threat", "classification", "threat_category", "malware_type"),
    "severity": ("severity", "priority", "risk"),
    "threat_level": ("threat_level", "level", "score"),
    "confidence": ("confidence", "confidence_score", "reliability_score"),
    "tags": ("tags", "labels", "tag"),
    "mitre_techniques": ("mitre_techniques", "mitre", "techniques", "technique", "attack_id", "ttp", "ttps"),
    "first_seen": ("first_seen", "date_detected", "detected", "date", "timestamp", "created", "valid_from"),
    "last_seen": ("last_seen", "modified", "updated", "last_observed"),
    "expires_at": ("expires_at", "valid_until", "expiration", "expires"),
    "description": ("description", "comment", "notes", "details", "name"),
    "country": ("country", "country_code", "geo"),
    "tlp": ("tlp", "marking", "tlp_level"),
    "source": ("source", "feed", "provider", "reporter"),
}
TYPE_SPECIFIC_VALUE_COLUMNS = {
    "ip": None, "ip_address": None, "ipv4": IOCType.IPV4, "ipv6": IOCType.IPV6, "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN, "url": IOCType.URL, "md5": IOCType.MD5, "sha1": IOCType.SHA1,
    "sha256": IOCType.SHA256, "email": IOCType.EMAIL, "cve": IOCType.CVE, "hash": None,
}
SEVERITY_NAMES = {
    "info": Severity.LOW, "informational": Severity.LOW, "low": Severity.LOW,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "med": Severity.MEDIUM,
    "high": Severity.HIGH, "severe": Severity.HIGH,
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL, "urgent": Severity.CRITICAL,
}
THREAT_TYPE_ALIASES = {
    "c&c": ThreatType.C2, "cnc": ThreatType.C2, "c2": ThreatType.C2, "command_and_control": ThreatType.C2,
    "command-and-control": ThreatType.C2, "trojan": ThreatType.MALWARE, "virus": ThreatType.MALWARE,
    "worm": ThreatType.MALWARE, "stealer": ThreatType.MALWARE, "infostealer": ThreatType.MALWARE,
    "loader": ThreatType.MALWARE, "malicious-activity": ThreatType.MALWARE, "rat": ThreatType.MALWARE,
    "scan": ThreatType.SCANNER, "scanning": ThreatType.SCANNER, "recon": ThreatType.SCANNER,
    "bruteforce": ThreatType.BRUTE_FORCE, "brute-force": ThreatType.BRUTE_FORCE,
    "exfiltration": ThreatType.DATA_EXFIL, "exfil": ThreatType.DATA_EXFIL, "vulnerability": ThreatType.EXPLOIT,
    "attribution": ThreatType.APT, "apt": ThreatType.APT, "anomalous-activity": ThreatType.OTHER,
    "compromised": ThreatType.OTHER,
}
TLP_ALIASES = {
    "white": TLP.CLEAR, "clear": TLP.CLEAR, "green": TLP.GREEN, "amber": TLP.AMBER,
    "amber+strict": TLP.AMBER_STRICT, "amber_strict": TLP.AMBER_STRICT, "red": TLP.RED,
}
STIX_PATTERN_RE = re.compile(
    r"\[\s*(?P<object>ipv4-addr|ipv6-addr|domain-name|url|email-addr|file)"
    r":(?P<path>value|hashes\.(?:'(?P<q1>[^']+)'|\"(?P<q2>[^\"]+)\"|(?P<bare>[A-Za-z0-9-]+)))"
    r"\s*=\s*'(?P<value>(?:\\'|[^'])+)'\s*\]"
)
STIX_OBJECT_TYPES = {
    "ipv4-addr": IOCType.IPV4, "ipv6-addr": IOCType.IPV6, "domain-name": IOCType.DOMAIN,
    "url": IOCType.URL, "email-addr": IOCType.EMAIL,
}
STIX_HASH_TYPES = {"md5": IOCType.MD5, "sha-1": IOCType.SHA1, "sha1": IOCType.SHA1,
                   "sha-256": IOCType.SHA256, "sha256": IOCType.SHA256}


class ImportFormatError(ValueError):
    """The file as a whole could not be parsed."""


class RecordError(ValueError):
    """A single record is invalid; the import continues with the next one."""


# --------------------------------------------------------------------------- #
# Format detection and parsing
# --------------------------------------------------------------------------- #

def detect_format(filename, head):
    name = (filename or "").lower()
    stripped = head.lstrip()
    if name.endswith((".stix", ".stix2")):
        return ImportJob.Format.STIX
    if name.endswith((".json", ".jsonl", ".ndjson")) or stripped.startswith(("{", "[")):
        if re.search(r'"type"\s*:\s*"bundle"', head):
            return ImportJob.Format.STIX
        return ImportJob.Format.JSON
    if name.endswith(".xml") or stripped.startswith("<"):
        return ImportJob.Format.XML
    if name.endswith((".csv", ".tsv")):
        return ImportJob.Format.CSV
    first_line = stripped.splitlines()[0] if stripped else ""
    if "," in first_line or "\t" in first_line:
        return ImportJob.Format.CSV
    return ImportJob.Format.TEXT


def decode_bytes(raw):
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(encoding)
            if "\x00" not in text:
                return text
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def parse_csv(text):
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise ImportFormatError("The CSV file has no header row.")
    for row in reader:
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue
        yield {k.strip(): v for k, v in row.items() if k}


def parse_json(text):
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # JSON Lines / NDJSON
        records = []
        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ImportFormatError(f"Invalid JSON on line {number}: {exc.msg}.") from exc
        data = records
    if isinstance(data, dict):
        if data.get("type") == "bundle":
            yield from parse_stix_objects(data)
            return
        for key in ("indicators", "data", "results", "items", "iocs", "objects"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        raise ImportFormatError("JSON must be a list of indicator objects.")
    for item in data:
        if isinstance(item, str):
            yield {"value": item}
        elif isinstance(item, dict):
            yield item
        else:
            yield {"__error__": "Record is not an object."}


RECORD_TAGS = {"indicator", "ioc", "threat", "record", "item", "row", "entry"}


def parse_xml(text):
    try:
        root = ElementTree.fromstring(text.encode("utf-8"))
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ImportFormatError(f"Invalid or unsafe XML: {exc}") from exc

    def local(tag):
        return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""

    # Descend through single wrapper elements (<feed><indicators><indicator/>...)
    # until we reach the level that holds the records themselves.
    container = root
    while len(container) == 1 and len(container[0]) and local(container[0].tag) not in RECORD_TAGS:
        container = container[0]
    records = list(container)
    for element in records:
        record = {local(k): v for k, v in element.attrib.items()}
        children = list(element)
        if not children and (element.text or "").strip():
            record.setdefault("value", element.text.strip())
        for child in children:
            name = local(child.tag)
            grand = list(child)
            if grand:
                record[name] = [(g.text or "").strip() for g in grand if (g.text or "").strip()]
            else:
                record[name] = (child.text or "").strip()
        yield record


def _stix_pattern_values(pattern):
    for match in STIX_PATTERN_RE.finditer(pattern or ""):
        obj = match.group("object")
        value = match.group("value").replace("\\'", "'")
        if obj == "file":
            algo = (match.group("q1") or match.group("q2") or match.group("bare") or "").lower()
            ioc_type = STIX_HASH_TYPES.get(algo)
            if ioc_type:
                yield ioc_type, value
        else:
            yield STIX_OBJECT_TYPES[obj], value


def parse_stix_objects(bundle):
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ImportFormatError("STIX bundle has no 'objects' list.")
    markings = {
        o.get("id"): (o.get("definition") or {}).get("tlp") or o.get("name", "")
        for o in objects if isinstance(o, dict) and o.get("type") == "marking-definition"
    }
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("revoked"):
            continue
        matches = list(_stix_pattern_values(obj.get("pattern")))
        if not matches:
            yield {"__error__": f"Unsupported STIX pattern in {obj.get('id', 'indicator')}."}
            continue
        techniques = [
            ref.get("external_id") for ref in obj.get("external_references", []) or []
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
        ]
        labels = list(obj.get("labels") or []) + list(obj.get("indicator_types") or [])
        tlp = ""
        for ref in obj.get("object_marking_refs") or []:
            tlp = str(markings.get(ref, "")).lower().replace("tlp:", "") or tlp
        for ioc_type, value in matches:
            yield {
                "value": value,
                "ioc_type": ioc_type,
                "threat_type": (obj.get("indicator_types") or [""])[0],
                "confidence": obj.get("confidence"),
                "tags": labels,
                "mitre_techniques": techniques,
                "first_seen": obj.get("valid_from") or obj.get("created"),
                "last_seen": obj.get("modified"),
                "expires_at": obj.get("valid_until"),
                "description": obj.get("description") or obj.get("name") or "",
                "tlp": tlp,
            }


def parse_stix(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportFormatError(f"Invalid STIX JSON: {exc.msg}.") from exc
    yield from parse_stix_objects(data)


def parse_text(text):
    for line in text.splitlines():
        line = re.split(r"\s+#", line.strip(), maxsplit=1)[0].strip()
        if line and not line.startswith(("#", "//", ";")):
            yield {"value": line}


PARSERS = {
    ImportJob.Format.CSV: parse_csv,
    ImportJob.Format.JSON: parse_json,
    ImportJob.Format.XML: parse_xml,
    ImportJob.Format.STIX: parse_stix,
    ImportJob.Format.TEXT: parse_text,
}


# --------------------------------------------------------------------------- #
# Record normalisation
# --------------------------------------------------------------------------- #

def _pick(record, field):
    for alias in FIELD_ALIASES[field]:
        if alias in record and record[alias] not in (None, "", []):
            return record[alias]
    return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return re.split(r"[,;|]", str(value))


def parse_timestamp(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**11 else value
        parsed = datetime.fromtimestamp(seconds, tz=dt_timezone.utc)
    else:
        text = str(value).strip()
        if re.fullmatch(r"\d{9,13}", text):
            return parse_timestamp(int(text))
        parsed = parse_datetime(text.replace(" UTC", "").replace("Z", "+00:00"))
        if parsed is None:
            day = parse_date(text)
            if day is None:
                for fmt in ("%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d", "%d-%m-%Y", "%Y-%m-%d %H:%M"):
                    try:
                        parsed = datetime.strptime(text, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    raise RecordError(f"Unrecognised date {text[:40]!r}.")
            else:
                parsed = datetime.combine(day, time.min)
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_default_timezone())
    return parsed


def parse_severity(record):
    raw = _pick(record, "severity")
    if raw is not None:
        text = str(raw).strip().lower()
        if text in SEVERITY_NAMES:
            return SEVERITY_NAMES[text]
        try:
            number = int(float(text))
        except ValueError as exc:
            raise RecordError(f"Unrecognised severity {raw!r}.") from exc
        return min(max(number, 1), 4)
    level = _pick(record, "threat_level")
    if level is not None:
        text = str(level).strip().lower()
        if text in SEVERITY_NAMES:
            return SEVERITY_NAMES[text]
        try:
            number = float(text)
        except ValueError as exc:
            raise RecordError(f"Unrecognised threat level {level!r}.") from exc
        # threat_level is a 1-10 scale (legacy ThreatData model) or 0-100 score.
        if number > 10:
            number = number / 10
        if number >= 9:
            return Severity.CRITICAL
        if number >= 6:
            return Severity.HIGH
        if number >= 4:
            return Severity.MEDIUM
        return Severity.LOW
    return None


def parse_threat_type(raw):
    if not raw:
        return None
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else ""
    key = str(raw).strip().lower().replace(" ", "_")
    if key in ThreatType.values:
        return key
    return THREAT_TYPE_ALIASES.get(key, ThreatType.OTHER)


def normalize_record(record):
    """Turn a raw parsed record into validated keyword arguments for Indicator."""
    if "__error__" in record:
        raise RecordError(record["__error__"])
    record = {str(k).strip().lower().replace(" ", "_").replace("-", "_"): v for k, v in record.items()}

    raw_value = _pick(record, "value")
    type_hint = _pick(record, "ioc_type")
    if raw_value is None:
        for column, column_type in TYPE_SPECIFIC_VALUE_COLUMNS.items():
            if record.get(column):
                raw_value, type_hint = record[column], type_hint or column_type
                break
    if raw_value is None:
        raise RecordError("Missing indicator value.")
    raw_value = str(raw_value)

    try:
        hint = resolve_type_alias(str(type_hint), raw_value) if type_hint else None
        # A type column that names something we don't track (e.g. "malware") is
        # treated as a threat type instead, and the IOC type is detected.
        if hint and hint not in IOCType.values:
            record.setdefault("threat_type", hint)
            hint = None
        ioc_type, value = parse_indicator(raw_value, hint)
    except IOCError as exc:
        raise RecordError(str(exc)) from exc

    data = {"ioc_type": ioc_type, "value": value}
    severity = parse_severity(record)
    if severity:
        data["severity"] = severity
    threat_type = parse_threat_type(_pick(record, "threat_type"))
    if threat_type:
        data["threat_type"] = threat_type
    confidence = _pick(record, "confidence")
    if confidence is not None:
        try:
            number = float(confidence)
        except (TypeError, ValueError) as exc:
            raise RecordError(f"Confidence must be a number, got {confidence!r}.") from exc
        if 0 < number <= 1 and "." in str(confidence):
            number *= 100
        data["confidence"] = int(min(max(number, 0), 100))
    data["tags"] = normalize_tags(_as_list(_pick(record, "tags")))
    data["mitre_techniques"] = normalize_mitre(_as_list(_pick(record, "mitre_techniques")))
    for field in ("first_seen", "last_seen", "expires_at"):
        stamp = parse_timestamp(_pick(record, field))
        if stamp:
            data[field] = stamp
    description = _pick(record, "description")
    if description:
        data["description"] = str(description)[:5000]
    country = _pick(record, "country")
    if country and re.fullmatch(r"[A-Za-z]{2}", str(country).strip()):
        data["country"] = str(country).strip().upper()
    tlp = _pick(record, "tlp")
    if tlp:
        data["tlp"] = TLP_ALIASES.get(str(tlp).strip().lower().replace("tlp:", ""), TLP.AMBER)
    source_name = _pick(record, "source")
    if source_name:
        data["source_name"] = str(source_name).strip()[:120]
    return data


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def upsert_indicator(data, source=None, user=None):
    """Create the indicator or merge the new sighting into the existing one.

    Returns ``(indicator, created)``.
    """
    data = dict(data)
    source_name = data.pop("source_name", None)
    if source_name:
        source, _ = Source.objects.get_or_create(name=source_name, defaults={"kind": Source.Kind.FEED})
    now = timezone.now()
    lookup = {"ioc_type": data.pop("ioc_type"), "value": data.pop("value")}
    indicator = Indicator.objects.select_for_update().filter(**lookup).first()

    if indicator is None:
        data.setdefault("first_seen", data.get("last_seen") or now)
        data.setdefault("last_seen", data["first_seen"])
        if "expires_at" not in data and settings.THREATDASH_DEFAULT_INDICATOR_TTL_DAYS:
            data["expires_at"] = data["last_seen"] + timedelta(days=settings.THREATDASH_DEFAULT_INDICATOR_TTL_DAYS)
        try:
            with transaction.atomic():
                indicator = Indicator.objects.create(**lookup, **data, source=source, created_by=user)
            return indicator, True
        except IntegrityError:
            # Created concurrently by another import; fall through and merge.
            indicator = Indicator.objects.get(**lookup)

    seen = data.get("last_seen") or now
    indicator.sighting_count += 1
    indicator.last_seen = max(indicator.last_seen, seen)
    if data.get("first_seen"):
        indicator.first_seen = min(indicator.first_seen, data["first_seen"])
    if data.get("severity"):
        indicator.severity = max(indicator.severity, data["severity"])
    if data.get("confidence") is not None:
        indicator.confidence = max(indicator.confidence, data["confidence"])
    if data.get("threat_type") and indicator.threat_type == ThreatType.OTHER:
        indicator.threat_type = data["threat_type"]
    indicator.tags = normalize_tags(list(indicator.tags or []) + data.get("tags", []))
    indicator.mitre_techniques = normalize_mitre(list(indicator.mitre_techniques or []) + data.get("mitre_techniques", []))
    if data.get("description") and not indicator.description:
        indicator.description = data["description"]
    if data.get("country") and not indicator.country:
        indicator.country = data["country"]
    if data.get("expires_at"):
        indicator.expires_at = max(indicator.expires_at or data["expires_at"], data["expires_at"])
    elif indicator.expires_at and settings.THREATDASH_DEFAULT_INDICATOR_TTL_DAYS:
        indicator.expires_at = max(
            indicator.expires_at, indicator.last_seen + timedelta(days=settings.THREATDASH_DEFAULT_INDICATOR_TTL_DAYS)
        )
    if indicator.status == Indicator.Status.EXPIRED:
        indicator.status = Indicator.Status.ACTIVE
    if source and indicator.source_id is None:
        indicator.source = source
    indicator.save()
    return indicator, False


def run_import(job, raw_bytes, source=None, user=None, defaults=None):
    """Parse ``raw_bytes`` and ingest every record, updating ``job`` in place.

    ``defaults`` pre-fills fields (e.g. ``threat_type`` for a plain-text feed)
    that individual records do not set themselves.
    """
    defaults = {k: v for k, v in (defaults or {}).items() if v not in (None, "")}
    text = decode_bytes(raw_bytes)
    if not job.file_format:
        job.file_format = detect_format(job.filename, text[:4096])
    parser = PARSERS[job.file_format]
    touched = []
    errors = []
    created = updated = total = 0
    try:
        with transaction.atomic():
            for index, record in enumerate(parser(text), 1):
                total = index
                if index > settings.THREATDASH_MAX_IMPORT_ROWS:
                    errors.append({"row": index, "error": "Row limit reached; remaining rows were skipped."})
                    break
                try:
                    if defaults:
                        record = {**record, **{k: v for k, v in defaults.items() if record.get(k) in (None, "", [])}}
                    data = normalize_record(record)
                    with transaction.atomic():
                        indicator, was_created = upsert_indicator(data, source=source, user=user)
                except (RecordError, ValueError) as exc:
                    errors.append({"row": index, "error": str(exc)[:300]})
                    continue
                touched.append(indicator)
                created += was_created
                updated += not was_created
            alerts = evaluate_indicators(touched)
    except ImportFormatError as exc:
        # The transaction was rolled back, so nothing from this file was kept.
        job.status = ImportJob.Status.FAILED
        job.message = str(exc)
        alerts, touched = [], []
        created = updated = 0
    else:
        if not touched and errors:
            job.status = ImportJob.Status.FAILED
            job.message = "No valid indicators were found in the file."
        elif errors:
            job.status = ImportJob.Status.COMPLETED_WITH_ERRORS
        else:
            job.status = ImportJob.Status.COMPLETED
        if not touched and not errors:
            job.status = ImportJob.Status.FAILED
            job.message = "The file did not contain any records."

    job.total_rows = total
    job.created_count = created
    job.updated_count = updated
    job.error_count = len(errors)
    job.alert_count = len(alerts)
    job.errors = errors[:MAX_STORED_ERRORS]
    job.finished_at = timezone.now()
    if not job.message and job.status != ImportJob.Status.FAILED:
        job.message = f"Imported {created} new and updated {updated} existing indicator(s)."
    job.save()
    logger.info("Import %s finished: %s (%d created, %d updated, %d errors)",
                job.pk, job.status, created, updated, len(errors))
    return job
