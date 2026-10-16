"""Cross-domain telemetry fusion.

Events from endpoints, cloud control planes (AWS CloudTrail, Azure), identity
providers (Entra ID), network sensors and email gateways are normalised into
one ``TelemetryEvent`` schema. Ingestion then:

1. discovers assets passively (unknown internal devices become shadow IT),
2. matches every observable against the indicator database,
3. runs behavioural detections (brute force, impossible travel, exfiltration),
4. raises alerts, which the incident engine bundles into cases.
"""
import ipaddress
import logging
import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.db import transaction
from django.db.models import F, Sum
from django.utils import timezone

from ..models import Alert, Asset, DataConnector, Indicator, Severity, TelemetryDomain, TelemetryEvent
from .importers import RecordError, parse_timestamp
from .ioc import is_internal_ip, refang

logger = logging.getLogger(__name__)

MAX_EVENTS_PER_REQUEST = 5000
FAILED_AUTH_THRESHOLD = 10
FAILED_AUTH_WINDOW = timedelta(minutes=15)
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(hours=2)
EXFIL_WINDOW = timedelta(hours=1)

SEVERITY_WORDS = {
    "informational": 1, "info": 1, "low": 1, "medium": 2, "moderate": 2, "warning": 2,
    "high": 3, "error": 3, "critical": 4, "severe": 4,
}

# (event name pattern, severity, ATT&CK technique, description)
CLOUDTRAIL_DETECTIONS = [
    (r"^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors)$", 4, "T1562.008", "CloudTrail logging tampered with"),
    (r"^(DeleteDetector|DisassociateFromMasterAccount|StopMonitoringMembers)$", 4, "T1562.001", "GuardDuty disabled"),
    (r"^(PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|PutBucketPublicAccessBlock)$", 3, "T1530",
     "S3 bucket access policy changed"),
    (r"^(AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy|AddUserToGroup)$", 3, "T1098",
     "IAM permissions escalated"),
    (r"^(CreateAccessKey|CreateLoginProfile|UpdateLoginProfile)$", 2, "T1098.001", "IAM credentials created"),
    (r"^(CreateUser)$", 2, "T1136.003", "IAM user created"),
    (r"^(AuthorizeSecurityGroupIngress)$", 2, "T1562.007", "Security group opened"),
    (r"^(GetSecretValue|GetParametersByPath)$", 2, "T1555", "Secrets accessed"),
    (r"^(RunInstances)$", 1, "T1578.002", "Compute instance launched"),
    (r"^(DeleteBucket|DeleteDBInstance|DeleteSnapshot)$", 3, "T1485", "Destructive cloud operation"),
]
AZURE_ACTIVITY_DETECTIONS = [
    (r"diagnosticsettings/delete", 4, "T1562.008", "Azure diagnostic logging deleted"),
    (r"roleassignments/write", 3, "T1098", "Azure role assignment created"),
    (r"virtualmachines/runcommand/action", 3, "T1059", "Command run on Azure VM"),
    (r"vaults/secrets/(read|getsecret)", 2, "T1555", "Key Vault secret read"),
    (r"networksecuritygroups/securityrules/write", 2, "T1562.007", "NSG rule changed"),
    (r"(storageaccounts/listkeys|storageaccounts/regeneratekey)", 3, "T1552", "Storage account keys accessed"),
    (r"/delete$", 2, "T1485", "Azure resource deleted"),
]
AUTH_EVENT_RE = re.compile(r"(login|logon|signin|sign_in|sign-in|auth)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Normalisers
# --------------------------------------------------------------------------- #

def _severity(value, default=Severity.LOW):
    if value in (None, ""):
        return default
    text = str(value).strip().lower()
    if text in SEVERITY_WORDS:
        return SEVERITY_WORDS[text]
    try:
        number = int(float(text))
    except ValueError:
        return default
    if number > 4:  # 0-10 vendor scale
        return 4 if number >= 9 else 3 if number >= 7 else 2 if number >= 4 else 1
    return max(number, 1)


def _ip(value):
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]")).compressed
    except ValueError:
        return None


def _str(value, limit):
    return str(value)[:limit] if value not in (None, "") else ""


def _int(value):
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _match_detection(table, name):
    for pattern, severity, technique, description in table:
        if re.search(pattern, name or "", re.IGNORECASE):
            return severity, technique, description
    return None


def normalize_generic(record, default_domain=None):
    domain = str(record.get("domain") or record.get("category") or default_domain or "").lower()
    if domain not in TelemetryDomain.values:
        raise RecordError("Event 'domain' must be one of: " + ", ".join(TelemetryDomain.values) + ".")
    event_type = _str(record.get("event_type") or record.get("action") or record.get("type"), 100)
    if not event_type:
        raise RecordError("Event is missing 'event_type'.")
    url = refang(_str(record.get("url"), 2048)) if record.get("url") else ""
    return {
        "timestamp": parse_timestamp(record.get("timestamp") or record.get("time")) or timezone.now(),
        "domain": domain,
        "provider": _str(record.get("provider") or record.get("vendor"), 30).lower(),
        "event_type": event_type,
        "severity": _severity(record.get("severity")),
        "outcome": _str(record.get("outcome") or record.get("result"), 20).lower(),
        "message": _str(record.get("message") or record.get("description"), 1000),
        "username": _str(record.get("username") or record.get("user"), 255),
        "src_ip": _ip(record.get("src_ip") or record.get("source_ip")),
        "dst_ip": _ip(record.get("dst_ip") or record.get("destination_ip")),
        "dst_port": _int(record.get("dst_port") or record.get("destination_port")),
        "hostname": _str(record.get("hostname") or record.get("host") or record.get("device"), 255).lower(),
        "domain_name": refang(_str(record.get("domain_name") or record.get("query") or record.get("sender_domain"),
                                   255)).lower(),
        "url": url,
        "file_hash": _str(record.get("file_hash") or record.get("sha256") or record.get("md5"), 64).lower(),
        "process": _str(record.get("process") or record.get("command_line"), 500),
        "bytes_out": _int(record.get("bytes_out") or record.get("bytes_sent")),
        "country": _str(record.get("country"), 2).upper(),
        "mitre_technique": _str(record.get("mitre_technique") or record.get("technique"), 12).upper(),
        "asset": {
            "hostname": _str(record.get("hostname") or record.get("host") or record.get("device"), 255).lower(),
            "ip_address": _ip(record.get("asset_ip") or record.get("host_ip")),
            "mac_address": _str(record.get("mac_address"), 17).lower(),
            "operating_system": _str(record.get("os") or record.get("operating_system"), 120),
            "asset_type": _str(record.get("asset_type"), 20),
            "department": _str(record.get("department"), 100),
            "owner": _str(record.get("owner"), 150),
            "managed": record.get("managed"),
            "software": record.get("software") if isinstance(record.get("software"), list) else None,
        },
        "target_hostname": _str(record.get("target_hostname") or record.get("dest_host"), 255).lower(),
    }


def normalize_cloudtrail(record, default_domain=None):
    identity = record.get("userIdentity") or {}
    name = _str(record.get("eventName"), 100)
    if not name:
        raise RecordError("CloudTrail record is missing 'eventName'.")
    failed = bool(record.get("errorCode")) or (record.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
    severity, technique, description = Severity.LOW, "", ""
    hit = _match_detection(CLOUDTRAIL_DETECTIONS, name)
    if hit:
        severity, technique, description = hit
    if identity.get("type") == "Root":
        severity, technique = max(severity, Severity.HIGH), technique or "T1078.004"
        description = description or "AWS root account used"
    if name == "ConsoleLogin" and failed:
        severity = max(severity, Severity.MEDIUM)
    username = identity.get("userName") or identity.get("arn") or identity.get("principalId") or ""
    src = record.get("sourceIPAddress")
    return {
        "timestamp": parse_timestamp(record.get("eventTime")) or timezone.now(),
        "domain": TelemetryDomain.CLOUD,
        "provider": "aws",
        "event_type": name,
        "severity": severity,
        "outcome": "failure" if failed else "success",
        "message": _str(description or f"{record.get('eventSource', '')} {name}".strip(), 1000),
        "username": _str(username, 255),
        "src_ip": _ip(src),
        "dst_ip": None, "dst_port": None,
        "hostname": "",
        "domain_name": "" if _ip(src) else _str(src, 255).lower(),
        "url": "", "file_hash": "", "process": "", "bytes_out": None, "country": "",
        "mitre_technique": technique,
        "asset": None,
        "target_hostname": "",
    }


def normalize_azure_signin(record, default_domain=None):
    record = {**record, **(record.get("properties") or {})}
    status = record.get("status") or {}
    error_code = status.get("errorCode", 0) if isinstance(status, dict) else 0
    failed = bool(error_code) and str(error_code) != "0"
    risk = str(record.get("riskLevelDuringSignIn") or record.get("riskLevelAggregated") or "none").lower()
    severity = {"high": Severity.HIGH, "medium": Severity.MEDIUM}.get(risk, Severity.LOW)
    if failed:
        severity = max(severity, Severity.LOW)
    device = record.get("deviceDetail") or {}
    location = record.get("location") or {}
    hostname = _str(device.get("displayName"), 255).lower()
    return {
        "timestamp": parse_timestamp(record.get("createdDateTime") or record.get("time")) or timezone.now(),
        "domain": TelemetryDomain.IDENTITY,
        "provider": "entra_id",
        "event_type": "signin_failure" if failed else "signin_success",
        "severity": severity,
        "outcome": "failure" if failed else "success",
        "message": _str(
            f"Sign-in to {record.get('appDisplayName') or 'application'}"
            + (f": {status.get('failureReason')}" if failed and isinstance(status, dict) else "")
            + (f" (risk {risk})" if risk not in ("none", "") else ""), 1000),
        "username": _str(record.get("userPrincipalName") or record.get("identity"), 255).lower(),
        "src_ip": _ip(record.get("ipAddress") or record.get("callerIpAddress")),
        "dst_ip": None, "dst_port": None,
        "hostname": hostname,
        "domain_name": "", "url": "", "file_hash": "", "process": "", "bytes_out": None,
        "country": _str(location.get("countryOrRegion"), 2).upper(),
        "mitre_technique": "T1078" if risk == "high" else ("T1110" if failed else ""),
        "asset": {
            "hostname": hostname,
            "ip_address": None,
            "operating_system": _str(device.get("operatingSystem"), 120),
            "managed": device.get("isManaged") if "isManaged" in device else None,
            "asset_type": "", "department": "", "owner": "", "mac_address": "", "software": None,
        } if hostname else None,
        "target_hostname": "",
    }


def normalize_azure_activity(record, default_domain=None):
    operation = record.get("operationName")
    if isinstance(operation, dict):
        operation = operation.get("value") or operation.get("localizedValue")
    operation = _str(operation, 100)
    if not operation:
        raise RecordError("Azure activity record is missing 'operationName'.")
    status = record.get("status") or record.get("resultType") or ""
    if isinstance(status, dict):
        status = status.get("value", "")
    severity, technique, description = Severity.LOW, "", ""
    hit = _match_detection(AZURE_ACTIVITY_DETECTIONS, operation)
    if hit:
        severity, technique, description = hit
    resource_id = _str(record.get("resourceId"), 500)
    asset = None
    vm = re.search(r"/virtualMachines/([^/]+)", resource_id, re.IGNORECASE)
    if vm:
        asset = {"hostname": vm.group(1).lower(), "ip_address": None, "asset_type": "cloud_instance",
                 "operating_system": "", "managed": None, "department": "", "owner": "", "mac_address": "",
                 "software": None, "cloud_provider": "azure", "cloud_resource_id": resource_id}
    return {
        "timestamp": parse_timestamp(record.get("eventTimestamp") or record.get("time")) or timezone.now(),
        "domain": TelemetryDomain.CLOUD,
        "provider": "azure",
        "event_type": operation,
        "severity": max(severity, _severity(record.get("level"), Severity.LOW)),
        "outcome": "failure" if str(status).lower() in ("failed", "failure") else "success",
        "message": _str(description or operation, 1000),
        "username": _str(record.get("caller"), 255).lower(),
        "src_ip": _ip(record.get("callerIpAddress")),
        "dst_ip": None, "dst_port": None,
        "hostname": asset["hostname"] if asset else "",
        "domain_name": "", "url": "", "file_hash": "", "process": "", "bytes_out": None, "country": "",
        "mitre_technique": technique,
        "asset": asset,
        "target_hostname": "",
    }


NORMALIZERS = {
    DataConnector.Provider.GENERIC: normalize_generic,
    DataConnector.Provider.EDR: normalize_generic,
    DataConnector.Provider.FIREWALL: normalize_generic,
    DataConnector.Provider.EMAIL_GATEWAY: normalize_generic,
    DataConnector.Provider.AWS_CLOUDTRAIL: normalize_cloudtrail,
    DataConnector.Provider.AZURE_SIGNIN: normalize_azure_signin,
    DataConnector.Provider.AZURE_ACTIVITY: normalize_azure_activity,
}


def unwrap_records(payload):
    """Accept a list, ``{"events": [...]}``, CloudTrail ``{"Records": [...]}`` or Azure ``{"value": [...]}``."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("events", "Records", "records", "value", "logs"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return [payload]
    raise RecordError("Payload must be a JSON object or array of events.")


# --------------------------------------------------------------------------- #
# Asset discovery
# --------------------------------------------------------------------------- #

def _is_internal(ip):
    return bool(ip) and is_internal_ip(ip)


def discover_asset(info, when, provider, cache):
    """Find or create the asset described by ``info``; returns it or ``None``."""
    if not info:
        return None
    hostname = (info.get("hostname") or "").lower()
    ip = info.get("ip_address")
    if not hostname and not ip:
        return None
    key = hostname or ip
    if key in cache:
        asset = cache[key]
    else:
        asset = None
        if hostname:
            asset = Asset.objects.filter(hostname=hostname).first()
        if asset is None and ip:
            # IP-only sightings attach to whatever asset holds the address; a
            # named sighting may adopt an asset previously known only by IP.
            by_ip = Asset.objects.filter(ip_address=ip).order_by("-last_seen")
            asset = (by_ip.filter(hostname="") if hostname else by_ip).first()
        if asset is None:
            # Only a host identity reported by the agent itself proves enrolment;
            # devices an EDR merely sees on the wire are still unmanaged.
            agent = provider in (DataConnector.Provider.EDR, "edr") and bool(hostname)
            asset = Asset(
                hostname=hostname, ip_address=ip, first_seen=when, last_seen=when,
                discovered_via=Asset.DiscoveryMethod.AGENT if agent else Asset.DiscoveryMethod.TELEMETRY,
                managed=bool(agent),
            )
            if info.get("cloud_provider"):
                asset.discovered_via = Asset.DiscoveryMethod.CLOUD_API
            asset.newly_discovered = True
        cache[key] = asset

    changed = asset.pk is None
    if when > asset.last_seen:
        asset.last_seen, changed = when, True
    for field in ("operating_system", "department", "owner", "mac_address", "cloud_provider", "cloud_resource_id"):
        value = info.get(field)
        if value and not getattr(asset, field):
            setattr(asset, field, value)
            changed = True
    if ip and not asset.ip_address:
        asset.ip_address, changed = ip, True
    asset_type = info.get("asset_type")
    if asset_type in Asset.AssetType.values and asset.asset_type == Asset.AssetType.UNKNOWN:
        asset.asset_type, changed = asset_type, True
    if info.get("managed") is True and not asset.managed:
        asset.managed, changed = True, True
    if info.get("software"):
        asset.software = [s for s in info["software"] if isinstance(s, dict)][:500]
        changed = True
    if changed:
        asset.save()
    return asset


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #

def _observables(event):
    values = set()
    for ip in (event.src_ip, event.dst_ip):
        if ip and not _is_internal(ip):
            values.add(ip)
    if event.domain_name:
        values.add(event.domain_name)
    if event.url:
        values.add(event.url)
        host = (urlsplit(event.url).hostname or "").lower()
        if host:
            values.add(host)
    if event.file_hash:
        values.add(event.file_hash)
    if event.username and "@" in event.username:
        values.add(event.username)
    return values


def _open_alert_exists(dedup_key):
    return Alert.objects.filter(dedup_key=dedup_key, status__in=Alert.OPEN_STATUSES).exists()


def _new_alert(alerts, dedup_key, **fields):
    if dedup_key in {a.dedup_key for a in alerts} or _open_alert_exists(dedup_key):
        return
    alerts.append(Alert(dedup_key=dedup_key[:300], **fields))


def match_indicators(events, alerts):
    by_value = defaultdict(list)
    for event in events:
        for value in _observables(event):
            by_value[value].append(event)
    if not by_value:
        return 0
    matches = 0
    values = list(by_value)
    indicators = []
    for start in range(0, len(values), 500):
        indicators += list(Indicator.objects.filter(
            value__in=values[start:start + 500],
            status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING],
        ))
    for indicator in indicators:
        hit_events = by_value[indicator.value]
        for event in hit_events:
            event.matched_indicators.add(indicator)
            matches += 1
            asset = event.asset
            _new_alert(
                alerts, f"ioc:{indicator.pk}:{asset.pk if asset else event.username or event.src_ip}",
                title=f"Known {indicator.get_threat_type_display().lower()} indicator {indicator.value} observed"
                      + (f" on {asset}" if asset else ""),
                description=f"{event.get_domain_display()} telemetry ({event.provider or 'unknown source'}) "
                            f"matched a {indicator.get_severity_display().lower()}-severity indicator: {event.message}",
                detection_type=Alert.DetectionType.IOC_MATCH,
                indicator=indicator, asset=asset, event=event,
                severity=max(indicator.severity, event.severity),
                mitre_techniques=list(dict.fromkeys(
                    list(indicator.mitre_techniques or []) + ([event.mitre_technique] if event.mitre_technique else []))),
            )
        latest = max(e.timestamp for e in hit_events)
        Indicator.objects.filter(pk=indicator.pk).update(sighting_count=F("sighting_count") + len(hit_events))
        if latest > indicator.last_seen:
            Indicator.objects.filter(pk=indicator.pk).update(last_seen=latest)
    return matches


def source_detections(events, alerts):
    """Promote high-severity events reported by the source itself to alerts."""
    for event in events:
        if event.severity < Severity.HIGH:
            continue
        subject = event.asset or event.username or event.src_ip or "unknown"
        _new_alert(
            alerts, f"telemetry:{event.provider}:{event.event_type}:{subject}",
            title=f"{event.message or event.event_type} ({event.get_domain_display()})"[:300],
            description=f"{event.provider or event.domain} reported {event.event_type}"
                        + (f" by {event.username}" if event.username else "")
                        + (f" from {event.src_ip}" if event.src_ip else ""),
            detection_type=Alert.DetectionType.TELEMETRY,
            asset=event.asset, event=event, severity=event.severity,
            mitre_techniques=[event.mitre_technique] if event.mitre_technique else [],
        )


def behavioural_detections(events, alerts):
    """Brute force, impossible travel and data-exfiltration analytics."""
    failed_keys = {(e.username, e.src_ip) for e in events
                   if e.outcome == "failure" and AUTH_EVENT_RE.search(e.event_type) and (e.username or e.src_ip)}
    for username, src_ip in failed_keys:
        anchor = max(e.timestamp for e in events if (e.username, e.src_ip) == (username, src_ip))
        window = TelemetryEvent.objects.filter(
            outcome="failure", timestamp__gte=anchor - FAILED_AUTH_WINDOW, timestamp__lte=anchor + timedelta(minutes=1),
        ).filter(event_type__iregex=AUTH_EVENT_RE.pattern)
        window = window.filter(username=username) if username else window.filter(src_ip=src_ip)
        count = window.count()
        if count >= FAILED_AUTH_THRESHOLD:
            event = window.order_by("-timestamp").first()
            subject = username or src_ip
            _new_alert(
                alerts, f"bruteforce:{subject}",
                title=f"Possible brute-force / password spraying against {subject}",
                description=f"{count} failed authentications in {int(FAILED_AUTH_WINDOW.total_seconds() // 60)} "
                            f"minutes" + (f" from {src_ip}" if src_ip else ""),
                detection_type=Alert.DetectionType.BEHAVIORAL, event=event, asset=event.asset,
                severity=Severity.HIGH if count >= FAILED_AUTH_THRESHOLD * 3 else Severity.MEDIUM,
                mitre_techniques=["T1110"],
            )

    logins = [e for e in events if e.domain == TelemetryDomain.IDENTITY and e.outcome == "success"
              and e.username and e.country]
    for event in logins:
        other = (TelemetryEvent.objects.filter(
            domain=TelemetryDomain.IDENTITY, outcome="success", username=event.username,
            timestamp__gte=event.timestamp - IMPOSSIBLE_TRAVEL_WINDOW,
            timestamp__lte=event.timestamp + IMPOSSIBLE_TRAVEL_WINDOW,
        ).exclude(country="").exclude(country=event.country).order_by("-timestamp").first())
        if other:
            _new_alert(
                alerts, f"travel:{event.username}",
                title=f"Impossible travel for {event.username}: {other.country} and {event.country}",
                description=f"Successful sign-ins from {other.country} ({other.src_ip}) and {event.country} "
                            f"({event.src_ip}) within {int(IMPOSSIBLE_TRAVEL_WINDOW.total_seconds() // 3600)} hours.",
                detection_type=Alert.DetectionType.BEHAVIORAL, event=event, asset=event.asset,
                severity=Severity.HIGH, mitre_techniques=["T1078"],
            )

    threshold = settings.THREATDASH_EXFIL_BYTES
    pairs = {(e.asset_id, e.dst_ip) for e in events if e.bytes_out and e.asset_id and e.dst_ip
             and not _is_internal(e.dst_ip)}
    for asset_id, dst_ip in pairs:
        anchor = max(e.timestamp for e in events if (e.asset_id, e.dst_ip) == (asset_id, dst_ip))
        total = TelemetryEvent.objects.filter(
            asset_id=asset_id, dst_ip=dst_ip, timestamp__gte=anchor - EXFIL_WINDOW, timestamp__lte=anchor,
        ).aggregate(total=Sum("bytes_out"))["total"] or 0
        if total >= threshold:
            event = TelemetryEvent.objects.filter(asset_id=asset_id, dst_ip=dst_ip).order_by("-timestamp").first()
            _new_alert(
                alerts, f"exfil:{asset_id}:{dst_ip}",
                title=f"Possible data exfiltration from {event.asset} to {dst_ip}",
                description=f"{total / 1024 / 1024:.0f} MB sent to an external address.",
                detection_type=Alert.DetectionType.BEHAVIORAL, event=event, asset=event.asset,
                severity=Severity.CRITICAL if total >= threshold * 4 else Severity.HIGH,
                mitre_techniques=["T1048"],
            )


def ingest_events(payload, provider=DataConnector.Provider.GENERIC, connector=None, default_domain=None):
    """Normalise and store events, then run detections. Returns a summary dict."""
    from .assets import refresh_asset_risk
    from .incidents import correlate_alerts

    records = unwrap_records(payload)
    if len(records) > MAX_EVENTS_PER_REQUEST:
        raise RecordError(f"At most {MAX_EVENTS_PER_REQUEST} events can be sent per request.")
    normalizer = NORMALIZERS.get(provider, normalize_generic)
    errors, events, alerts = [], [], []
    asset_cache = {}

    with transaction.atomic():
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                errors.append({"index": index, "error": "Event must be a JSON object."})
                continue
            try:
                data = normalizer(record, default_domain or (connector.domain if connector else None))
            except (RecordError, ValueError, TypeError, AttributeError) as exc:
                errors.append({"index": index, "error": str(exc)[:300]})
                continue
            if not data.get("provider"):
                data["provider"] = str(provider)[:30]
            asset_info = data.pop("asset", None)
            target_hostname = data.pop("target_hostname", "")
            if asset_info and not (asset_info.get("hostname") or asset_info.get("ip_address")):
                asset_info = None
            if asset_info is None and data.get("src_ip") and _is_internal(data["src_ip"]) \
                    and data["domain"] in (TelemetryDomain.NETWORK, TelemetryDomain.ENDPOINT):
                asset_info = {"ip_address": data["src_ip"]}
            asset = discover_asset(asset_info, data["timestamp"], provider, asset_cache)
            target = discover_asset({"hostname": target_hostname}, data["timestamp"], provider, asset_cache) \
                if target_hostname else None
            event = TelemetryEvent.objects.create(
                **data, connector=connector, asset=asset, target_asset=target,
                raw=record if len(str(record)) < 20000 else {"truncated": True},
            )
            events.append(event)

        matches = match_indicators(events, alerts)
        source_detections(events, alerts)
        behavioural_detections(events, alerts)
        if alerts:
            Alert.objects.bulk_create(alerts)
            correlate_alerts(alerts)
        if connector and events:
            DataConnector.objects.filter(pk=connector.pk).update(
                events_received=F("events_received") + len(events), last_event_at=timezone.now()
            )
        touched_assets = {e.asset_id for e in events if e.asset_id} | {e.target_asset_id for e in events
                                                                         if e.target_asset_id}
        refresh_asset_risk(Asset.objects.filter(pk__in=touched_assets))

    logger.info("Ingested %d event(s) from %s: %d IoC matches, %d alert(s), %d error(s)",
                len(events), provider, matches, len(alerts), len(errors))
    return {
        "received": len(records),
        "ingested": len(events),
        "ioc_matches": matches,
        "alerts_created": len(alerts),
        "assets_discovered": len({a.pk for a in asset_cache.values() if getattr(a, "newly_discovered", False)}),
        "errors": errors[:100],
    }
