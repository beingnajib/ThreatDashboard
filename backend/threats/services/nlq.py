"""Natural-language querying.

A question such as *"top 5 countries with critical indicators in the last 7
days"* is translated into a small, whitelisted query spec::

    {"entity": "indicators", "filters": {"severity_min": 4}, "since_hours": 168,
     "group_by": "country", "limit": 5}

which is then executed with the ORM. Only fields named in ``ENTITIES`` can
ever be filtered or grouped, so the translation layer cannot produce
arbitrary SQL. Translation uses a deterministic keyword parser; when
``ANTHROPIC_API_KEY`` is set, Claude translates instead (structured JSON
output against the same schema) and the parser remains the fallback.
"""
import json
import logging
import re
from datetime import timedelta

from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from ..models import Alert, Asset, ExternalExposure, Incident, Indicator, Severity, TelemetryEvent

logger = logging.getLogger(__name__)

ENTITIES = {
    "alerts": {
        "model": Alert, "time": "created_at", "label": "alerts",
        "groups": {"severity": "severity", "status": "status", "detection_type": "detection_type",
                   "asset": "asset__hostname", "department": "asset__department", "rule": "rule__name"},
        "filters": {"status": "status", "detection_type": "detection_type", "department": "asset__department"},
        "columns": ["id", "title", "severity", "status", "detection_type", "created_at"],
    },
    "incidents": {
        "model": Incident, "time": "last_activity", "label": "incidents",
        "groups": {"severity": "severity", "status": "status"},
        "filters": {"status": "status"},
        "columns": ["id", "title", "severity", "status", "priority_score", "alert_count", "last_activity"],
    },
    "indicators": {
        "model": Indicator, "time": "first_seen", "label": "indicators",
        "groups": {"severity": "severity", "ioc_type": "ioc_type", "threat_type": "threat_type", "status": "status",
                   "country": "country", "source": "source__name"},
        "filters": {"status": "status", "ioc_type": "ioc_type", "threat_type": "threat_type", "country": "country"},
        "columns": ["id", "value", "ioc_type", "threat_type", "severity", "risk_score", "first_seen"],
    },
    "events": {
        "model": TelemetryEvent, "time": "timestamp", "label": "telemetry events",
        "groups": {"domain": "domain", "provider": "provider", "event_type": "event_type", "severity": "severity",
                   "outcome": "outcome", "country": "country", "user": "username", "host": "asset__hostname",
                   "src_ip": "src_ip"},
        "filters": {"domain": "domain", "provider": "provider", "outcome": "outcome", "country": "country",
                    "user": "username", "event_type_contains": "event_type__icontains"},
        "columns": ["id", "timestamp", "domain", "provider", "event_type", "severity", "username", "src_ip",
                    "message"],
    },
    "assets": {
        "model": Asset, "time": "last_seen", "label": "assets",
        "groups": {"asset_type": "asset_type", "department": "department", "managed": "managed",
                   "operating_system": "operating_system", "criticality": "criticality"},
        "filters": {"asset_type": "asset_type", "department": "department", "managed": "managed",
                    "isolated": "is_isolated"},
        "columns": ["id", "hostname", "ip_address", "asset_type", "department", "managed", "risk_score",
                    "last_seen"],
    },
    "exposures": {
        "model": ExternalExposure, "time": "observed_at", "label": "external exposures",
        "groups": {"kind": "kind", "severity": "severity", "status": "status", "source": "source"},
        "filters": {"kind": "kind", "status": "status"},
        "columns": ["id", "title", "kind", "severity", "status", "observed_at"],
    },
}
SEVERITY_ENTITIES = {"alerts", "incidents", "indicators", "events", "exposures"}
MAX_LIMIT = 100

ENTITY_WORDS = [
    ("exposures", r"\b(exposures?|leak(?:ed|s)?|breach(?:ed|es)?|credentials?|dark ?web|typo ?squat\w*|look-?alike)"),
    ("incidents", r"\b(incidents?|cases?)\b"),
    ("assets", r"\b(assets?|devices?|hosts?|machines?|endpoints?|servers?|laptops?|shadow it|inventory)\b"),
    ("events", r"\b(events?|logs?|telemetry|sign-?ins?|logins?|log-?ons?|authentications?|traffic|dns queries)\b"),
    ("indicators", r"\b(indicators?|iocs?|ips?|domains?|urls?|hashes|threats?|intel)\b"),
    ("alerts", r"\b(alerts?|detections?|alarms?)\b"),
]
GROUP_WORDS = [
    ("day", r"\b(per|by|each|over) (day|date|time)|\b(trend|timeline|daily|over time|time series)\b"),
    ("country", r"\b(countr(y|ies)|geo|locations?)\b"),
    ("severity", r"\b(by|per) severity|\bseverit(y|ies) (breakdown|distribution)"),
    ("status", r"\b(by|per) status\b"),
    ("ioc_type", r"\b(by|per) (ioc|indicator) type|\btypes? of (ioc|indicator)s?"),
    ("threat_type", r"\b(by|per) (threat|category)|\bthreat (types?|categor(y|ies))"),
    ("event_type", r"\b(by|per) event type|\bevent types?"),
    ("domain", r"\b(by|per) (domain|security domain|source domain)\b"),
    ("provider", r"\b(by|per) (provider|vendor|cloud)\b"),
    ("user", r"\b(by|per) user|\busers\b|\baccounts\b"),
    ("host", r"\b(by|per) (host|device)\b"),
    ("asset", r"\b(by|per) (asset|host|device)\b"),
    ("department", r"\b(departments?|business units?|teams?)\b"),
    ("asset_type", r"\b(by|per) (asset|device) type|\bdevice types?"),
    ("source", r"\b(by|per) (source|feed)|\bsources\b|\bfeeds\b"),
    ("kind", r"\b(by|per) (kind|type)\b"),
    ("rule", r"\b(by|per) rule|\brules\b"),
    ("src_ip", r"\bsource ips?|\b(by|per) (src|source) ip"),
    ("detection_type", r"\b(by|per) detection"),
    ("operating_system", r"\b(operating systems?|\bos\b)"),
]
COUNTRIES = {
    "russia": "RU", "china": "CN", "iran": "IR", "north korea": "KP", "united states": "US", "usa": "US",
    "germany": "DE", "brazil": "BR", "india": "IN", "united kingdom": "GB", "uk": "GB", "netherlands": "NL",
    "ukraine": "UA", "vietnam": "VN", "france": "FR", "nigeria": "NG", "romania": "RO", "pakistan": "PK",
}


def _since_hours(text):
    match = re.search(r"\b(?:last|past|previous)\s+(\d+)\s*(hour|hr|day|week|month)s?\b", text)
    if match:
        n, unit = int(match.group(1)), match.group(2)
        return n * {"hour": 1, "hr": 1, "day": 24, "week": 168, "month": 720}[unit]
    for pattern, hours in ((r"\btoday\b|\blast 24 ?h", 24), (r"\byesterday\b", 48), (r"\b(this|last|past) week\b", 168),
                           (r"\b(this|last|past) month\b", 720), (r"\b(last|past) hour\b", 1),
                           (r"\b(this|last|past) (quarter)\b", 2160), (r"\b(this|last|past) year\b", 8760)):
        if re.search(pattern, text):
            return hours
    return None


def parse_question(question):
    """Deterministic keyword translation of a question into a query spec."""
    text = " " + question.lower().strip() + " "
    # The entity mentioned first is the subject: "alerts by host" vs "hosts with alerts".
    positions = [(m.start(), name) for name, pattern in ENTITY_WORDS if (m := re.search(pattern, text))]
    entity = min(positions)[1] if positions else "alerts"
    spec = {"entity": entity, "filters": {}, "since_hours": _since_hours(text), "group_by": None, "limit": None}
    allowed_groups = ENTITIES[entity]["groups"]
    for group, pattern in GROUP_WORDS:
        if (group == "day" or group in allowed_groups) and re.search(pattern, text):
            spec["group_by"] = group
            break
    top = re.search(r"\btop\s+(\d+)", text)
    if top:
        spec["limit"] = min(int(top.group(1)), MAX_LIMIT)
        if not spec["group_by"]:
            spec["group_by"] = {"indicators": "threat_type", "events": "user", "alerts": "asset",
                                "assets": "department", "exposures": "kind", "incidents": "severity"}[entity]

    filters = spec["filters"]
    if entity in SEVERITY_ENTITIES:
        if re.search(r"\bcritical\b", text):
            filters["severity_min"] = Severity.CRITICAL
        elif re.search(r"\bhigh\b", text):
            filters["severity_min"] = Severity.HIGH
        elif re.search(r"\bmedium\b", text):
            filters["severity_min"] = Severity.MEDIUM
    if entity == "assets" and re.search(r"\bcritical\b", text):
        filters["criticality_min"] = Severity.CRITICAL
    status_words = {
        "alerts": {"open": "open", "unresolved": "open", "acknowledged": "acknowledged", "resolved": "resolved",
                   "dismissed": "dismissed"},
        "incidents": {"open": None, "new": "new", "contained": "contained", "closed": "closed", "triage": "triage"},
        "indicators": {"active": "active", "investigating": "investigating", "expired": "expired",
                       "false positive": "false_positive", "mitigated": "mitigated"},
        "exposures": {"open": "open", "remediated": "remediated"},
    }.get(entity, {})
    for word, status in status_words.items():
        if re.search(rf"\b{word}\b", text):
            if status:
                filters["status"] = status
            else:
                filters["open_only"] = True
            break
    if entity == "indicators":
        for word, ioc in (("ip", "ipv4"), ("ips", "ipv4"), ("domain", "domain"), ("domains", "domain"),
                          ("url", "url"), ("urls", "url"), ("hash", "sha256"), ("hashes", "sha256"),
                          ("cve", "cve"), ("cves", "cve"), ("email", "email")):
            if re.search(rf"\b{word}\b", text):
                filters["ioc_type"] = ioc
                break
        for threat in ("ransomware", "phishing", "malware", "botnet", "apt", "exploit", "scanner", "spam"):
            if re.search(rf"\b{threat}\b", text):
                filters["threat_type"] = threat
                break
        if re.search(r"\bc2\b|command (and|&) control", text):
            filters["threat_type"] = "c2"
    if entity == "events":
        for domain in ("endpoint", "cloud", "identity", "network", "email"):
            if re.search(rf"\b{domain}\b", text):
                filters["domain"] = domain
                break
        for provider, key in (("aws", "aws"), ("azure", "azure"), ("entra", "entra_id"), ("okta", "okta")):
            if re.search(rf"\b{provider}\b", text):
                filters["provider"] = key
                break
        if re.search(r"\bfail(ed|ure|ing)?\b", text):
            filters["outcome"] = "failure"
        if re.search(r"\b(sign-?ins?|logins?|log-?ons?|authentications?)\b", text):
            filters["event_type_contains"] = "sign" if "sign" in text else "login"
            if filters.get("provider") == "entra_id" or "sign" in text:
                filters["event_type_contains"] = "signin"
    if entity == "assets":
        if re.search(r"\b(shadow it|unmanaged|unknown devices?|rogue)\b", text):
            filters["managed"] = False
        elif re.search(r"\bmanaged\b", text):
            filters["managed"] = True
        if re.search(r"\bisolated\b|\bquarantined\b", text):
            filters["isolated"] = True
    if entity == "exposures":
        for word, kind in (("credential", "leaked_credential"), ("leak", "leaked_credential"),
                           ("typo", "typosquat"), ("look-alike", "typosquat"), ("lookalike", "typosquat"),
                           ("dark web", "dark_web_mention"), ("darkweb", "dark_web_mention")):
            if word in text:
                filters["kind"] = kind
                break
    if "country" in ENTITIES[entity]["filters"]:
        for name, code in COUNTRIES.items():
            if re.search(rf"\b(from|in) {name}\b", text):
                filters["country"] = code
                break
    return spec


# --------------------------------------------------------------------------- #
# Optional LLM translation
# --------------------------------------------------------------------------- #

def _llm_schema():
    groups = sorted({g for e in ENTITIES.values() for g in e["groups"]} | {"day"})

    def nullable(schema):
        return {"anyOf": [schema, {"type": "null"}]}

    return {
        "type": "object",
        "properties": {
            "entity": {"type": "string", "enum": list(ENTITIES)},
            "since_hours": nullable({"type": "integer"}),
            "group_by": nullable({"type": "string", "enum": groups}),
            "limit": nullable({"type": "integer"}),
            "filters": {
                "type": "object",
                "properties": {
                    "severity_min": nullable({"type": "integer", "enum": [1, 2, 3, 4]}),
                    "status": nullable({"type": "string"}),
                    "open_only": nullable({"type": "boolean"}),
                    "ioc_type": nullable({"type": "string", "enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1",
                                                                     "sha256", "email", "cve"]}),
                    "threat_type": nullable({"type": "string"}),
                    "domain": nullable({"type": "string", "enum": ["endpoint", "cloud", "identity", "network",
                                                                   "email"]}),
                    "provider": nullable({"type": "string"}),
                    "outcome": nullable({"type": "string", "enum": ["success", "failure"]}),
                    "event_type_contains": nullable({"type": "string"}),
                    "country": nullable({"type": "string"}),
                    "user": nullable({"type": "string"}),
                    "kind": nullable({"type": "string"}),
                    "department": nullable({"type": "string"}),
                    "asset_type": nullable({"type": "string"}),
                    "managed": nullable({"type": "boolean"}),
                    "isolated": nullable({"type": "boolean"}),
                    "criticality_min": nullable({"type": "integer", "enum": [1, 2, 3, 4]}),
                    "detection_type": nullable({"type": "string"}),
                },
                "required": ["severity_min", "status", "open_only", "ioc_type", "threat_type", "domain", "provider",
                             "outcome", "event_type_contains", "country", "user", "kind", "department", "asset_type",
                             "managed", "isolated", "criticality_min", "detection_type"],
                "additionalProperties": False,
            },
        },
        "required": ["entity", "since_hours", "group_by", "limit", "filters"],
        "additionalProperties": False,
    }


LLM_SYSTEM_PROMPT = """You translate a security analyst's question into a query spec for a SOC platform.

Entities and what they hold:
- alerts: detections (severity 1-4, status open/acknowledged/resolved/dismissed, detection_type rule/ioc_match/behavioral/telemetry/external)
- incidents: correlated cases (status new/triage/contained/eradicated/closed; open_only=true for any non-closed)
- indicators: IoCs (ioc_type, threat_type malware/ransomware/phishing/c2/botnet/apt/exploit/scanner/brute_force/spam/data_exfiltration/other, status active/investigating/mitigated/false_positive/expired, country ISO-2)
- events: normalised logs (domain endpoint/cloud/identity/network/email, provider e.g. aws/azure/entra_id, outcome, event_type_contains substring such as "signin", user, country)
- assets: devices and workloads (asset_type, department, managed=false means shadow IT, isolated, criticality_min)
- exposures: external risk (kind leaked_credential/dark_web_mention/typosquat/exposed_service/brand_abuse/data_leak, status open/remediated)

Severity: 1 low, 2 medium, 3 high, 4 critical; severity_min=3 means high and above.
group_by must be a field valid for the entity, or "day" for a trend over time; use limit for "top N".
since_hours expresses the time window ("last week" = 168). Leave anything not asked for as null."""


def llm_translate(question):
    """Translate with Claude; returns a spec or ``None`` if unavailable or unusable."""
    if not settings.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
    except ImportError:
        logger.warning("ANTHROPIC_API_KEY is set but the anthropic package is not installed.")
        return None
    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY, timeout=20.0, max_retries=1)
    try:
        response = client.beta.messages.create(
            model=settings.THREATDASH_NLQ_MODEL,
            max_tokens=2048,
            system=LLM_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": question}],
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": _llm_schema()}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.APIConnectionError:
        logger.warning("NLQ translation failed: could not reach the Anthropic API.")
        return None
    except anthropic.APIStatusError as exc:
        logger.warning("NLQ translation failed with HTTP %s: %s", exc.status_code, exc.message)
        return None
    except (anthropic.AnthropicError, TypeError, ValueError) as exc:
        logger.warning("NLQ translation unavailable (%s); using the keyword parser.", exc.__class__.__name__)
        return None
    if response.stop_reason in ("refusal", "max_tokens"):
        logger.info("NLQ translation stopped with %s; using the keyword parser.", response.stop_reason)
        return None
    text = next((block.text for block in response.content if block.type == "text"), "")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        return None
    spec["filters"] = {k: v for k, v in (spec.get("filters") or {}).items() if v is not None}
    return spec


# --------------------------------------------------------------------------- #
# Validation and execution
# --------------------------------------------------------------------------- #

def validate_spec(spec):
    entity = spec.get("entity")
    if entity not in ENTITIES:
        entity = "alerts"
    config = ENTITIES[entity]
    group_by = spec.get("group_by")
    if group_by not in config["groups"] and group_by != "day":
        group_by = None
    since = spec.get("since_hours")
    since = int(since) if isinstance(since, (int, float)) and 0 < since <= 24 * 366 else None
    limit = spec.get("limit")
    limit = int(limit) if isinstance(limit, (int, float)) and 0 < limit <= MAX_LIMIT else None
    clean = {}
    for key, value in (spec.get("filters") or {}).items():
        if value in (None, ""):
            continue
        if key == "severity_min" and entity in SEVERITY_ENTITIES and value in Severity.values:
            clean[key] = int(value)
        elif key == "criticality_min" and entity == "assets" and value in Severity.values:
            clean[key] = int(value)
        elif key == "open_only" and entity == "incidents" and isinstance(value, bool):
            clean[key] = value
        elif key in config["filters"]:
            if key in ("managed", "isolated"):
                if isinstance(value, bool):
                    clean[key] = value
            else:
                clean[key] = str(value)[:100]
    return {"entity": entity, "filters": clean, "since_hours": since, "group_by": group_by, "limit": limit}


def describe(spec):
    config = ENTITIES[spec["entity"]]
    parts = []
    f = spec["filters"]
    if "severity_min" in f:
        parts.append(f"{Severity(f['severity_min']).label.lower()}{'' if f['severity_min'] == 4 else '+'} severity")
    for key, value in f.items():
        if key not in ("severity_min",):
            parts.append(f"{key.replace('_', ' ')} = {value}")
    text = config["label"]
    if parts:
        text += " where " + ", ".join(parts)
    if spec["since_hours"]:
        hours = spec["since_hours"]
        text += f" in the last {hours // 24} days" if hours % 24 == 0 and hours >= 48 else f" in the last {hours} hours"
    if spec["group_by"]:
        text = ("count of " + text + (" per day" if spec["group_by"] == "day" else
                                       f" grouped by {spec['group_by'].replace('_', ' ')}"))
    if spec["limit"]:
        text = f"top {spec['limit']} " + text
    return text[0].upper() + text[1:]


def execute(spec):
    config = ENTITIES[spec["entity"]]
    queryset = config["model"].objects.all()
    f = spec["filters"]
    if "severity_min" in f:
        queryset = queryset.filter(severity__gte=f["severity_min"])
    if "criticality_min" in f:
        queryset = queryset.filter(criticality__gte=f["criticality_min"])
    if f.get("open_only") and spec["entity"] == "incidents":
        queryset = queryset.filter(status__in=Incident.OPEN_STATUSES)
    for key, field in config["filters"].items():
        if key in f:
            value = f[key]
            if key == "country":
                value = value.upper()
            queryset = queryset.filter(**{field: value})
    if spec["since_hours"]:
        queryset = queryset.filter(**{f"{config['time']}__gte": timezone.now() - timedelta(hours=spec["since_hours"])})

    total = queryset.count()
    group_by = spec["group_by"]
    if group_by == "day":
        rows = (queryset.annotate(day=TruncDate(config["time"])).values("day").annotate(count=Count("id"))
                .order_by("day"))
        series = [{"label": row["day"].isoformat() if row["day"] else "unknown", "value": row["count"]} for row in rows]
        return {"chart": "line", "total": total, "series": series, "rows": []}
    if group_by:
        field = config["groups"][group_by]
        rows = queryset.values(field).annotate(count=Count("id")).order_by("-count")[:spec["limit"] or 20]
        labels = {}
        if group_by == "severity":
            labels = dict(Severity.choices)
        series = [{"label": str(labels.get(row[field], row[field] if row[field] not in (None, "") else "unknown")),
                   "value": row["count"]} for row in rows]
        return {"chart": "bar", "total": total, "series": series, "rows": []}
    order = f"-{config['time']}"
    rows = list(queryset.order_by(order).values(*config["columns"])[:spec["limit"] or 25])
    return {"chart": "table", "total": total, "series": [], "rows": rows, "columns": config["columns"]}


def answer(question):
    question = (question or "").strip()[:500]
    if not question:
        raise ValueError("Ask a question, for example: 'failed sign-ins by country in the last 24 hours'.")
    engine = "keyword"
    spec = llm_translate(question)
    if spec is not None:
        engine = "claude"
    else:
        spec = parse_question(question)
    spec = validate_spec(spec)
    result = execute(spec)
    return {"question": question, "engine": engine, "spec": spec, "interpretation": describe(spec), **result}
