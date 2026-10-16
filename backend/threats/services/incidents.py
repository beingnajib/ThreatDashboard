"""Incident correlation, prioritisation and attack-path reconstruction.

Alerts that share an entity — the same asset, user, external IP or indicator —
within a rolling window are bundled into one incident, so a burst of hundreds
of low-level detections becomes a single case with a coherent story.
"""
import math
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ..models import Alert, Incident, Severity, TelemetryEvent
from .ioc import is_internal_ip

CORRELATION_WINDOW = timedelta(hours=48)
MAX_CANDIDATES = 500

TACTIC_ORDER = [
    "reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration",
    "impact",
]
TACTIC_LABELS = {t: t.replace("_", " ").title().replace("And", "and") for t in TACTIC_ORDER}
TECHNIQUE_TACTICS = {
    "T1595": "reconnaissance", "T1592": "reconnaissance", "T1589": "reconnaissance",
    "T1566": "initial_access", "T1078": "initial_access", "T1190": "initial_access", "T1133": "initial_access",
    "T1189": "initial_access", "T1195": "initial_access",
    "T1059": "execution", "T1204": "execution", "T1203": "execution", "T1047": "execution", "T1053": "persistence",
    "T1547": "persistence", "T1136": "persistence", "T1098": "persistence", "T1505": "persistence",
    "T1543": "persistence", "T1068": "privilege_escalation", "T1548": "privilege_escalation",
    "T1134": "privilege_escalation", "T1562": "defense_evasion", "T1070": "defense_evasion",
    "T1027": "defense_evasion", "T1036": "defense_evasion", "T1578": "defense_evasion",
    "T1003": "credential_access", "T1110": "credential_access", "T1555": "credential_access",
    "T1552": "credential_access", "T1558": "credential_access", "T1087": "discovery", "T1046": "discovery",
    "T1018": "discovery", "T1082": "discovery", "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1550": "lateral_movement", "T1560": "collection", "T1005": "collection", "T1530": "collection",
    "T1114": "collection", "T1071": "command_and_control", "T1105": "command_and_control",
    "T1572": "command_and_control", "T1573": "command_and_control", "T1090": "command_and_control",
    "T1568": "command_and_control", "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    "T1486": "impact", "T1490": "impact", "T1489": "impact", "T1485": "impact", "T1496": "impact",
}
EVENT_KEYWORDS = [
    ("exfiltration", ("exfil", "upload", "bytes_out")),
    ("lateral_movement", ("lateral", "psexec", "rdp", "smb", "wmi_remote", "remote_service")),
    ("credential_access", ("lsass", "credential", "mimikatz", "kerberoast")),
    ("command_and_control", ("beacon", "c2", "dns_query", "dns", "tunnel")),
    ("impact", ("encrypt", "ransom", "wipe", "shadow_copy_delete")),
    ("privilege_escalation", ("privilege", "elevat", "sudo", "role")),
    ("persistence", ("scheduled_task", "service_install", "registry_run", "autorun")),
    ("execution", ("process", "powershell", "script", "exec", "command")),
    ("initial_access", ("phish", "email", "signin", "login", "logon", "attachment", "exploit")),
    ("discovery", ("scan", "enum", "discovery")),
]
SEVERITY_WEIGHT = {1: 15, 2: 35, 3: 60, 4: 80}


def tactic_for(technique="", event_type=""):
    if technique:
        tactic = TECHNIQUE_TACTICS.get(technique.split(".")[0].upper())
        if tactic:
            return tactic
    lowered = (event_type or "").lower()
    for tactic, words in EVENT_KEYWORDS:
        if any(word in lowered for word in words):
            return tactic
    return None


def alert_keys(alert):
    keys = set()
    if alert.asset_id:
        keys.add(f"asset:{alert.asset_id}")
    if alert.indicator_id:
        keys.add(f"indicator:{alert.indicator_id}")
    event = alert.event
    if event is not None:
        if event.username:
            keys.add(f"user:{event.username.lower()}")
        for ip in (event.src_ip, event.dst_ip):
            if ip and not is_internal_ip(ip):
                keys.add(f"ip:{ip}")
        if event.target_asset_id:
            keys.add(f"asset:{event.target_asset_id}")
    return keys


def _alert_time(alert):
    return alert.event.timestamp if alert.event_id and alert.event else (alert.created_at or timezone.now())


def compute_priority(incident, alerts=None):
    """0-100 priority from severity, volume, kill-chain breadth, asset value and attribution."""
    alerts = list(alerts if alerts is not None else incident.alerts.select_related("asset", "event"))
    if not alerts:
        return 0
    severity = max(a.severity for a in alerts)
    tactics = {tactic_for(t) for a in alerts for t in (a.mitre_techniques or [])}
    tactics |= {tactic_for("", a.event.event_type) for a in alerts if a.event_id and a.event}
    tactics.discard(None)
    assets = {a.asset for a in alerts if a.asset_id}
    criticality = max((asset.criticality for asset in assets), default=1)
    max_cvss = max((asset.max_cvss for asset in assets), default=0)
    score = SEVERITY_WEIGHT.get(severity, 35)
    score += min(4 * math.log2(len(alerts) + 1), 12)
    score += min(4 * max(len(tactics) - 1, 0), 16)
    score += (criticality - 1) * 3
    score += 5 if max_cvss >= 9 else 0
    score += 5 if incident.pk and incident.attributed_actors.exists() else 0
    return int(min(round(score), 100))


def _refresh(incident, alerts):
    severity = max(a.severity for a in alerts)
    times = [_alert_time(a) for a in alerts]
    techniques = list(dict.fromkeys(t for a in alerts for t in (a.mitre_techniques or [])))
    assets = {a.asset_id for a in alerts if a.asset_id}
    assets |= {a.event.target_asset_id for a in alerts if a.event_id and a.event and a.event.target_asset_id}
    incident.severity = severity
    incident.alert_count = len(alerts)
    incident.first_activity = min(times)
    incident.last_activity = max(times)
    incident.mitre_techniques = techniques[:50]
    keys = set(incident.correlation_keys or [])
    for alert in alerts:
        keys |= alert_keys(alert)
    incident.correlation_keys = sorted(keys)[:200]
    incident.priority_score = compute_priority(incident, alerts)
    if len(alerts) > 1:
        tactics = {tactic_for(t) for t in techniques} - {None}
        subject = next((a.asset for a in alerts if a.asset_id), None) or next(
            (a.event.username for a in alerts if a.event_id and a.event and a.event.username), None)
        stage_text = f"{len(tactics)}-stage " if len(tactics) > 1 else ""
        if incident.status == Incident.Status.NEW:  # don't rename a case an analyst is working
            incident.title = (f"{stage_text}{Severity(severity).label.lower()} activity"
                              + (f" involving {subject}" if subject else "")).capitalize()[:300]
        incident.summary = (
            f"{len(alerts)} correlated alerts between {incident.first_activity:%Y-%m-%d %H:%M} and "
            f"{incident.last_activity:%Y-%m-%d %H:%M} UTC"
            + (f" across tactics: {', '.join(TACTIC_LABELS[t] for t in TACTIC_ORDER if t in tactics)}." if tactics
               else ".")
        )
    incident.save()
    if assets:
        incident.assets.add(*assets)


@transaction.atomic
def correlate_alerts(alerts):
    """Attach each alert to an overlapping open incident, or open a new one."""
    alerts = [a for a in alerts if a.pk and a.incident_id is None]
    if not alerts:
        return []
    alerts = list(Alert.objects.filter(pk__in=[a.pk for a in alerts]).select_related("event", "asset", "indicator"))
    since = timezone.now() - CORRELATION_WINDOW
    candidates = list(
        Incident.objects.filter(status__in=Incident.OPEN_STATUSES)
        .filter(Q(last_activity__gte=since) | Q(updated_at__gte=since))
        .order_by("-last_activity")[:MAX_CANDIDATES]
    )
    touched = {}
    for alert in alerts:
        keys = alert_keys(alert)
        best, best_overlap = None, 0
        for incident in candidates:
            overlap = len(keys & set(incident.correlation_keys or []))
            if overlap > best_overlap:
                best, best_overlap = incident, overlap
        if best is None:
            best = Incident.objects.create(
                title=alert.title[:300], summary=alert.description, severity=alert.severity,
                correlation_keys=sorted(keys), first_activity=_alert_time(alert), last_activity=_alert_time(alert),
            )
            candidates.insert(0, best)
        else:
            best.correlation_keys = sorted(set(best.correlation_keys or []) | keys)
        alert.incident = best
        Alert.objects.filter(pk=alert.pk).update(incident=best)
        touched[best.pk] = best
    for incident in touched.values():
        _refresh(incident, list(incident.alerts.select_related("event", "asset", "event__target_asset")))
    return list(touched.values())


def recompute_incident(incident):
    alerts = list(incident.alerts.select_related("event", "asset", "event__target_asset"))
    if alerts:
        _refresh(incident, alerts)
    return incident


# --------------------------------------------------------------------------- #
# Attack path
# --------------------------------------------------------------------------- #

def attack_path(incident, max_events=400):
    """Build a node/edge graph of how the intrusion progressed through the estate."""
    alerts = list(incident.alerts.select_related("event", "asset", "indicator", "event__asset", "event__target_asset"))
    asset_ids = set(incident.assets.values_list("pk", flat=True))
    users = {a.event.username for a in alerts if a.event_id and a.event and a.event.username}
    start = (incident.first_activity or incident.created_at) - timedelta(hours=1)
    end = (incident.last_activity or timezone.now()) + timedelta(hours=1)
    event_ids = {a.event_id for a in alerts if a.event_id}
    related = TelemetryEvent.objects.filter(timestamp__gte=start, timestamp__lte=end).filter(
        Q(pk__in=event_ids) | Q(asset_id__in=asset_ids) | Q(target_asset_id__in=asset_ids) | Q(username__in=users)
    ).select_related("asset", "target_asset").prefetch_related("matched_indicators").order_by("timestamp")
    events = list(related[:max_events])
    alerted = {a.event_id for a in alerts}

    nodes, edges = {}, {}

    def node(node_id, kind, label, **extra):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": kind, "label": label, "stage": None, "first_seen": None,
                              "malicious": False, "compromised": False, **extra}
        return nodes[node_id]

    def touch(n, stage, when):
        if when and (n["first_seen"] is None or when.isoformat() < n["first_seen"]):
            n["first_seen"] = when.isoformat()
        if stage and (n["stage"] is None or TACTIC_ORDER.index(stage) < TACTIC_ORDER.index(n["stage"])):
            n["stage"] = stage

    def external(ip=None, name=None):
        if ip:
            return node(f"ip:{ip}", "external_ip", ip)
        return node(f"domain:{name}", "external_domain", name)

    for event in events:
        stage = tactic_for(event.mitre_technique, event.event_type) or (
            "initial_access" if event.domain in ("identity", "email") else "execution")
        malicious = bool(event.matched_indicators.all())
        source_node = None
        if event.asset_id:
            source_node = node(f"asset:{event.asset_id}", "asset", str(event.asset),
                               asset_type=event.asset.asset_type, criticality=event.asset.criticality,
                               isolated=event.asset.is_isolated)
            source_node["compromised"] = source_node["compromised"] or event.asset_id in asset_ids
        user_node = node(f"user:{event.username}", "user", event.username) if event.username else None
        src_ext = bool(event.src_ip) and not is_internal_ip(event.src_ip)
        dst_ext = bool(event.dst_ip) and not is_internal_ip(event.dst_ip)

        hops = []
        if src_ext:
            ext = external(ip=event.src_ip)
            ext["malicious"] |= malicious
            hops.append((ext, user_node or source_node))
        if user_node and source_node:
            hops.append((user_node, source_node))
        elif user_node and not src_ext and event.domain == "cloud":
            hops.append((user_node, node(f"cloud:{event.provider}", "cloud", (event.provider or "cloud").upper())))
        if event.target_asset_id:
            target = node(f"asset:{event.target_asset_id}", "asset", str(event.target_asset),
                          asset_type=event.target_asset.asset_type, criticality=event.target_asset.criticality,
                          isolated=event.target_asset.is_isolated)
            target["compromised"] = True
            hops.append((source_node or user_node, target))
            stage = "lateral_movement" if stage in ("execution", "initial_access") else stage
        if dst_ext or event.domain_name:
            ext = external(ip=event.dst_ip) if dst_ext else external(name=event.domain_name)
            ext["malicious"] |= malicious
            hops.append((source_node or user_node, ext))

        for src, dst in hops:
            if src is None or dst is None or src is dst:
                continue
            touch(src, stage, event.timestamp)
            touch(dst, stage, event.timestamp)
            key = (src["id"], dst["id"], stage)
            edge = edges.setdefault(key, {
                "id": f"e{len(edges) + 1}", "source": src["id"], "target": dst["id"], "stage": stage,
                "label": event.event_type, "count": 0, "first_seen": event.timestamp.isoformat(),
                "last_seen": event.timestamp.isoformat(), "alerted": False, "techniques": [],
            })
            edge["count"] += 1
            edge["last_seen"] = event.timestamp.isoformat()
            edge["alerted"] |= event.pk in alerted
            if event.mitre_technique and event.mitre_technique not in edge["techniques"]:
                edge["techniques"].append(event.mitre_technique)

    stages = [s for s in TACTIC_ORDER if any(e["stage"] == s for e in edges.values())]
    entry = [n["id"] for n in nodes.values() if n["type"] in ("external_ip", "user")
             and any(e["source"] == n["id"] for e in edges.values()) and not any(e["target"] == n["id"]
                                                                                for e in edges.values())]
    return {
        "incident": incident.pk,
        "stages": [{"key": s, "label": TACTIC_LABELS[s]} for s in stages],
        "nodes": list(nodes.values()),
        "edges": sorted(edges.values(), key=lambda e: e["first_seen"]),
        "entry_points": entry,
        "exfiltration_targets": sorted({e["target"] for e in edges.values() if e["stage"] == "exfiltration"}),
        "truncated": len(events) >= max_events,
    }
