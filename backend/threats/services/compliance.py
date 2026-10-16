"""Continuous compliance: framework controls evaluated against live platform state.

Each automated check returns a 0-100 readiness score and human-readable
evidence. Controls map onto checks; controls without a check are tracked
manually by analysts. Results are point-in-time evidence for audit readiness,
not a certification.
"""
from datetime import timedelta

from django.conf import settings
from django.db.models import Avg, DurationField, ExpressionWrapper, F
from django.utils import timezone

from ..models import (
    Alert,
    Asset,
    AuditLog,
    ComplianceControl,
    ExternalExposure,
    Incident,
    Indicator,
    Severity,
    TelemetryDomain,
    TelemetryEvent,
    ThreatFeed,
)

ENDPOINT_TYPES = [Asset.AssetType.WORKSTATION, Asset.AssetType.LAPTOP, Asset.AssetType.SERVER]


def _pct(part, whole):
    return round(100 * part / whole) if whole else 0


def check_asset_inventory(now):
    recent = Asset.objects.filter(last_seen__gte=now - timedelta(days=7))
    total = recent.count()
    managed = recent.filter(managed=True).count()
    if not total:
        return 0, "No assets observed in the last 7 days; connect telemetry sources to build the inventory."
    return _pct(managed, total), f"{managed} of {total} active assets are managed; {total - managed} unmanaged " \
                                 f"(shadow IT) devices need an owner and enrolment."


def check_software_inventory(now):
    total = Asset.objects.count()
    with_software = Asset.objects.exclude(software=[]).count()
    return _pct(with_software, total), f"Software inventory captured for {with_software} of {total} assets."


def check_edr_coverage(now):
    endpoints = Asset.objects.filter(asset_type__in=ENDPOINT_TYPES)
    total = endpoints.count()
    managed = endpoints.filter(managed=True).count()
    if not total:
        return 0, "No workstations, laptops or servers in the inventory."
    return _pct(managed, total), f"EDR agent present on {managed} of {total} endpoints."


def check_vulnerability_management(now):
    assets = list(Asset.objects.exclude(vulnerabilities=[]).only("vulnerabilities", "hostname"))
    critical = [a for a in assets if a.max_cvss >= 9]
    high = [a for a in assets if 7 <= a.max_cvss < 9]
    score = max(100 - 20 * len(critical) - 5 * len(high), 0)
    return score, f"{len(critical)} asset(s) with critical (CVSS >= 9.0) and {len(high)} with high vulnerabilities " \
                  f"outstanding."


def check_threat_intelligence(now):
    feeds = list(ThreatFeed.objects.filter(enabled=True))
    fresh = [f for f in feeds if f.last_fetched_at and f.last_fetched_at >= now - timedelta(
        minutes=max(f.interval_minutes * 2, 120)) and not f.last_status.startswith("Failed")]
    updated = Indicator.objects.filter(updated_at__gte=now - timedelta(days=7)).count()
    score = 0
    if feeds:
        score += 60 * len(fresh) / len(feeds)
    if updated:
        score += 40
    return round(score), f"{len(fresh)} of {len(feeds)} enabled feeds are current; {updated} indicators updated " \
                         f"in the last 7 days."


def check_continuous_monitoring(now):
    active = set(TelemetryEvent.objects.filter(timestamp__gte=now - timedelta(hours=24))
                 .values_list("domain", flat=True).distinct())
    missing = [d.label for d in TelemetryDomain if d.value not in active]
    return _pct(len(active), len(TelemetryDomain)), (
        f"Telemetry received from {len(active)} of {len(TelemetryDomain)} security domains in the last 24 hours"
        + (f"; missing: {', '.join(missing)}." if missing else ".")
    )


def check_audit_logging(now):
    events = TelemetryEvent.objects.filter(timestamp__gte=now - timedelta(hours=24)).exists()
    audit = AuditLog.objects.exists()
    score = (60 if events else 0) + (40 if audit else 0)
    return score, ("Security events are being collected. " if events else "No events in 24 hours. ") + \
                  ("Platform audit trail is active." if audit else "No platform audit records yet.")


def check_detection_timeliness(now):
    acked = Alert.objects.filter(acknowledged_at__isnull=False, created_at__gte=now - timedelta(days=30)).annotate(
        delay=ExpressionWrapper(F("acknowledged_at") - F("created_at"), output_field=DurationField()))
    avg = acked.aggregate(avg=Avg("delay"))["avg"]
    stale = Alert.objects.filter(status=Alert.Status.OPEN, severity__gte=Severity.HIGH,
                                 created_at__lt=now - timedelta(hours=4)).count()
    score = 100
    if avg is None:
        score -= 30
    elif avg > timedelta(hours=1):
        score -= min(int(avg.total_seconds() // 3600) * 5, 50)
    score -= min(stale * 5, 50)
    avg_text = f"{avg.total_seconds() / 60:.0f} min" if avg is not None else "n/a"
    return max(score, 0), f"Mean time to acknowledge: {avg_text}; {stale} high/critical alerts un-triaged > 4h."


def check_incident_response(now):
    stale = Incident.objects.filter(status__in=Incident.OPEN_STATUSES, severity__gte=Severity.HIGH,
                                    created_at__lt=now - timedelta(hours=24)).exclude(
        status=Incident.Status.CONTAINED).count()
    closed = Incident.objects.filter(status=Incident.Status.CLOSED, closed_at__isnull=False).count()
    score = max(100 - stale * 20, 0)
    return score, f"{stale} high/critical incident(s) uncontained after 24 hours; {closed} incidents closed."


def check_containment_capability(now):
    connector = settings.THREATDASH_RESPONSE_CONNECTOR
    if connector == "webhook" and settings.THREATDASH_RESPONSE_WEBHOOK_URL:
        return 100, "Automated containment is wired to the EDR/SOAR webhook connector."
    return 50, "Response actions run in simulated mode; connect an EDR/SOAR webhook for real containment."


def check_credential_exposure(now):
    open_leaks = ExternalExposure.objects.filter(kind=ExternalExposure.Kind.LEAKED_CREDENTIAL,
                                                 status__in=["open", "investigating"])
    critical = open_leaks.filter(severity__gte=Severity.HIGH).count()
    total = open_leaks.count()
    return max(100 - critical * 15 - (total - critical) * 5, 0), \
        f"{total} leaked credential(s) awaiting remediation ({critical} high/critical)."


def check_external_attack_surface(now):
    exposures = ExternalExposure.objects.filter(
        kind__in=[ExternalExposure.Kind.TYPOSQUAT, ExternalExposure.Kind.EXPOSED_SERVICE,
                  ExternalExposure.Kind.BRAND_ABUSE], status__in=["open", "investigating"])
    count = exposures.count()
    return max(100 - count * 10, 0), f"{count} open external attack-surface finding(s)."


def check_breach_notification(now):
    overdue = Incident.objects.filter(severity=Severity.CRITICAL, created_at__lt=now - timedelta(hours=72)).exclude(
        status=Incident.Status.CLOSED).count()
    return (100 if not overdue else 0), (
        "No critical incidents open beyond the 72-hour notification window." if not overdue else
        f"{overdue} critical incident(s) open > 72h: confirm whether supervisory-authority notification is required."
    )


CHECKS = {
    "asset_inventory": check_asset_inventory,
    "software_inventory": check_software_inventory,
    "edr_coverage": check_edr_coverage,
    "vulnerability_management": check_vulnerability_management,
    "threat_intelligence": check_threat_intelligence,
    "continuous_monitoring": check_continuous_monitoring,
    "audit_logging": check_audit_logging,
    "detection_timeliness": check_detection_timeliness,
    "incident_response": check_incident_response,
    "containment_capability": check_containment_capability,
    "credential_exposure": check_credential_exposure,
    "external_attack_surface": check_external_attack_surface,
    "breach_notification": check_breach_notification,
}

CONTROL_CATALOG = [
    # NIST Cybersecurity Framework 2.0
    ("nist_csf", "ID.AM-01", "Inventories of hardware managed by the organization are maintained", "asset_inventory"),
    ("nist_csf", "ID.AM-02", "Inventories of software, services and systems are maintained", "software_inventory"),
    ("nist_csf", "ID.RA-01", "Vulnerabilities in assets are identified, validated and recorded",
     "vulnerability_management"),
    ("nist_csf", "ID.RA-02", "Cyber threat intelligence is received from information sharing forums and sources",
     "threat_intelligence"),
    ("nist_csf", "PR.AA-01", "Identities and credentials for authorized users are managed", "credential_exposure"),
    ("nist_csf", "PR.PS-04", "Log records are generated and made available for continuous monitoring",
     "audit_logging"),
    ("nist_csf", "DE.CM-01", "Networks and network services are monitored to find adverse events",
     "continuous_monitoring"),
    ("nist_csf", "DE.CM-09", "Computing hardware, software and their data are monitored", "edr_coverage"),
    ("nist_csf", "DE.AE-02", "Potentially adverse events are analyzed to better understand associated activities",
     "detection_timeliness"),
    ("nist_csf", "RS.MA-01", "The incident response plan is executed once an incident is declared",
     "incident_response"),
    ("nist_csf", "RS.MI-01", "Incidents are contained", "containment_capability"),
    ("nist_csf", "GV.SC-01", "A cybersecurity supply chain risk management program is established", ""),
    # ISO/IEC 27001:2022 Annex A
    ("iso27001", "A.5.7", "Threat intelligence", "threat_intelligence"),
    ("iso27001", "A.5.9", "Inventory of information and other associated assets", "asset_inventory"),
    ("iso27001", "A.5.17", "Authentication information", "credential_exposure"),
    ("iso27001", "A.5.24", "Information security incident management planning and preparation", "incident_response"),
    ("iso27001", "A.5.25", "Assessment and decision on information security events", "detection_timeliness"),
    ("iso27001", "A.5.26", "Response to information security incidents", "containment_capability"),
    ("iso27001", "A.8.7", "Protection against malware", "edr_coverage"),
    ("iso27001", "A.8.8", "Management of technical vulnerabilities", "vulnerability_management"),
    ("iso27001", "A.8.15", "Logging", "audit_logging"),
    ("iso27001", "A.8.16", "Monitoring activities", "continuous_monitoring"),
    ("iso27001", "A.5.30", "ICT readiness for business continuity", ""),
    # SOC 2 Trust Services Criteria (2017, revised points of focus 2022)
    ("soc2", "CC3.2", "Identifies and analyzes risks to the achievement of objectives", "threat_intelligence"),
    ("soc2", "CC6.1", "Logical access security over protected information assets", "credential_exposure"),
    ("soc2", "CC6.6", "Security measures against threats from sources outside system boundaries",
     "external_attack_surface"),
    ("soc2", "CC6.8", "Controls to prevent or detect unauthorized or malicious software", "edr_coverage"),
    ("soc2", "CC7.1", "Detection and monitoring procedures identify configuration changes and vulnerabilities",
     "vulnerability_management"),
    ("soc2", "CC7.2", "System components are monitored for anomalies indicative of malicious acts",
     "continuous_monitoring"),
    ("soc2", "CC7.3", "Security events are evaluated to determine whether they are incidents", "detection_timeliness"),
    ("soc2", "CC7.4", "Identified security incidents are responded to", "incident_response"),
    ("soc2", "CC7.5", "Activities to recover from identified security incidents", ""),
    # GDPR
    ("gdpr", "Art. 5(1)(f)", "Integrity and confidentiality of personal data", "credential_exposure"),
    ("gdpr", "Art. 25", "Data protection by design and by default", ""),
    ("gdpr", "Art. 30", "Records of processing activities", ""),
    ("gdpr", "Art. 32(1)(b)", "Ongoing confidentiality, integrity, availability and resilience",
     "continuous_monitoring"),
    ("gdpr", "Art. 32(1)(d)", "Regularly testing and evaluating the effectiveness of security measures",
     "vulnerability_management"),
    ("gdpr", "Art. 33", "Notification of a personal data breach within 72 hours", "breach_notification"),
]


def ensure_controls():
    for framework, control_id, title, check_key in CONTROL_CATALOG:
        ComplianceControl.objects.get_or_create(
            framework=framework, control_id=control_id,
            defaults={"title": title, "check_key": check_key,
                      "status": ComplianceControl.Status.MANUAL if not check_key else ComplianceControl.Status.FAIL},
        )


def status_for(score):
    if score >= 90:
        return ComplianceControl.Status.PASS
    if score >= 50:
        return ComplianceControl.Status.PARTIAL
    return ComplianceControl.Status.FAIL


def evaluate_controls(now=None):
    now = now or timezone.now()
    ensure_controls()
    results = {}
    for control in ComplianceControl.objects.exclude(check_key="").filter(manual_override=False):
        if control.check_key not in CHECKS:
            continue
        if control.check_key not in results:
            results[control.check_key] = CHECKS[control.check_key](now)
        score, evidence = results[control.check_key]
        control.score, control.evidence, control.status = score, evidence, status_for(score)
        control.last_evaluated = now
        control.save(update_fields=["score", "evidence", "status", "last_evaluated"])
    return results


def framework_summary():
    summary = []
    for framework, label in ComplianceControl.Framework.choices:
        controls = list(ComplianceControl.objects.filter(framework=framework))
        scored = [c for c in controls if c.status != ComplianceControl.Status.NOT_APPLICABLE
                  and c.status != ComplianceControl.Status.MANUAL]
        counts = {status: sum(1 for c in controls if c.status == status) for status in ComplianceControl.Status.values}
        summary.append({
            "framework": framework,
            "label": label,
            "readiness": round(sum(c.score for c in scored) / len(scored)) if scored else 0,
            "controls": len(controls),
            "counts": counts,
        })
    return summary
