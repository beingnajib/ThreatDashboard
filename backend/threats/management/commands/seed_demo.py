"""Populate the platform with a coherent, realistic demo dataset.

All external IPs come from the RFC 5737 documentation ranges and domains use
reserved TLDs (.example / .test / .invalid), so no real infrastructure is
labelled malicious. Telemetry is pushed through the real ingestion pipeline,
so assets, IoC matches, behavioural alerts and incidents are produced exactly
as they would be in production.
"""
import hashlib
import random
import secrets
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from threats.models import (
    Alert,
    Asset,
    DataConnector,
    DetectionRule,
    ExternalExposure,
    Incident,
    Indicator,
    Severity,
    Source,
    TelemetryEvent,
    ThreatActor,
)
from threats.services.assets import refresh_asset_risk
from threats.services.attribution import attribute_incident
from threats.services.compliance import evaluate_controls
from threats.services.exposure import ingest_dark_web, ingest_leaked_credentials, scan_typosquats
from threats.services.feeds import ensure_default_feeds
from threats.services.incidents import recompute_incident
from threats.services.response import ensure_default_playbooks
from threats.services.rules import evaluate_indicators
from threats.services.telemetry import ingest_events

EXTERNAL_NETS = ["203.0.113", "198.51.100", "192.0.2"]
THREAT_PROFILES = [
    ("phishing", ["T1566", "T1204"], ["phishing", "credential-harvest"]),
    ("c2", ["T1071", "T1573"], ["cobalt-strike", "beacon"]),
    ("ransomware", ["T1486", "T1490"], ["lockbit", "ransomware"]),
    ("malware", ["T1059", "T1105"], ["qakbot", "loader"]),
    ("botnet", ["T1071"], ["mirai", "iot"]),
    ("scanner", ["T1595", "T1046"], ["mass-scan"]),
    ("brute_force", ["T1110"], ["ssh", "rdp"]),
    ("apt", ["T1078", "T1021", "T1003"], ["apt29", "espionage"]),
    ("exploit", ["T1190"], ["cve-exploitation"]),
]
COUNTRIES = ["RU", "CN", "IR", "KP", "NL", "US", "BR", "UA", "VN", "RO"]
ACTORS = [
    {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard"], "actor_type": "nation_state",
     "origin_country": "RU", "mitre_group_id": "G0007", "motivation": "Espionage",
     "mitre_techniques": ["T1566", "T1078", "T1110", "T1059", "T1071", "T1003", "T1021", "T1560"],
     "malware_families": ["x-agent", "zebrocy"], "target_sectors": ["government", "defense", "energy"]},
    {"name": "APT29", "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM"], "actor_type": "nation_state",
     "origin_country": "RU", "mitre_group_id": "G0016", "motivation": "Espionage",
     "mitre_techniques": ["T1566", "T1078", "T1195", "T1059", "T1071", "T1550", "T1027", "T1003", "T1021"],
     "malware_families": ["apt29", "sunburst", "wellmess"], "target_sectors": ["government", "technology", "think tanks"]},
    {"name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Diamond Sleet"], "actor_type": "nation_state",
     "origin_country": "KP", "mitre_group_id": "G0032", "motivation": "Financial gain, espionage",
     "mitre_techniques": ["T1566", "T1204", "T1059", "T1105", "T1041", "T1486", "T1562"],
     "malware_families": ["appleJeus", "manuscrypt"], "target_sectors": ["finance", "cryptocurrency", "defense"]},
    {"name": "FIN7", "aliases": ["Carbanak", "Sangria Tempest"], "actor_type": "cybercrime",
     "origin_country": "", "mitre_group_id": "G0046", "motivation": "Financial gain",
     "mitre_techniques": ["T1566", "T1204", "T1059", "T1547", "T1071", "T1005", "T1486"],
     "malware_families": ["carbanak", "griffon", "qakbot"], "target_sectors": ["retail", "hospitality", "finance"]},
    {"name": "Sandworm Team", "aliases": ["Voodoo Bear", "Seashell Blizzard"], "actor_type": "nation_state",
     "origin_country": "RU", "mitre_group_id": "G0034", "motivation": "Disruption",
     "mitre_techniques": ["T1190", "T1059", "T1485", "T1486", "T1562", "T1078"],
     "malware_families": ["industroyer", "notpetya"], "target_sectors": ["energy", "government", "logistics"]},
    {"name": "LockBit", "aliases": ["LockBit 3.0", "LockBit Black"], "actor_type": "ransomware",
     "origin_country": "", "mitre_group_id": "", "motivation": "Extortion",
     "mitre_techniques": ["T1133", "T1078", "T1486", "T1490", "T1021", "T1048", "T1567", "T1562"],
     "malware_families": ["lockbit"], "target_sectors": ["manufacturing", "healthcare", "education"]},
    {"name": "Scattered Spider", "aliases": ["UNC3944", "Octo Tempest"], "actor_type": "cybercrime",
     "origin_country": "", "mitre_group_id": "G1015", "motivation": "Financial gain, extortion",
     "mitre_techniques": ["T1078", "T1566", "T1530", "T1567", "T1098", "T1136"],
     "malware_families": ["blackcat"], "target_sectors": ["telecommunications", "hospitality", "technology"]},
]
DEPARTMENTS = ["Finance", "Engineering", "Sales", "HR", "IT", "Operations"]


def _ip(rng):
    return f"{rng.choice(EXTERNAL_NETS)}.{rng.randint(1, 254)}"


def _sha256(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


class Command(BaseCommand):
    help = "Load a realistic demo dataset (indicators, telemetry, assets, incidents, actors, exposure)."

    def add_arguments(self, parser):
        parser.add_argument("--indicators", type=int, default=260)
        parser.add_argument("--days", type=int, default=45)
        parser.add_argument("--seed", type=int, default=7)
        parser.add_argument("--flush", action="store_true", help="Delete existing threat data first.")
        parser.add_argument("--create-users", action="store_true",
                            help="Create 'admin' (staff), 'responder' and 'analyst' accounts with random passwords.")

    def handle(self, *args, **options):
        rng = random.Random(options["seed"])
        now = timezone.now()
        if options["flush"]:
            for model in (Alert, Incident, TelemetryEvent, Asset, Indicator, DetectionRule, ExternalExposure,
                          ThreatActor, Source, DataConnector):
                model.objects.all().delete()
            self.stdout.write("Existing threat data deleted.")

        if options["create_users"]:
            self._create_users()

        with transaction.atomic():
            sources = self._sources()
            actors = self._actors()
            indicators = self._indicators(rng, sources, options["indicators"], options["days"], now)
            self._link_actors(rng, actors, indicators)
            self._rules()
            ensure_default_playbooks()
            ensure_default_feeds()
            evaluate_indicators(Indicator.objects.select_related("source").filter(
                status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING]))
        self._assets(rng, now)
        self._background_telemetry(rng, now)
        self._intrusion_story(rng, now, indicators)
        self._external_risk(now)
        self._age_alerts(rng, now)
        refresh_asset_risk()
        for incident in Incident.objects.all():
            results = attribute_incident(incident)
            strong = [r["actor_id"] for r in results if r["confidence"] >= 50]
            if strong:
                incident.attributed_actors.set(strong)
                recompute_incident(incident)
        evaluate_controls()
        self.stdout.write(self.style.SUCCESS(
            f"Demo data ready: {Indicator.objects.count()} indicators, {Asset.objects.count()} assets "
            f"({Asset.objects.filter(managed=False).count()} shadow IT), {TelemetryEvent.objects.count()} events, "
            f"{Alert.objects.count()} alerts in {Incident.objects.count()} incidents, "
            f"{ExternalExposure.objects.count()} external exposures."))

    # ------------------------------------------------------------------ #

    def _create_users(self):
        User = get_user_model()
        responders, _ = Group.objects.get_or_create(name="responders")
        forensics, _ = Group.objects.get_or_create(name="forensics")
        for username, staff, groups in (("admin", True, [responders, forensics]), ("responder", False,
                                        [responders, forensics]), ("analyst", False, [])):
            if User.objects.filter(username=username).exists():
                self.stdout.write(f"User {username} already exists; password unchanged.")
                continue
            password = secrets.token_urlsafe(12)
            user = User.objects.create_user(username=username, password=password, is_staff=staff,
                                            is_superuser=staff, email=f"{username}@example.com")
            user.groups.set(groups)
            self.stdout.write(self.style.WARNING(f"Created {username!r} with password: {password}"))

    def _sources(self):
        specs = [("AlienVault OTX (demo)", "osint", "C"), ("abuse.ch (demo)", "feed", "B"),
                 ("Internal SOC", "internal", "A"), ("ISAC sharing group", "feed", "B"),
                 ("Honeypot network", "internal", "B")]
        return [Source.objects.get_or_create(name=n, defaults={"kind": k, "reliability": r})[0] for n, k, r in specs]

    def _actors(self):
        actors = []
        for spec in ACTORS:
            actor, _ = ThreatActor.objects.update_or_create(name=spec["name"], defaults={
                **spec, "description": f"{spec['name']} ({', '.join(spec['aliases'][:2])}). Profile summarised from "
                                       f"public MITRE ATT&CK reporting for demonstration.",
                "references": [f"https://attack.mitre.org/groups/{spec['mitre_group_id']}/"]
                if spec["mitre_group_id"] else [],
                "last_activity": timezone.now().date() - timedelta(days=random.randint(3, 60)),
            })
            actors.append(actor)
        return actors

    def _indicators(self, rng, sources, count, days, now):
        created = []
        for i in range(count):
            # A burst on day 3 gives the anomaly detector something to find.
            offset = rng.choice([3] * 6 + list(range(days))) if i % 3 == 0 else rng.randint(0, days)
            first_seen = now - timedelta(days=offset, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            threat_type, techniques, tags = rng.choice(THREAT_PROFILES)
            kind = rng.choices(["ipv4", "domain", "url", "sha256", "email", "cve"], [40, 22, 16, 14, 4, 4])[0]
            if kind == "ipv4":
                value = _ip(rng)
            elif kind == "domain":
                value = f"{rng.choice(['secure', 'login', 'cdn', 'update', 'mail', 'api', 'portal'])}-" \
                        f"{rng.choice(['verify', 'sync', 'cloud', 'docs', 'pay', 'auth'])}{rng.randint(1, 99)}." \
                        f"{rng.choice(['example', 'test', 'invalid'])}"
                if rng.random() < 0.15:
                    value = "".join(rng.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(14)) + ".example"
            elif kind == "url":
                value = f"http://{_ip(rng) if rng.random() < 0.3 else 'files-' + str(rng.randint(1, 500)) + '.example'}" \
                        f"/{rng.choice(['invoice.exe', 'login.php', 'update.js', 'doc.hta', 'payload.bin'])}"
            elif kind == "sha256":
                value = _sha256(f"sample-{i}")
            elif kind == "email":
                value = f"{rng.choice(['billing', 'hr-notice', 'it-support', 'ceo-office'])}{i}@mail.example"
            else:
                value = f"CVE-202{rng.randint(3, 6)}-{rng.randint(1000, 49999)}"
            if Indicator.objects.filter(value=value).exists():
                continue
            severity = rng.choices([1, 2, 3, 4], [15, 35, 32, 18])[0]
            indicator = Indicator.objects.create(
                value=value, ioc_type=kind, threat_type="exploit" if kind == "cve" else threat_type,
                severity=severity, confidence=rng.randint(35, 98),
                status=rng.choices(["active", "investigating", "mitigated", "false_positive"], [78, 10, 8, 4])[0],
                tlp=rng.choice(["green", "amber", "amber", "red"]), source=rng.choice(sources),
                tags=rng.sample(tags, k=len(tags)), mitre_techniques=techniques[: rng.randint(1, len(techniques))],
                country=rng.choice(COUNTRIES) if kind in ("ipv4", "domain", "url") else "",
                cvss_score=round(rng.uniform(6.5, 10.0), 1) if kind == "cve" else None,
                description=f"Observed {threat_type.replace('_', ' ')} activity.",
                sighting_count=rng.randint(1, 30), first_seen=first_seen,
                last_seen=min(first_seen + timedelta(days=rng.randint(0, 10)), now),
                expires_at=first_seen + timedelta(days=90),
            )
            created.append(indicator)
        return created

    def _link_actors(self, rng, actors, indicators):
        by_tag = {a.name: a for a in actors}
        for indicator in indicators:
            if "apt29" in indicator.tags:
                by_tag["APT29"].indicators.add(indicator)
            elif "lockbit" in indicator.tags:
                by_tag["LockBit"].indicators.add(indicator)
            elif "qakbot" in indicator.tags and rng.random() < 0.5:
                by_tag["FIN7"].indicators.add(indicator)

    def _rules(self):
        specs = [
            {"name": "Critical C2 infrastructure", "threat_types": ["c2", "botnet"], "min_severity": 3,
             "description": "High-severity command-and-control indicators."},
            {"name": "Ransomware indicators", "threat_types": ["ransomware"], "min_severity": 2,
             "alert_severity": 4, "description": "Any indicator linked to ransomware operations."},
            {"name": "Very high risk score", "min_risk_score": 85,
             "description": "Indicators scoring 85+ after confidence, reliability and recency weighting."},
            {"name": "Credential phishing domains", "threat_types": ["phishing"], "ioc_types": ["domain", "url"],
             "min_confidence": 60, "description": "Phishing infrastructure likely to target staff."},
        ]
        for spec in specs:
            DetectionRule.objects.update_or_create(name=spec["name"], defaults=spec)

    def _assets(self, rng, now):
        os_choices = ["Windows 11 23H2", "Windows Server 2022", "Ubuntu 22.04", "macOS 14", "RHEL 9"]
        for i in range(1, 37):
            dept = DEPARTMENTS[i % len(DEPARTMENTS)]
            kind = rng.choices(["workstation", "laptop", "server", "cloud_instance"], [30, 35, 25, 10])[0]
            prefix = {"workstation": "ws", "laptop": "lt", "server": "srv", "cloud_instance": "vm"}[kind]
            vulns = []
            if rng.random() < 0.25:
                vulns = [{"cve": f"CVE-2024-{rng.randint(1000, 9999)}", "cvss": round(rng.uniform(5, 10), 1)}]
            Asset.objects.update_or_create(hostname=f"{prefix}-{dept.lower()}-{i:02d}", defaults={
                "ip_address": f"10.{10 + i % 4}.{i}.{rng.randint(10, 250)}", "asset_type": kind,
                "operating_system": rng.choice(os_choices), "department": dept, "owner": f"user{i}@example.com",
                "criticality": 4 if kind == "server" and dept in ("Finance", "IT") else rng.choice([1, 2, 2, 3]),
                "managed": rng.random() > 0.06, "discovered_via": "agent",
                "software": [{"name": "openssl", "version": "3.0.13"}, {"name": "chrome", "version": "128.0"}],
                "vulnerabilities": vulns, "first_seen": now - timedelta(days=rng.randint(30, 400)),
                "last_seen": now - timedelta(minutes=rng.randint(1, 600)),
            })

    def _connectors(self):
        connectors = {}
        for name, provider, domain in (("CrowdStrike Falcon (demo)", "edr", "endpoint"),
                                       ("AWS CloudTrail - prod", "aws_cloudtrail", "cloud"),
                                       ("Microsoft Entra ID", "azure_signin", "identity"),
                                       ("Azure activity - prod", "azure_activity", "cloud"),
                                       ("Perimeter firewall", "firewall", "network"),
                                       ("Email security gateway", "email_gateway", "email")):
            connector = DataConnector.objects.filter(name=name).first()
            if connector is None:
                connector = DataConnector(name=name, provider=provider, domain=domain)
                connector.rotate_key()
                connector.save()
            connectors[provider] = connector
        return connectors

    def _background_telemetry(self, rng, now):
        connectors = self._connectors()
        hosts = list(Asset.objects.filter(managed=True).values_list("hostname", "ip_address", "department"))
        endpoint, network, identity, email = [], [], [], []
        for _ in range(260):
            host, ip, dept = rng.choice(hosts)
            ts = (now - timedelta(minutes=rng.randint(5, 60 * 24 * 7))).isoformat()
            endpoint.append({"domain": "endpoint", "event_type": rng.choice(["process_start", "file_write",
                             "dns_query", "service_install"]), "hostname": host, "asset_ip": ip, "timestamp": ts,
                             "process": rng.choice(["chrome.exe", "outlook.exe", "teams.exe", "python3", "svchost.exe"]),
                             "username": f"{host.split('-')[1]}.user@example.com", "department": dept,
                             "managed": True, "severity": "low", "message": "Routine endpoint activity"})
            network.append({"domain": "network", "event_type": "connection", "src_ip": ip,
                            "dst_ip": f"{rng.choice(['93.184.216', '151.101.1', '140.82.112'])}.{rng.randint(1, 250)}",
                            "dst_port": rng.choice([443, 443, 443, 80, 53]), "outcome": "success", "timestamp": ts,
                            "bytes_out": rng.randint(500, 900000), "provider": "firewall"})
        for _ in range(60):
            identity.append({"createdDateTime": (now - timedelta(minutes=rng.randint(5, 10000))).isoformat(),
                             "userPrincipalName": f"user{rng.randint(1, 36)}@example.com",
                             "ipAddress": f"10.10.{rng.randint(1, 36)}.{rng.randint(10, 250)}",
                             "appDisplayName": rng.choice(["Office 365", "Salesforce", "Workday"]),
                             "status": {"errorCode": 0}, "location": {"countryOrRegion": "US"},
                             "riskLevelDuringSignIn": "none"})
        for i in range(40):
            email.append({"domain": "email", "event_type": "message_delivered", "provider": "email_gateway",
                          "domain_name": rng.choice(["partner.example", "vendor.test", "newsletter.example"]),
                          "username": f"user{rng.randint(1, 36)}@example.com", "outcome": "success",
                          "timestamp": (now - timedelta(minutes=rng.randint(5, 10000))).isoformat(),
                          "message": "Inbound message delivered"})
        ingest_events(endpoint, provider="edr", connector=connectors["edr"])
        # Three unmanaged devices appear only in network telemetry -> shadow IT.
        for octet in (77, 78, 201):
            network.append({"domain": "network", "event_type": "dhcp_lease", "src_ip": f"10.12.9.{octet}",
                            "timestamp": (now - timedelta(hours=rng.randint(1, 40))).isoformat(),
                            "message": "New DHCP lease for unknown MAC", "provider": "firewall"})
        ingest_events(network, provider="firewall", connector=connectors["firewall"])
        ingest_events(identity, provider="azure_signin", connector=connectors["azure_signin"])
        ingest_events(email, provider="email_gateway", connector=connectors["email_gateway"])

    def _intrusion_story(self, rng, now, indicators):
        """Phish -> credential theft -> lateral movement -> exfiltration, across five security domains."""
        connectors = self._connectors()
        c2_ip, exfil_ip, attacker_ip = "203.0.113.66", "198.51.100.23", "192.0.2.150"
        phish_domain = "examp1e-sso.test"
        payload_hash = _sha256("story-loader")
        for value, ioc_type, threat_type, severity, tags, techniques in (
            (c2_ip, "ipv4", "c2", 4, ["cobalt-strike", "apt29"], ["T1071", "T1573"]),
            (exfil_ip, "ipv4", "data_exfiltration", 4, ["apt29"], ["T1048"]),
            (phish_domain, "domain", "phishing", 3, ["phishing", "apt29"], ["T1566"]),
            (payload_hash, "sha256", "malware", 4, ["loader", "apt29"], ["T1059", "T1105"]),
        ):
            indicator, _ = Indicator.objects.get_or_create(ioc_type=ioc_type, value=value, defaults={
                "threat_type": threat_type, "severity": severity, "confidence": 90, "tags": tags,
                "mitre_techniques": techniques, "source": Source.objects.get(name="ISAC sharing group"),
                "country": "RU", "first_seen": now - timedelta(days=2), "last_seen": now - timedelta(hours=6),
            })
            ThreatActor.objects.get(name="APT29").indicators.add(indicator)

        t0 = now - timedelta(hours=5)
        victim, victim_user = "lt-finance-07", "user7@example.com"
        for hostname, kind, ip, criticality in ((victim, "laptop", "10.10.7.20", 3),
                                                ("srv-finance-06", "server", "10.11.6.40", 4)):
            Asset.objects.update_or_create(hostname=hostname, defaults={
                "asset_type": kind, "ip_address": ip, "criticality": criticality, "managed": True,
                "department": "Finance", "operating_system": "Windows 11 23H2" if kind == "laptop" else
                "Windows Server 2022", "owner": victim_user if kind == "laptop" else "finance-it@example.com",
                "discovered_via": "agent", "vulnerabilities": [] if kind == "laptop" else
                [{"cve": "CVE-2024-38063", "cvss": 9.8}],
            })

        def at(minutes):
            return (t0 + timedelta(minutes=minutes)).isoformat()

        ingest_events([
            {"domain": "email", "event_type": "phishing_link_clicked", "provider": "email_gateway",
             "username": victim_user, "domain_name": phish_domain, "url": f"https://{phish_domain}/login",
             "src_ip": attacker_ip, "severity": "medium", "timestamp": at(0), "mitre_technique": "T1566",
             "message": "User clicked a link in a credential-phishing email"},
        ], provider="email_gateway", connector=connectors["email_gateway"])
        failed = [{"createdDateTime": at(10 + i), "userPrincipalName": victim_user, "ipAddress": attacker_ip,
                   "appDisplayName": "Office 365", "status": {"errorCode": 50126, "failureReason": "Invalid password"},
                   "location": {"countryOrRegion": "NL"}} for i in range(12)]
        failed.append({"createdDateTime": at(25), "userPrincipalName": victim_user, "ipAddress": attacker_ip,
                       "appDisplayName": "Office 365", "status": {"errorCode": 0},
                       "location": {"countryOrRegion": "NL"}, "riskLevelDuringSignIn": "high"})
        failed.append({"createdDateTime": at(5), "userPrincipalName": victim_user, "ipAddress": "10.10.7.20",
                       "appDisplayName": "Office 365", "status": {"errorCode": 0},
                       "location": {"countryOrRegion": "US"}, "riskLevelDuringSignIn": "none"})
        ingest_events(failed, provider="azure_signin", connector=connectors["azure_signin"])
        ingest_events([
            {"domain": "endpoint", "event_type": "process_start", "hostname": victim, "username": victim_user,
             "process": "powershell.exe -enc SQBFAFgA...", "file_hash": payload_hash, "severity": "high",
             "mitre_technique": "T1059.001", "timestamp": at(40), "message": "Encoded PowerShell launched loader"},
            {"domain": "endpoint", "event_type": "beacon", "hostname": victim, "dst_ip": c2_ip, "dst_port": 443,
             "mitre_technique": "T1071.001", "timestamp": at(45), "severity": "medium",
             "message": "Periodic HTTPS beacon to rare external host"},
            {"domain": "endpoint", "event_type": "lsass_access", "hostname": victim, "username": victim_user,
             "process": "rundll32.exe comsvcs.dll MiniDump", "severity": "critical", "mitre_technique": "T1003.001",
             "timestamp": at(70), "message": "LSASS memory dumped"},
            {"domain": "endpoint", "event_type": "lateral_psexec", "hostname": victim,
             "target_hostname": "srv-finance-06", "username": "svc_backup", "severity": "high",
             "mitre_technique": "T1021.002", "timestamp": at(95),
             "message": "Remote service created over SMB on finance server"},
            {"domain": "endpoint", "event_type": "archive_created", "hostname": "srv-finance-06",
             "process": "7z.exe a -p q3_ledgers.7z", "severity": "medium", "mitre_technique": "T1560.001",
             "timestamp": at(120), "message": "Password-protected archive of finance share"},
        ], provider="edr", connector=connectors["edr"])
        ingest_events([
            {"domain": "network", "event_type": "upload", "hostname": "srv-finance-06", "src_ip": "10.11.6.40",
             "dst_ip": exfil_ip, "dst_port": 443, "bytes_out": 2_400_000_000, "mitre_technique": "T1048",
             "timestamp": at(150), "severity": "high", "provider": "firewall",
             "message": "2.4 GB uploaded to external host"},
        ], provider="firewall", connector=connectors["firewall"])
        ingest_events({"Records": [
            {"eventTime": at(160), "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com",
             "sourceIPAddress": attacker_ip, "userIdentity": {"type": "IAMUser", "userName": "svc_backup"}},
            {"eventTime": at(162), "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
             "sourceIPAddress": attacker_ip, "userIdentity": {"type": "IAMUser", "userName": "svc_backup"}},
        ]}, provider="aws_cloudtrail", connector=connectors["aws_cloudtrail"])
        ingest_events({"value": [
            {"eventTimestamp": at(170), "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
             "caller": "svc_backup@example.com", "callerIpAddress": attacker_ip, "status": {"value": "Succeeded"},
             "resourceId": "/subscriptions/0000/resourceGroups/prod/providers/Microsoft.Authorization"},
        ]}, provider="azure_activity", connector=connectors["azure_activity"])

    def _external_risk(self, now):
        ingest_leaked_credentials([
            {"email": "cfo@example.com", "password": "Winter2024!", "breach": "Combolist 2026-09"},
            {"email": "user7@example.com", "password": "Summer#22", "breach": "Combolist 2026-09"},
            {"email": "admin@example.com", "breach": "SaaS vendor breach"},
            {"email": "someone@other.example", "password": "x", "breach": "Combolist 2026-09"},
        ], source="breach-monitoring", domains=["example.com"])
        ingest_dark_web([
            {"title": "Initial access to 'Example Corp' VPN offered on access-broker forum", "kind": "dark_web_mention",
             "severity": "critical", "source": "forum-monitor", "detail": "Seller claims domain-user VPN access.",
             "observed_at": (now - timedelta(days=1)).isoformat(), "price": "USD 3,000"},
            {"title": "Example Corp mentioned in ransomware leak-site countdown", "kind": "data_leak",
             "severity": "high", "source": "leak-site-monitor", "observed_at": (now - timedelta(hours=8)).isoformat()},
        ])
        # A look-alike of example.com seen in DNS traffic becomes a typosquat finding.
        connectors = self._connectors()
        host = Asset.objects.filter(managed=True).first()
        ingest_events([{"domain": "network", "event_type": "dns_query", "hostname": host.hostname,
                        "domain_name": "examp1e.com", "timestamp": (now - timedelta(hours=3)).isoformat(),
                        "provider": "firewall", "message": "DNS query for look-alike domain"}],
                      provider="firewall", connector=connectors["firewall"])
        scan_typosquats(["example.com"], resolve=False)

    def _age_alerts(self, rng, now):
        """Spread rule alerts over time and resolve some, so trends and MTTR have history."""
        for alert in Alert.objects.filter(detection_type=Alert.DetectionType.RULE).select_related("indicator"):
            created = alert.indicator.first_seen + timedelta(minutes=rng.randint(1, 120))
            Alert.objects.filter(pk=alert.pk).update(created_at=created)
            if created < now - timedelta(days=2) and rng.random() < 0.7:
                resolved = min(created + timedelta(hours=rng.uniform(0.5, 36)), now)
                Alert.objects.filter(pk=alert.pk).update(
                    status=rng.choice([Alert.Status.RESOLVED, Alert.Status.RESOLVED, Alert.Status.DISMISSED]),
                    acknowledged_at=created + timedelta(minutes=rng.randint(5, 90)), resolved_at=resolved)
        for incident in Incident.objects.all():
            if not incident.alerts.filter(status__in=Alert.OPEN_STATUSES).exists():
                incident.status = Incident.Status.CLOSED
                incident.closed_at = now
                incident.save(update_fields=["status", "closed_at"])
            else:
                recompute_incident(incident)
