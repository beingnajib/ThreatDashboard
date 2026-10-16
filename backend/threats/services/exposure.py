"""External risk ingestion: typosquatting, leaked credentials and dark-web telemetry.

Leaked passwords are never stored. Only a 5-character SHA-1 prefix is kept
(the same k-anonymity scheme used by breach-checking services) so analysts
can tell whether two leaks share a password without the platform holding it.
"""
import concurrent.futures
import hashlib
import re
import socket

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ..models import ExternalExposure, Indicator, IOCType, Severity, TelemetryEvent
from .importers import RecordError, parse_timestamp
from .ioc import DOMAIN_RE

KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "o", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn",
    "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm",
    "m": "njk",
}
HOMOGLYPHS = {
    "o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "g": ["9", "q"],
    "m": ["rn"], "w": ["vv"], "d": ["cl"], "b": ["6"], "t": ["7"],
}
ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "app", "online", "site", "xyz", "top", "us", "cc"]
PRIVILEGED_MAILBOXES = re.compile(r"^(admin|administrator|root|it|helpdesk|security|ceo|cfo|cto|ciso|finance|hr|"
                                  r"payroll|billing|sysadmin|devops)([._-]|$)", re.IGNORECASE)


def _split(domain):
    domain = domain.lower().strip().rstrip(".")
    label, _, tld = domain.partition(".")
    return label, tld


def typosquat_candidates(domain):
    """Generate look-alike domains (dnstwist-style fuzzers). Returns ``[{"domain", "technique"}]``."""
    label, tld = _split(domain)
    if not label or not tld:
        return []
    results = {}

    def add(candidate_label, technique, candidate_tld=None):
        candidate = f"{candidate_label}.{candidate_tld or tld}"
        if candidate != f"{label}.{tld}" and candidate_label and DOMAIN_RE.match(candidate) \
                and not candidate_label.startswith("-") and not candidate_label.endswith("-"):
            results.setdefault(candidate, technique)

    for i in range(len(label)):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] + label[i:], "repetition")
        if i < len(label) - 1:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
            add(label[:i + 1] + "-" + label[i + 1:], "hyphenation")
        for neighbour in KEYBOARD_ADJACENT.get(label[i], ""):
            add(label[:i] + neighbour + label[i + 1:], "replacement")
            add(label[:i] + neighbour + label[i:], "insertion")
        for glyph in HOMOGLYPHS.get(label[i], []):
            add(label[:i] + glyph + label[i + 1:], "homoglyph")
        for bit in range(8):
            flipped = chr(ord(label[i]) ^ (1 << bit))
            if re.fullmatch(r"[a-z0-9-]", flipped):
                add(label[:i] + flipped + label[i + 1:], "bitsquatting")
    for alt in ALT_TLDS:
        if alt != tld:
            add(label, "tld-swap", alt)
    for affix in ("login", "secure", "account", "support", "my", "portal", "sso", "auth"):
        add(f"{label}-{affix}", "keyword")
        add(f"{affix}-{label}", "keyword")
    add(f"www{label}", "subdomain-merge")
    return [{"domain": d, "technique": t} for d, t in sorted(results.items())]


def _resolves(domain):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(domain, None)})[:5]
    except (socket.gaierror, UnicodeError, OSError):
        return []


def _upsert_exposure(fingerprint, **fields):
    fingerprint = hashlib.sha256(fingerprint.encode()).hexdigest()
    try:
        with transaction.atomic():
            exposure, created = ExternalExposure.objects.get_or_create(fingerprint=fingerprint, defaults=fields)
    except IntegrityError:
        exposure, created = ExternalExposure.objects.get(fingerprint=fingerprint), False
    if not created:
        exposure.observed_at = max(exposure.observed_at, fields.get("observed_at") or exposure.observed_at)
        exposure.data = {**exposure.data, **fields.get("data", {})}
        exposure.severity = max(exposure.severity, fields.get("severity", exposure.severity))
        exposure.save(update_fields=["observed_at", "data", "severity", "updated_at"])
    return exposure, created


def scan_typosquats(domains=None, resolve=False, max_lookups=400, timeout=20):
    """Find look-alikes of the organisation's domains that are live or already seen in telemetry/intel.

    With ``resolve`` the candidates are resolved in DNS (bounded by ``timeout``
    seconds overall). Without it, only candidates already present in the
    indicator database or in observed traffic are reported.
    """
    domains = [d.lower() for d in (domains or settings.THREATDASH_ORG_DOMAINS) if d]
    now = timezone.now()
    findings = []
    for domain in domains:
        candidates = typosquat_candidates(domain)
        names = [c["domain"] for c in candidates]
        technique = {c["domain"]: c["technique"] for c in candidates}
        seen_in_intel = set(Indicator.objects.filter(ioc_type=IOCType.DOMAIN, value__in=names)
                            .values_list("value", flat=True))
        seen_in_traffic = set(TelemetryEvent.objects.filter(domain_name__in=names).values_list("domain_name", flat=True))
        resolved = {}
        if resolve:
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                futures = {pool.submit(_resolves, name): name for name in names[:max_lookups]}
                try:
                    for future in concurrent.futures.as_completed(futures, timeout=timeout):
                        addresses = future.result()
                        if addresses:
                            resolved[futures[future]] = addresses
                except concurrent.futures.TimeoutError:
                    pass
        for name in sorted(seen_in_intel | seen_in_traffic | set(resolved)):
            in_traffic = name in seen_in_traffic
            severity = Severity.HIGH if in_traffic or name in seen_in_intel else Severity.MEDIUM
            exposure, created = _upsert_exposure(
                f"typosquat:{name}",
                kind=ExternalExposure.Kind.TYPOSQUAT,
                title=f"Look-alike domain {name} targets {domain}",
                detail=f"Generated by {technique[name]}. "
                       + ("Seen in your network traffic. " if in_traffic else "")
                       + ("Present in threat intelligence. " if name in seen_in_intel else "")
                       + (f"Resolves to {', '.join(resolved[name])}." if name in resolved else ""),
                severity=severity, source="typosquat-scanner", observed_at=now,
                data={"domain": name, "target": domain, "technique": technique[name],
                      "addresses": resolved.get(name, []), "seen_in_traffic": in_traffic,
                      "in_threat_intel": name in seen_in_intel},
            )
            findings.append({"exposure": exposure.pk, "domain": name, "created": created})
    return findings


def _sha1_prefix(secret):
    return hashlib.sha1(secret.encode("utf-8", "replace")).hexdigest()[:5].upper()  # noqa: S324 - k-anonymity only


def _mask_email(email):
    local, _, domain = email.partition("@")
    return f"{local[:2]}{'*' * max(len(local) - 2, 1)}@{domain}"


def parse_credential_dump(text):
    """Parse ``email:password`` / ``email,password`` lines or a JSON list into records."""
    import json

    text = text.strip()
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RecordError(f"Invalid JSON: {exc.msg}") from exc
        return [r for r in data if isinstance(r, dict)]
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([^\s:,;|]+@[^\s:,;|]+)[\s:,;|]+(.*)$", line)
        if match:
            records.append({"email": match.group(1), "password": match.group(2)})
        elif "@" in line:
            records.append({"email": line})
    return records


def ingest_leaked_credentials(records, breach_name="", source="", domains=None):
    """Record leaked credentials for the organisation's domains. Plaintext passwords are discarded."""
    domains = {d.lower() for d in (domains or settings.THREATDASH_ORG_DOMAINS)}
    known_users = set(TelemetryEvent.objects.exclude(username="").values_list("username", flat=True).distinct()[:50000])
    created = matched = skipped = 0
    for record in records:
        email = str(record.get("email") or record.get("username") or "").strip().lower()
        if "@" not in email:
            skipped += 1
            continue
        email_domain = email.rpartition("@")[2]
        if domains and not any(email_domain == d or email_domain.endswith("." + d) for d in domains):
            skipped += 1
            continue
        matched += 1
        password = record.pop("password", None) or ""
        breach = str(record.get("breach") or breach_name or "unknown breach")[:120]
        active = email in known_users
        privileged = bool(PRIVILEGED_MAILBOXES.match(email.partition("@")[0]))
        severity = Severity.CRITICAL if privileged and password else Severity.HIGH if password or active \
            else Severity.MEDIUM
        _, was_created = _upsert_exposure(
            f"cred:{email}:{breach}",
            kind=ExternalExposure.Kind.LEAKED_CREDENTIAL,
            title=f"Credential for {_mask_email(email)} exposed in {breach}",
            detail=("A password was included. " if password else "Email only. ")
                   + ("This account is active in your identity telemetry. " if active else "")
                   + ("Privileged mailbox." if privileged else ""),
            severity=severity, source=str(source or record.get("source") or "credential-dump")[:120],
            observed_at=parse_timestamp(record.get("date") or record.get("observed_at")) or timezone.now(),
            data={"email": email, "breach": breach, "password_included": bool(password),
                  "password_sha1_prefix": _sha1_prefix(password) if password else None,
                  "active_account": active, "privileged": privileged},
        )
        created += was_created
    return {"received": len(records), "matched_org": matched, "created": created, "skipped": skipped}


def ingest_dark_web(records, source="dark-web-feed"):
    """Store dark-web / external telemetry records (forum posts, marketplace listings, leak-site entries)."""
    kinds = set(ExternalExposure.Kind.values)
    created = errors = 0
    for record in records:
        if not isinstance(record, dict) or not record.get("title"):
            errors += 1
            continue
        kind = record.get("kind") if record.get("kind") in kinds else ExternalExposure.Kind.DARK_WEB_MENTION
        sev = record.get("severity")
        severity = sev if sev in Severity.values else {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            str(sev).lower(), Severity.MEDIUM)
        try:
            observed = parse_timestamp(record.get("observed_at") or record.get("date")) or timezone.now()
        except RecordError:
            observed = timezone.now()
        _, was_created = _upsert_exposure(
            f"{kind}:{record.get('source', source)}:{record.get('url', '')}:{record['title']}",
            kind=kind, title=str(record["title"])[:300], detail=str(record.get("detail", ""))[:5000],
            severity=severity, source=str(record.get("source") or source)[:120], observed_at=observed,
            data={k: v for k, v in record.items() if k in ("url", "actor", "forum", "price", "records", "tags")},
        )
        created += was_created
    return {"received": len(records), "created": created, "errors": errors}
