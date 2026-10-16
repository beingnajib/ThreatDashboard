"""Offline enrichment of indicators.

Everything here is computed locally (no outbound lookups), so enrichment is
deterministic, fast and safe to run on untrusted input. It provides network
context for IPs and a lexical domain-generation-algorithm (DGA) heuristic for
domains and URL hosts.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

from ..models import IOCType

VOWELS = set("aeiou")
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "rest", "loan", "kim", "men", "date", "racing", "download", "review", "su", "cyou", "icu",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "buff.ly"}
SUSPICIOUS_URL_TOKENS = ("login", "verify", "account", "secure", "update", "wallet", "invoice", "signin", "password")
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".jar", ".bat", ".msi", ".hta", ".lnk", ".iso")


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def registered_label(domain):
    """The label just left of the TLD (``example`` in ``www.example.co``)."""
    labels = [label for label in domain.lower().split(".") if label]
    if len(labels) < 2:
        return labels[0] if labels else ""
    # Treat common two-part public suffixes (co.uk, com.au) as a single TLD.
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2]


def dga_score(domain):
    """Lexical likelihood (0-1) that ``domain`` was algorithmically generated."""
    label = registered_label(domain)
    if len(label) < 6 or label.startswith("xn--"):
        return 0.0
    letters = [c for c in label if c.isalpha()]
    entropy = shannon_entropy(label)
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    vowel_ratio = (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0
    longest_consonant_run = max((len(run) for run in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", label)), default=0)

    score = 0.0
    score += min(max((entropy - 2.5) / 1.5, 0.0), 1.0) * 0.40
    score += min(len(label) / 20, 1.0) * 0.15
    score += min(digit_ratio * 2.5, 1.0) * 0.15
    score += (1.0 - min(vowel_ratio / 0.35, 1.0)) * 0.15
    score += min(max(longest_consonant_run - 3, 0) / 4, 1.0) * 0.15
    return round(min(score, 1.0), 3)


def _domain_enrichment(domain):
    labels = domain.split(".")
    tld = labels[-1] if labels else ""
    score = dga_score(domain)
    return {
        "tld": tld,
        "subdomain_depth": max(len(labels) - 2, 0),
        "entropy": round(shannon_entropy(registered_label(domain)), 3),
        "dga_score": score,
        "dga_suspected": score >= 0.6,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "punycode": any(label.startswith("xn--") for label in labels),
    }


def _ip_enrichment(value):
    ip = ipaddress.ip_address(value)
    network = ipaddress.ip_network(f"{value}/{24 if ip.version == 4 else 64}", strict=False)
    return {
        "version": ip.version,
        "network": str(network),
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_loopback": ip.is_loopback,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
    }


def _url_enrichment(value):
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    data = {"scheme": parts.scheme, "host": host, "path": parts.path, "port": None}
    try:
        data["port"] = parts.port
    except ValueError:
        data["port"] = None
    try:
        ipaddress.ip_address(host)
        data["host_is_ip"] = True
    except ValueError:
        data["host_is_ip"] = False
        data.update({f"host_{k}": v for k, v in _domain_enrichment(host).items()})
    lowered = value.lower()
    data["shortener"] = host in URL_SHORTENERS
    data["credential_lure"] = any(token in lowered for token in SUSPICIOUS_URL_TOKENS)
    data["executable_download"] = parts.path.lower().endswith(EXECUTABLE_EXTENSIONS)
    data["insecure_scheme"] = parts.scheme == "http"
    return data


def enrich(ioc_type, value):
    """Return a JSON-serialisable dict of context for the indicator."""
    try:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return _ip_enrichment(value)
        if ioc_type == IOCType.DOMAIN:
            return _domain_enrichment(value)
        if ioc_type == IOCType.URL:
            return _url_enrichment(value)
        if ioc_type == IOCType.EMAIL:
            domain = value.rpartition("@")[2]
            return {"domain": domain, **{f"domain_{k}": v for k, v in _domain_enrichment(domain).items()}}
        if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return {"algorithm": ioc_type, "bits": len(value) * 4}
        if ioc_type == IOCType.CVE:
            _, year, number = value.split("-", 2)
            return {"year": int(year), "sequence": int(number)}
    except (ValueError, TypeError):
        pass
    return {}


def suspicion_flags(enrichment):
    """Names of the enrichment findings that should raise an indicator's risk."""
    flag_keys = (
        "dga_suspected", "suspicious_tld", "punycode",
        "host_dga_suspected", "host_suspicious_tld", "host_punycode",
        "domain_dga_suspected", "domain_suspicious_tld",
        "host_is_ip", "shortener", "credential_lure", "executable_download",
    )
    return [key for key in flag_keys if enrichment.get(key)]
