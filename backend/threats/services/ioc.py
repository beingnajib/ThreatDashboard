"""Detection, refanging and normalisation of indicator values."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from ..models import IOCType

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z0-9-]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$",
    re.IGNORECASE,
)
URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

HASH_LENGTHS = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}

_REFANG_REPLACEMENTS = [
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s\.\s", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\[://\]"), lambda m: m.group(0).strip("[]")),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
]


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
)]


def is_internal_ip(value):
    """True for addresses inside the organisation (RFC 1918, CGNAT, ULA, link-local, loopback).

    ``ipaddress.is_private`` is deliberately not used: it also covers the
    documentation and benchmarking ranges, which appear as external hosts in
    feeds and test data.
    """
    try:
        address = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return False
    return any(address in network for network in INTERNAL_NETWORKS if network.version == address.version)


class IOCError(ValueError):
    """Raised when a value cannot be recognised as a supported indicator."""


def refang(value):
    """Turn a defanged indicator (``hxxp://evil[.]com``) back into its real form."""
    value = (value or "").strip().strip("\"'<>")
    for pattern, replacement in _REFANG_REPLACEMENTS:
        value = pattern.sub(replacement, value)
    return value.strip()


def defang(ioc_type, value):
    """Make an indicator safe to paste into email or chat."""
    if ioc_type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.EMAIL):
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
        value = value.replace("@", "[@]")
        # Only defang the final dot so that the value stays readable.
        head, sep, tail = value.rpartition(".")
        if sep:
            value = f"{head}[.]{tail}"
    return value


def detect_type(value):
    """Best-effort classification of a raw indicator value."""
    value = refang(value)
    if not value:
        raise IOCError("Empty indicator value.")
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass
    if HEX_RE.match(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]
    if CVE_RE.match(value):
        return IOCType.CVE
    if URL_SCHEME_RE.match(value):
        return IOCType.URL
    if EMAIL_RE.match(value):
        return IOCType.EMAIL
    if DOMAIN_RE.match(value):
        return IOCType.DOMAIN
    raise IOCError(f"Could not determine the indicator type of {value[:80]!r}.")


def normalize(ioc_type, value):
    """Validate and canonicalise ``value`` for ``ioc_type``; returns the clean value."""
    value = refang(value)
    if not value:
        raise IOCError("Empty indicator value.")
    if len(value) > 2048:
        raise IOCError("Indicator value is longer than 2048 characters.")

    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        try:
            ip = ipaddress.ip_address(value.strip("[]"))
        except ValueError as exc:
            raise IOCError(f"{value[:80]!r} is not a valid IP address.") from exc
        expected = 4 if ioc_type == IOCType.IPV4 else 6
        if ip.version != expected:
            raise IOCError(f"{value!r} is not an IPv{expected} address.")
        return ip.compressed
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        expected_len = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}[ioc_type]
        if not HEX_RE.match(value) or len(value) != expected_len:
            raise IOCError(f"{value[:80]!r} is not a valid {ioc_type.upper()} hash.")
        return value.lower()
    if ioc_type == IOCType.CVE:
        if not CVE_RE.match(value):
            raise IOCError(f"{value[:80]!r} is not a valid CVE identifier.")
        return value.upper()
    if ioc_type == IOCType.EMAIL:
        if not EMAIL_RE.match(value):
            raise IOCError(f"{value[:80]!r} is not a valid email address.")
        local, _, domain = value.rpartition("@")
        return f"{local}@{domain.lower()}"
    if ioc_type == IOCType.DOMAIN:
        value = value.rstrip(".").lower()
        if not DOMAIN_RE.match(value):
            raise IOCError(f"{value[:80]!r} is not a valid domain name.")
        return value
    if ioc_type == IOCType.URL:
        if not URL_SCHEME_RE.match(value):
            raise IOCError(f"{value[:80]!r} is not a valid URL (missing scheme).")
        parts = urlsplit(value)
        if not parts.hostname:
            raise IOCError(f"{value[:80]!r} is not a valid URL (missing host).")
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
    raise IOCError(f"Unsupported indicator type {ioc_type!r}.")


def parse_indicator(value, ioc_type=None):
    """Return ``(ioc_type, normalised_value)``, detecting the type when not given."""
    resolved = resolve_type_alias(ioc_type, value) or detect_type(value)
    if resolved not in IOCType.values:
        raise IOCError(f"Unsupported indicator type {ioc_type!r}.")
    return resolved, normalize(resolved, value)


TYPE_ALIASES = {
    "ip": None,  # resolved by detection below
    "ipv4-addr": IOCType.IPV4,
    "ipv6-addr": IOCType.IPV6,
    "ip-dst": None,
    "ip-src": None,
    "hostname": IOCType.DOMAIN,
    "domain-name": IOCType.DOMAIN,
    "fqdn": IOCType.DOMAIN,
    "uri": IOCType.URL,
    "link": IOCType.URL,
    "sha-1": IOCType.SHA1,
    "sha-256": IOCType.SHA256,
    "email-addr": IOCType.EMAIL,
    "email-src": IOCType.EMAIL,
    "vulnerability": IOCType.CVE,
}


def resolve_type_alias(raw_type, value):
    """Map aliases such as ``ip`` / ``ip-dst`` / ``domain-name`` onto IOCType values."""
    key = (raw_type or "").strip().lower()
    if not key:
        return None
    if key in TYPE_ALIASES:
        alias = TYPE_ALIASES[key]
        return alias if alias is not None else detect_type(value)
    return key


def normalize_mitre(values):
    """Keep only well-formed ATT&CK technique IDs (``T1059`` / ``T1059.001``)."""
    result = []
    for item in values or []:
        item = str(item).strip().upper()
        if MITRE_RE.match(item) and item not in result:
            result.append(item)
    return result


def normalize_tags(values):
    if isinstance(values, str):
        values = re.split(r"[,;|]", values)
    result = []
    for item in values or []:
        tag = str(item).strip().lower()[:64]
        if tag and tag not in result:
            result.append(tag)
    return result[:50]
