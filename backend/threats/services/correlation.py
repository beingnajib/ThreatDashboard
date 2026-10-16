"""Find indicators related to a given one, for analyst pivoting."""
import ipaddress
from urllib.parse import urlsplit

from django.db.models import Q

from ..models import Indicator, IOCType


def _host_of(indicator):
    if indicator.ioc_type == IOCType.URL:
        return (urlsplit(indicator.value).hostname or "").lower()
    if indicator.ioc_type == IOCType.DOMAIN:
        return indicator.value
    if indicator.ioc_type == IOCType.EMAIL:
        return indicator.value.rpartition("@")[2]
    return ""


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parent_domain(host):
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def related_indicators(indicator, limit=25):
    """Return ``[(indicator, [reasons])]`` ordered by number of shared links, then risk."""
    reasons = {}

    def add(queryset, reason):
        for other in queryset.exclude(pk=indicator.pk).select_related("source")[:200]:
            reasons.setdefault(other.pk, (other, []))[1].append(reason)

    host = _host_of(indicator)
    if host and not _is_ip(host):
        parent = _parent_domain(host)
        add(Indicator.objects.filter(ioc_type=IOCType.DOMAIN).filter(Q(value=parent) | Q(value__endswith=f".{parent}")),
            f"same domain ({parent})")
        add(Indicator.objects.filter(ioc_type=IOCType.URL, value__icontains=f"//{parent}")
            | Indicator.objects.filter(ioc_type=IOCType.URL, value__icontains=f".{parent}"),
            f"URL on {parent}")
        add(Indicator.objects.filter(ioc_type=IOCType.EMAIL, value__iendswith=f"@{parent}"), f"email at {parent}")

    if indicator.ioc_type == IOCType.IPV4:
        # IPv4 values are stored in canonical dotted-quad form, so a prefix
        # match on the first three octets is exactly the /24.
        network = ipaddress.ip_network(f"{indicator.value}/24", strict=False)
        prefix = ".".join(indicator.value.split(".")[:3]) + "."
        add(Indicator.objects.filter(ioc_type=IOCType.IPV4, value__startswith=prefix),
            f"same /24 network ({network})")
        add(Indicator.objects.filter(ioc_type=IOCType.URL, value__contains=f"//{indicator.value}"), "URL hosted on this IP")

    for tag in (indicator.tags or [])[:10]:
        add(Indicator.objects.filter(tags__contains=[tag]) if _supports_json_contains() else
            Indicator.objects.filter(tags__icontains=f'"{tag}"'), f"shared tag '{tag}'")
    for technique in (indicator.mitre_techniques or [])[:10]:
        add(Indicator.objects.filter(mitre_techniques__contains=[technique]) if _supports_json_contains() else
            Indicator.objects.filter(mitre_techniques__icontains=f'"{technique}"'), f"shared technique {technique}")
    if indicator.source_id:
        add(Indicator.objects.filter(source_id=indicator.source_id, threat_type=indicator.threat_type,
                                     first_seen__date=indicator.first_seen.date()),
            "same source, threat type and day")

    ranked = sorted(reasons.values(), key=lambda item: (len(item[1]), item[0].risk_score), reverse=True)
    return ranked[:limit]


def _supports_json_contains():
    from django.db import connection

    return connection.features.supports_json_field_contains
