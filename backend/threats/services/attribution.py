"""Threat-actor attribution.

Scores each known actor against the evidence in an incident or indicator:

* shared indicators (file hashes, IPs, domains) — strongest signal,
* overlap between observed ATT&CK techniques and the actor's known TTPs,
* malware families named in tags.

The result is a ranked list with a 0-100 confidence and the evidence behind
it. Attribution is an analytical aid, not proof; the UI presents it as such.
"""
from ..models import ThreatActor

IOC_WEIGHT = 0.55
TTP_WEIGHT = 0.30
MALWARE_WEIGHT = 0.15


def _parents(techniques):
    techniques = {t.upper() for t in techniques if t}
    return techniques | {t.split(".")[0] for t in techniques}


def score_actor(actor, indicator_ids, techniques, tags, actor_indicator_ids=None):
    actor_iocs = actor_indicator_ids if actor_indicator_ids is not None else set(
        actor.indicators.values_list("pk", flat=True))
    shared_iocs = indicator_ids & actor_iocs
    observed = _parents(techniques)
    known = _parents(actor.mitre_techniques or [])
    shared_ttps = sorted(observed & known)
    families = {f.lower() for f in actor.malware_families or []}
    names = {actor.name.lower(), *[a.lower() for a in actor.aliases or []]}
    shared_malware = sorted((families | names) & {t.lower() for t in tags})

    ioc_score = min(len(shared_iocs) / 2, 1.0) if shared_iocs else 0.0
    ttp_score = (len(shared_ttps) / len(observed)) if observed else 0.0
    malware_score = 1.0 if shared_malware else 0.0
    confidence = round(100 * (IOC_WEIGHT * ioc_score + TTP_WEIGHT * ttp_score + MALWARE_WEIGHT * malware_score))
    return {
        "actor_id": actor.pk,
        "name": actor.name,
        "actor_type": actor.actor_type,
        "aliases": actor.aliases,
        "origin_country": actor.origin_country,
        "confidence": confidence,
        "evidence": {
            "shared_indicators": sorted(shared_iocs),
            "shared_techniques": shared_ttps,
            "malware_families": shared_malware,
        },
    }


def attribute(indicator_ids, techniques, tags, limit=5, min_confidence=10):
    indicator_ids, techniques, tags = set(indicator_ids), set(techniques), set(tags)
    if not (indicator_ids or techniques or tags):
        return []
    actors = ThreatActor.objects.prefetch_related("indicators")
    results = [
        score_actor(actor, indicator_ids, techniques, tags, {i.pk for i in actor.indicators.all()})
        for actor in actors
    ]
    results = [r for r in results if r["confidence"] >= min_confidence]
    results.sort(key=lambda r: r["confidence"], reverse=True)
    return results[:limit]


def attribute_indicator(indicator):
    return attribute({indicator.pk}, indicator.mitre_techniques or [], indicator.tags or [])


def attribute_incident(incident):
    alerts = list(incident.alerts.select_related("indicator", "event"))
    indicator_ids, techniques, tags = set(), set(incident.mitre_techniques or []), set()
    for alert in alerts:
        techniques |= set(alert.mitre_techniques or [])
        if alert.indicator_id:
            indicator_ids.add(alert.indicator_id)
            tags |= set(alert.indicator.tags or [])
            techniques |= set(alert.indicator.mitre_techniques or [])
        if alert.event_id and alert.event:
            indicator_ids |= set(alert.event.matched_indicators.values_list("pk", flat=True))
            if alert.event.mitre_technique:
                techniques.add(alert.event.mitre_technique)
    return attribute(indicator_ids, techniques, tags)
