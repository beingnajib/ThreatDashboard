"""Risk scoring.

The risk score (0-100) blends:

* severity — the analyst/feed assessment of impact, or the CVSS base score
  for vulnerabilities when that is higher,
* confidence — how sure we are the indicator is malicious,
* source reliability — the Admiralty grade of the supplying source,
* recency — exponential decay since the indicator was last seen,
* sightings — repeated observations raise the score logarithmically,
* context — MITRE ATT&CK mappings and suspicious enrichment findings,
* lifecycle — mitigated / expired / false-positive indicators are discounted.
"""
import math

from django.conf import settings
from django.utils import timezone

from .enrichment import suspicion_flags

SEVERITY_BASE = {1: 20, 2: 45, 3: 70, 4: 90}
RELIABILITY_FACTOR = {"A": 1.0, "B": 0.95, "C": 0.85, "D": 0.75, "E": 0.6, "F": 0.8}
STATUS_FACTOR = {"active": 1.0, "investigating": 1.0, "mitigated": 0.3, "expired": 0.2, "false_positive": 0.0}


def recency_factor(last_seen, now=None):
    if not last_seen:
        return 1.0
    now = now or timezone.now()
    age_days = max((now - last_seen).total_seconds() / 86400, 0)
    half_life = max(settings.THREATDASH_RISK_HALF_LIFE_DAYS, 1)
    return max(0.5 ** (age_days / half_life), 0.35)


def score_breakdown(indicator, now=None):
    """Return the score and each contributing factor, for display and auditing."""
    base = SEVERITY_BASE.get(int(indicator.severity or 2), 45)
    cvss = getattr(indicator, "cvss_score", None)
    if cvss is not None:
        # Standardised CVSS severity overrides a lower analyst rating.
        base = max(base, int(float(cvss) * 10))
    confidence = 0.5 + min(max(int(indicator.confidence or 0), 0), 100) / 200
    source = getattr(indicator, "source", None)
    reliability = RELIABILITY_FACTOR.get(getattr(source, "reliability", "F"), 0.8)
    recency = recency_factor(indicator.last_seen, now)
    sightings_bonus = min(3 * math.log2(max(int(indicator.sighting_count or 1), 1)), 10)
    mitre_bonus = min(2 * len(indicator.mitre_techniques or []), 6)
    flags = suspicion_flags(indicator.enrichment or {})
    enrichment_bonus = min(3 * len(flags), 9)
    lifecycle = STATUS_FACTOR.get(indicator.status, 1.0)

    raw = base * confidence * reliability * recency + sightings_bonus + mitre_bonus + enrichment_bonus
    score = int(round(min(max(raw * lifecycle, 0), 100)))
    return {
        "score": score,
        "severity_base": base,
        "cvss_score": float(cvss) if cvss is not None else None,
        "confidence_factor": round(confidence, 3),
        "reliability_factor": reliability,
        "recency_factor": round(recency, 3),
        "sightings_bonus": round(sightings_bonus, 2),
        "mitre_bonus": mitre_bonus,
        "enrichment_bonus": enrichment_bonus,
        "enrichment_flags": flags,
        "lifecycle_factor": lifecycle,
    }


def compute_risk_score(indicator, now=None):
    return score_breakdown(indicator, now)["score"]


def risk_band(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
