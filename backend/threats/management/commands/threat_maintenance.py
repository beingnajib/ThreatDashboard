from django.core.management.base import BaseCommand
from django.utils import timezone

from threats.models import Indicator
from threats.services.assets import refresh_asset_risk
from threats.services.compliance import evaluate_controls


def run_maintenance(stdout=None):
    """Expire stale indicators, refresh time-decayed risk scores, asset risk and compliance."""
    now = timezone.now()
    expired = 0
    for indicator in Indicator.objects.select_related("source").filter(
        expires_at__lt=now, status__in=[Indicator.Status.ACTIVE, Indicator.Status.INVESTIGATING]
    ).iterator(chunk_size=500):
        indicator.status = Indicator.Status.EXPIRED
        indicator.save(update_fields=["status"])
        expired += 1
    rescored = 0
    for indicator in Indicator.objects.select_related("source").exclude(
            status=Indicator.Status.EXPIRED).iterator(chunk_size=500):
        previous = indicator.risk_score
        indicator.save(update_fields=["risk_score"])
        rescored += indicator.risk_score != previous
    assets = refresh_asset_risk()
    evaluate_controls(now)
    return {"expired": expired, "rescored": rescored, "assets_rescored": assets}


class Command(BaseCommand):
    help = "Expire indicators past their TTL, recompute risk scores and re-evaluate compliance controls."

    def handle(self, *args, **options):
        result = run_maintenance()
        self.stdout.write(self.style.SUCCESS(
            f"Expired {result['expired']}, re-scored {result['rescored']} indicators and "
            f"{result['assets_rescored']} assets; compliance re-evaluated."))
