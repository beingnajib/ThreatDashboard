"""One-time startup tasks for platforms with no deploy hook (e.g. Vercel).

On a cold start the serverless function applies pending migrations and makes
sure the administrator from DJANGO_SUPERUSER_* exists. A Postgres advisory
lock stops concurrent cold starts from migrating at the same time. Failures
are logged rather than raised so the app can still report its health.
"""
import contextlib
import logging
import os

from django.conf import settings
from django.core.management import call_command
from django.db import connection

logger = logging.getLogger(__name__)
LOCK_KEY = 0x7D5B0071  # arbitrary, stable advisory-lock id for this app
_done = False


@contextlib.contextmanager
def _migration_lock():
    if connection.vendor != "postgresql":
        yield
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_lock(%s)", [LOCK_KEY])
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s)", [LOCK_KEY])


def ensure_superuser():
    """Create the DJANGO_SUPERUSER_* account if it doesn't exist. Never resets an existing password."""
    from django.contrib.auth import get_user_model
    from django.contrib.auth.models import Group

    username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "").strip()
    password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")
    if not username or not password:
        return None
    User = get_user_model()
    if User.objects.filter(username=username).exists():
        return None
    user = User.objects.create_superuser(username=username, password=password,
                                         email=os.environ.get("DJANGO_SUPERUSER_EMAIL", ""))
    groups = [Group.objects.get_or_create(name=name)[0] for name in ("responders", "forensics")]
    user.groups.add(*groups)
    logger.info("Created administrator %s", username)
    return user


def bootstrap():
    global _done
    if _done or not getattr(settings, "THREATDASH_AUTO_MIGRATE", False):
        return
    try:
        with _migration_lock():
            call_command("migrate", interactive=False, verbosity=0)
            ensure_superuser()
        _done = True
    except Exception:  # noqa: BLE001 - keep serving; /api/health/ will show the DB state
        logger.exception("Startup bootstrap failed")
