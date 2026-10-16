from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from rest_framework import authentication, exceptions, permissions, throttling

from .models import DataConnector

RESPONDER_GROUPS = {"responders", "forensics"}
FORENSICS_GROUPS = {"forensics"}


def in_groups(user, names):
    if not user or not user.is_authenticated:
        return False
    return user.is_staff or user.groups.filter(name__in=names).exists()


class IsAuthenticatedStaffDelete(permissions.IsAuthenticated):
    """Any analyst may read and write; deleting records requires staff."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return request.method != "DELETE" or request.user.is_staff


class IsStaffOrReadOnly(permissions.IsAuthenticated):
    """Configuration that can reach the network or holds secrets is staff-only to change."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return request.method in permissions.SAFE_METHODS or request.user.is_staff


class IsStaff(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff


class CanRespond(permissions.IsAuthenticated):
    """Containment and remediation: staff or members of the 'responders' / 'forensics' groups."""

    message = "Response actions require membership of the 'responders' group."

    def has_permission(self, request, view):
        return super().has_permission(request, view) and in_groups(request.user, RESPONDER_GROUPS)


class CanUseTerminal(permissions.IsAuthenticated):
    message = "Live response requires membership of the 'forensics' group."

    def has_permission(self, request, view):
        return super().has_permission(request, view) and in_groups(request.user, FORENSICS_GROUPS)


class ConnectorKeyAuthentication(authentication.BaseAuthentication):
    """Authenticates log shippers with ``X-Ingest-Key: tdk_...`` (or ``Authorization: Ingest tdk_...``)."""

    def authenticate(self, request):
        key = request.META.get("HTTP_X_INGEST_KEY", "")
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not key and header.startswith("Ingest "):
            key = header[len("Ingest "):].strip()
        if not key:
            return None
        connector = DataConnector.objects.filter(key_prefix=key[:12], enabled=True).first()
        if connector is None or not connector.check_key(key):
            raise exceptions.AuthenticationFailed("Invalid or disabled ingestion key.")
        return AnonymousUser(), connector

    def authenticate_header(self, request):
        return "Ingest"


class IsAuthenticatedOrConnector(permissions.BasePermission):
    def has_permission(self, request, view):
        if isinstance(request.auth, DataConnector):
            return True
        return bool(request.user and request.user.is_authenticated)


def token_expired(token):
    ttl = settings.THREATDASH_TOKEN_TTL_HOURS
    return bool(ttl) and token.created < timezone.now() - timedelta(hours=ttl)


class ExpiringTokenAuthentication(authentication.TokenAuthentication):
    """DRF token auth with a maximum token age; expired tokens are deleted."""

    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token_expired(token):
            token.delete()
            raise exceptions.AuthenticationFailed("Session expired; sign in again.")
        return user, token


class IngestRateThrottle(throttling.SimpleRateThrottle):
    """Per-connector (or per-user) rate limit for the telemetry ingestion endpoint."""

    scope = "ingest"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, DataConnector):
            ident = f"connector-{request.auth.pk}"
        elif request.user and request.user.is_authenticated:
            ident = f"user-{request.user.pk}"
        else:
            ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
