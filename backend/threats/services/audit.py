from ..models import AuditLog


def client_ip(request):
    if request is None:
        return None
    # Same rule as the rate limiter: with DJANGO_BEHIND_PROXY on, the client IP is
    # taken NUM_PROXIES entries from the right of X-Forwarded-For (entries the
    # client added itself are ignored); otherwise REMOTE_ADDR.
    from rest_framework.throttling import BaseThrottle

    return BaseThrottle().get_ident(request) or None


def audit(request_or_user, action, target="", **detail):
    request = request_or_user if hasattr(request_or_user, "META") else None
    user = getattr(request, "user", None) if request is not None else request_or_user
    if user is not None and not getattr(user, "is_authenticated", False):
        user = None
    return AuditLog.objects.create(
        actor=user,
        actor_name=getattr(user, "username", "") or "system",
        action=action,
        target=str(target)[:300],
        detail=detail,
        ip_address=client_ip(request),
    )
