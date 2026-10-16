from ..models import AuditLog


def client_ip(request):
    if request is None:
        return None
    # REMOTE_ADDR is set by the WSGI server; when DJANGO_BEHIND_PROXY is on the
    # proxy is trusted to have overwritten X-Forwarded-For.
    from django.conf import settings

    if getattr(settings, "USE_X_FORWARDED_HOST", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None


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
