"""Guarded outbound HTTP for feeds and response webhooks (SSRF protection).

Only http(s) is allowed, every redirect hop is re-validated, and, unless the
caller opts in, destinations that resolve to loopback, private, link-local
(cloud metadata at 169.254.169.254) or other non-public addresses are refused.
"""
import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class UnsafeURLError(ValueError):
    pass


def validate_outbound_url(url, allow_private=False):
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise UnsafeURLError("Only http and https URLs are allowed.")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host.")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise UnsafeURLError(f"Cannot resolve {host}: {exc}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not address.is_global:
            raise UnsafeURLError(
                f"{host} resolves to the non-public address {address}; "
                "set THREATDASH_FEED_ALLOW_PRIVATE_NETWORKS=1 to allow internal feeds."
            )


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_private, max_redirects):
        super().__init__()
        self.allow_private = allow_private
        self.allowed_redirects = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.allowed_redirects <= 0:
            raise urllib.error.HTTPError(newurl, code, "Redirects are not allowed for this request.", headers, fp)
        try:
            validate_outbound_url(newurl, self.allow_private)
        except UnsafeURLError as exc:
            raise urllib.error.HTTPError(newurl, code, f"Blocked redirect: {exc}", headers, fp) from exc
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(request, timeout, allow_private=False, max_redirects=5):
    """``urlopen`` that refuses unsafe schemes, destinations and redirect targets."""
    validate_outbound_url(request.full_url, allow_private)
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),  # honours HTTP(S)_PROXY for egress-controlled deployments
        urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(), _GuardedRedirectHandler(allow_private, max_redirects),
    ):
        opener.add_handler(handler)
    return opener.open(request, timeout=timeout)
