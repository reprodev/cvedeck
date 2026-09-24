"""Response headers and the Host check, applied to every request (Req 16.15, 16.17).

Both are plain ASGI middleware rather than Starlette's ``BaseHTTPMiddleware``,
so they add no task per request and cannot swallow a streaming response.

The headers are what a browser needs to be told, because it cannot work them
out for itself: that this page may not be framed by another site, that a
response is the type it says it is, that it runs only its own scripts, and that
it sends no referrer when a user follows an advisory link out of it.

The Host check is the one defence against DNS rebinding. A page on another site
can point its own hostname at an address on the victim's network; the browser
then treats the dashboard as same-origin with that page, so an Origin check
passes -- but the ``Host`` header still carries the attacker's name. With login
switched off, nothing else stands between that page and a scan using the
server's own SSH key.
"""

from __future__ import annotations

import logging

from .. import config

logger = logging.getLogger("app.security")

#: The one policy, for every response. Nothing is loaded from anywhere but this
#: origin -- no CDN, no inline script, no inline style. The built index has none,
#: and React's style props go through the CSSOM, which ``style-src`` does not
#: govern. Until 0.8.14 the Swagger page needed an exception for jsDelivr and
#: inline script; the page was removed rather than excepted (Req 16.21).
DASHBOARD_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
_CSP_HEADER = DASHBOARD_CSP.encode("latin-1")

_COMMON_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (
        b"permissions-policy",
        b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        b"interest-cohort=()",
    ),
]

#: Always accepted by the Host check, so the container's own health check and a
#: shell on the host keep working however the allowlist is written.
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


class SecurityHeadersMiddleware:
    """Add the browser security headers to every HTTP response (Req 16.15)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        async def send_with_headers(message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"content-security-policy"
                ]
                headers.append((b"content-security-policy", _CSP_HEADER))
                present = {name.lower() for name, _ in headers}
                headers.extend(h for h in _COMMON_HEADERS if h[0] not in present)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def host_name(host_header: str) -> str:
    """The name in a ``Host`` header, without its port, lower-cased.

    Handles a bracketed IPv6 literal (``[::1]:8000``), which a naive split on
    ``:`` reduces to ``[``.
    """
    value = host_header.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end != -1 else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def host_allowed(host_header: str, allowed: list[str]) -> bool:
    """Whether ``host_header`` names this instance (Req 16.17).

    An entry ``*.example.com`` matches any subdomain, not the bare domain.
    """
    name = host_name(host_header)
    if not name:
        return False
    if name in _LOOPBACK:
        return True
    for entry in allowed:
        if entry.startswith("*."):
            if name.endswith(entry[1:]):
                return True
        elif name == entry:
            return True
    return False


class AllowedHostsMiddleware:
    """Refuse a request whose ``Host`` is not this instance's (Req 16.17).

    Active only when ``CVEDECK_ALLOWED_HOSTS`` is set; defaulting it on would
    break every install reached by a LAN name nobody listed.
    """

    def __init__(self, app, allowed: list[str]) -> None:
        self.app = app
        self.allowed = allowed

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        host = ""
        for name, value in scope.get("headers", []):
            if name == b"host":
                host = value.decode("latin-1")
                break
        if host_allowed(host, self.allowed):
            await self.app(scope, receive, send)
            return
        logger.warning("Refused a request for host %r: not in CVEDECK_ALLOWED_HOSTS.", host[:100])
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = b'{"detail":"This host name is not configured for CveDeck."}'
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def install(app) -> None:
    """Add both middlewares to ``app``. The Host check runs first."""
    app.add_middleware(SecurityHeadersMiddleware)
    allowed = config.allowed_hosts()
    if allowed:
        app.add_middleware(AllowedHostsMiddleware, allowed=allowed)
