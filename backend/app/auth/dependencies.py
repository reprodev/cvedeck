"""The request-level gate every protected router uses (Req 16.1, 16.10).

:func:`require_principal` is attached to whole routers, not to individual
routes, so a route added later is protected without anyone remembering to ask
for it. ``tests/test_auth_enforcement.py`` walks the application's routes to
hold that line (Property 12).

A caller is accepted with either:

- the ``cvedeck_session`` cookie a browser receives at sign-in, or
- an ``Authorization: Bearer cvd_...`` API token.

A cookie is sent by the browser automatically, including on a request another
site triggers, so a cookie-authenticated request that changes something must
also come from this dashboard's own origin. A bearer token is never sent
automatically, so token requests are exempt from that check.
"""

from __future__ import annotations

import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

import logging

from .. import config
from ..api.dependencies import get_session
from .service import AuthService, Principal

SESSION_COOKIE = "cvedeck_session"

logger = logging.getLogger("app.security")

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def login_required() -> bool:
    """Whether this deployment asks for a login at all (Req 16.9, 16.11).

    Demo mode is a public, read-only showcase, so it stays open.

    That rests on ``actions.refuse_writes_in_demo_mode``, attached to the
    routers in ``create_app`` and pinned by a test that walks every route
    (Req 15.9). Do not reason about it from this docstring: through 0.8.8 it
    asserted the dangerous routes were "already refused" while one was not, and
    through 0.8.12 the per-route guards it then pointed at still left three
    write routes open. The sentence was the reason nobody looked.
    """
    return config.auth_enabled() and not config.demo_mode()


@contextmanager
def request_session(request: Request) -> Iterator[Session]:
    """A database session for auth checks, honouring test overrides.

    Resolved lazily rather than declared with ``Depends(get_session)``: an
    unauthenticated request is refused without opening the database at all, and
    the ``get_session`` override a test installs is still the one used.
    """
    provider = request.app.dependency_overrides.get(get_session, get_session)
    result = provider()
    if inspect.isgenerator(result):
        try:
            yield next(result)
        finally:
            result.close()
    else:
        yield result


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def resolve_principal(request: Request) -> Principal | None:
    """Who is making this request, or ``None`` if nobody has signed in."""
    if not login_required():
        return Principal(kind="open")
    token = bearer_token(request)
    cookie = request.cookies.get(SESSION_COOKIE)
    if not token and not cookie:
        return None
    with request_session(request) as session:
        service = AuthService(session)
        principal = (
            service.resolve_api_token(token) if token else service.resolve_session(cookie)
        )
        session.commit()
    if principal is None and token:
        # Req 16.19. An expired cookie is routine; a bearer token that does not
        # resolve is either revoked or guessed, and either is worth a line.
        logger.warning(
            "Refused an unknown or revoked API token on %s %s from %s.",
            request.method, request.url.path, _client(request),
        )
    return principal


def _same_origin(request: Request) -> bool:
    """Whether a state-changing request came from this dashboard's own page.

    Compares the ``Origin`` (or, failing that, ``Referer``) host with the
    ``Host`` the request was sent to. Only the host and port are compared, not
    the scheme, because behind a TLS-terminating proxy the browser says https
    while this process sees http. Origins listed in ``CVEDECK_CORS_ORIGINS`` are
    accepted too, for split deployments.
    """
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source or source == "null":
        return False
    parts = urlsplit(source)
    if not parts.netloc:
        return False
    host = request.headers.get("host", "")
    if parts.netloc.lower() == host.lower():
        return True
    allowed = {o.rstrip("/").lower() for o in config.cors_origins()}
    return f"{parts.scheme}://{parts.netloc}".lower() in allowed


def _cross_site(request: Request) -> bool:
    """Whether the request says it came from another site.

    For a caller that has not signed in -- login switched off -- absence is not
    evidence: ``curl`` and every other script send no ``Origin``, and they are
    the reason an operator runs without login behind a proxy. But a browser
    always sends ``Origin`` on a cross-site POST, and ``Sec-Fetch-Site`` when it
    supports it, so a request carrying either that names another site is one a
    page elsewhere made the user's browser send.
    """
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return True
    if request.headers.get("origin") or request.headers.get("referer"):
        return not _same_origin(request)
    return False


def require_principal(request: Request) -> Principal:
    """Refuse the request unless it is signed in (Req 16.1, 16.10)."""
    principal = resolve_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Sign in to use CveDeck.",
            headers={"WWW-Authenticate": 'Bearer realm="CveDeck"'},
        )
    # Kept so an action route can say who asked for it in the audit log.
    request.state.principal = principal
    if request.method.upper() in _SAFE_METHODS:
        return principal
    if principal.kind == "session" and not _same_origin(request):
        logger.warning(
            "Refused a cross-origin %s %s from %s.",
            request.method, request.url.path, _client(request),
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "This request did not come from the CveDeck dashboard, so it was "
                "refused. Scripts should use an API token instead of a browser cookie."
            ),
        )
    if principal.kind == "open" and _cross_site(request):
        # Login is off, so the browser sends no credential at all -- any page
        # the user visits could otherwise POST here (Req 16.16).
        logger.warning(
            "Refused a cross-site %s %s from %s while login is off.",
            request.method, request.url.path, _client(request),
        )
        raise HTTPException(
            status_code=403,
            detail="This request came from another site, so it was refused.",
        )
    return principal


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"
