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

from .. import config
from ..api.dependencies import get_session
from .service import AuthService, Principal

SESSION_COOKIE = "cvedeck_session"

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def login_required() -> bool:
    """Whether this deployment asks for a login at all (Req 16.9, 16.11).

    Demo mode is a public, read-mostly showcase with its dangerous routes
    already refused, so it stays open.
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


def require_principal(request: Request) -> Principal:
    """Refuse the request unless it is signed in (Req 16.1, 16.10)."""
    principal = resolve_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Sign in to use CveDeck.",
            headers={"WWW-Authenticate": 'Bearer realm="CveDeck"'},
        )
    if (
        principal.kind == "session"
        and request.method.upper() not in _SAFE_METHODS
        and not _same_origin(request)
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "This request did not come from the CveDeck dashboard, so it was "
                "refused. Scripts should use an API token instead of a browser cookie."
            ),
        )
    return principal
