"""Sign-in, first-run setup and account routes (Req 16).

Two routers:

- :data:`public_router` -- the only ``/api/auth`` routes reachable without a
  session: reading the auth state, completing setup, signing in and signing
  out. Together with ``GET /api/health`` these are the whole public allowlist,
  and ``tests/test_auth_enforcement.py`` pins that list (Property 12).
- :data:`account_router` -- password change and API tokens, protected at router
  level like every other router.

Failures that could help someone guess -- a wrong password, an unknown username
-- all produce the same message, and repeated failures are throttled per client
address and username (Req 16.2, 16.8).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import config
from ..auth.dependencies import (
    SESSION_COOKIE,
    login_required,
    require_principal,
    resolve_principal,
)
from ..auth.service import (
    SESSION_ABSOLUTE,
    AuthError,
    AuthService,
    Principal,
    WrongSecretError,
)
from ..auth.throttle import throttle
from .dependencies import get_session
from .schemas import (
    ApiTokenCreatedOut,
    ApiTokenIn,
    ApiTokenOut,
    AuthStateOut,
    LoginIn,
    PasswordChangeIn,
    SetupIn,
)

logger = logging.getLogger(__name__)
security_log = logging.getLogger("app.security")

public_router = APIRouter(prefix="/api/auth", tags=["auth"])
account_router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
    dependencies=[Depends(require_principal)],
)

_BAD_LOGIN = "Incorrect username or password."
#: Throttle key for setup attempts, which have no username yet.
_SETUP_KEY = "\x00setup"


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_session_cookie(request: Request, response: Response, token: str) -> None:
    mode = config.cookie_secure()
    secure = mode == "true" or (mode == "auto" and request.url.scheme == "https")
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_ABSOLUTE.total_seconds()),
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _refuse_if_throttled(request: Request, key: str) -> None:
    wait = throttle.retry_after(_client(request), key)
    if wait:
        # Req 16.19: a lockout is the one sign of a guessing attack in progress.
        security_log.warning(
            "Refused %s from %s: throttled for %d more seconds.",
            request.url.path, _client(request), wait,
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {wait} seconds.",
            headers={"Retry-After": str(wait)},
        )


def _require_login_mode() -> None:
    if not login_required():
        raise HTTPException(status_code=409, detail="Login is not required on this instance.")


@public_router.get("/state", response_model=AuthStateOut)
def auth_state(request: Request, session: Session = Depends(get_session)) -> AuthStateOut:
    """What to show first: setup, sign-in, or the dashboard (Req 16.3)."""
    if not login_required():
        return AuthStateOut(state="open")
    if not AuthService(session).has_users():
        return AuthStateOut(state="setup_required")
    principal = resolve_principal(request)
    if principal is None:
        return AuthStateOut(state="signed_out")
    return AuthStateOut(state="signed_in", username=principal.username, via=principal.kind)


@public_router.post("/setup", response_model=AuthStateOut)
def complete_setup(
    body: SetupIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AuthStateOut:
    """Create the first account with the logged setup code (Req 16.3)."""
    _require_login_mode()
    _refuse_if_throttled(request, _SETUP_KEY)
    service = AuthService(session)
    try:
        user = service.complete_setup(body.setup_code, body.username, body.password)
    except AuthError as exc:
        session.rollback()
        if isinstance(exc, WrongSecretError):
            throttle.record_failure(_client(request), _SETUP_KEY)
            logger.warning("Setup refused from %s: invalid setup code.", _client(request))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = service.start_session(user)
    session.commit()
    throttle.record_success(_client(request), _SETUP_KEY)
    logger.info("Setup complete: account %r created from %s.", user.username, _client(request))
    _set_session_cookie(request, response, token)
    return AuthStateOut(state="signed_in", username=user.username, via="session")


@public_router.post("/login", response_model=AuthStateOut)
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AuthStateOut:
    """Sign in and receive a session cookie (Req 16.2)."""
    _require_login_mode()
    _refuse_if_throttled(request, body.username)
    service = AuthService(session)
    user = service.authenticate(body.username, body.password)
    if user is None:
        session.rollback()
        throttle.record_failure(_client(request), body.username)
        logger.warning("Failed sign-in for %r from %s.", body.username[:64], _client(request))
        raise HTTPException(status_code=401, detail=_BAD_LOGIN)
    token = service.start_session(user)
    session.commit()
    throttle.record_success(_client(request), body.username)
    logger.info("Signed in: %r from %s.", user.username, _client(request))
    _set_session_cookie(request, response, token)
    return AuthStateOut(state="signed_in", username=user.username, via="session")


@public_router.post("/logout", status_code=204)
def logout(request: Request, session: Session = Depends(get_session)) -> Response:
    """End this browser's session. Safe to call when not signed in."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        AuthService(session).end_session(cookie)
        session.commit()
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def _session_principal(principal: Principal = Depends(require_principal)) -> Principal:
    """Account changes need a signed-in person, not a script's token."""
    if principal.kind == "token":
        raise HTTPException(
            status_code=403,
            detail="Sign in to the dashboard to manage the account; API tokens cannot.",
        )
    if principal.kind != "session":
        raise HTTPException(status_code=409, detail="Login is not required on this instance.")
    return principal


@account_router.put("/password", status_code=204)
def change_password(
    body: PasswordChangeIn,
    request: Request,
    principal: Principal = Depends(_session_principal),
    session: Session = Depends(get_session),
) -> Response:
    """Change the password and sign out every other session (Req 16.6)."""
    assert principal.username is not None
    _refuse_if_throttled(request, principal.username)
    try:
        AuthService(session).change_password(
            principal.username,
            body.current_password,
            body.new_password,
            keep_session_hash=principal.session_token_hash,
        )
    except AuthError as exc:
        session.rollback()
        if isinstance(exc, WrongSecretError):
            throttle.record_failure(_client(request), principal.username)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    session.commit()
    logger.info("Password changed for %r; other sessions signed out.", principal.username)
    return Response(status_code=204)


def _token_out(row) -> ApiTokenOut:
    return ApiTokenOut(
        token_id=row.id,
        name=row.name,
        prefix=row.prefix,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
    )


@account_router.get("/tokens", response_model=list[ApiTokenOut])
def list_tokens(
    _: Principal = Depends(_session_principal),
    session: Session = Depends(get_session),
) -> list[ApiTokenOut]:
    return [_token_out(row) for row in AuthService(session).list_api_tokens()]


@account_router.post("/tokens", response_model=ApiTokenCreatedOut, status_code=201)
def create_token(
    body: ApiTokenIn,
    principal: Principal = Depends(_session_principal),
    session: Session = Depends(get_session),
) -> ApiTokenCreatedOut:
    """Create an API token. The response is the only time it is shown (Req 16.7)."""
    try:
        row, token = AuthService(session).create_api_token(body.name)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    session.commit()
    logger.info("API token %r created by %r.", row.name, principal.username)
    return ApiTokenCreatedOut(**_token_out(row).model_dump(), token=token)


@account_router.delete("/tokens", status_code=200)
def revoke_all_tokens(
    principal: Principal = Depends(_session_principal),
    session: Session = Depends(get_session),
) -> dict[str, int]:
    """Revoke every API token at once (Req 16.18).

    For when a token may have leaked and nobody knows which: revoking them one
    by one means knowing which one to worry about.
    """
    revoked = AuthService(session).revoke_all_api_tokens()
    session.commit()
    security_log.warning("All %d API token(s) revoked by %r.", revoked, principal.username)
    return {"revoked": revoked}


@account_router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(
    token_id: str,
    principal: Principal = Depends(_session_principal),
    session: Session = Depends(get_session),
) -> Response:
    if not AuthService(session).revoke_api_token(token_id):
        raise HTTPException(status_code=404, detail="No such token.")
    session.commit()
    logger.info("API token %s revoked by %r.", token_id, principal.username)
    return Response(status_code=204)
