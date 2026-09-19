"""FastAPI application factory for the Backend_API.

:func:`create_app` builds the outward-facing FastAPI application and mounts the
routers. It mounts the read router (machines and CVEs, task 8.1) and the action
router (POST scans/remediation/sync, PUT remediation, task 8.2); the action
router is a separate module so the read surface stays untouched.

All responses are Pydantic models serialized to JSON (Req 6.5), and unknown
machine ids return HTTP 404 (Req 6.4), handled within the routes.

A deployed process additionally asks for production wiring
(``create_app(wire_production=True)``, as the module-level ``app`` below does),
which installs the concrete scanner engine and sync service from
:mod:`app.api.wiring` and serves the built frontend when one is configured.
Callers that want the bare application -- tests included -- get today's
behavior from the default ``create_app()``.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import config
from ..auth.dependencies import login_required, require_principal, resolve_principal
from . import actions, auth_routes, routes
from .dependencies import get_engine, get_scanner_engine, get_sync_service

# Keep in step with the newest released heading in CHANGELOG.md. This is what
# GET /api/health reports, and it sat at 0.1.0 through three releases.
_VERSION = "0.8.9"


def create_app(*, wire_production: bool = False) -> FastAPI:
    """Create and configure the Backend_API FastAPI application.

    Returns a fresh app instance with the read and action routes mounted.
    Callers (and tests) may override the ``get_session``, ``get_scanner_engine``,
    and ``get_sync_service`` dependencies on the returned app to supply a
    specific database session, scanner engine, or sync service.

    Args:
        wire_production: When true, install the concrete scanner engine and sync
            service from :mod:`app.api.wiring`, apply the configured CORS
            origins, and serve the built frontend from the configured static
            directory. Left false, the application behaves exactly as it always
            has and the scan/sync dependencies remain unconfigured.
    """
    lifespan = _open_database_at_startup if wire_production else None
    app = FastAPI(
        lifespan=lifespan,
        title="CveDeck API",
        version=_VERSION,
        description=(
            "Outward-facing API exposing scanned machines and CVE findings."
        ),
        # FastAPI's defaults serve /docs, /redoc and /openapi.json to anyone.
        # They are re-served below under /api, behind sign-in (Req 16.1).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    origins = config.cors_origins() if wire_production else []
    if origins:
        # Only needed when the dashboard is served from a different origin than
        # the API; the single-container deployment shares one origin.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.get("/api/health", tags=["health"])
    def health(request: Request) -> dict[str, object]:
        """Liveness probe for container orchestrators and reverse proxies.

        Also reports deployment capabilities the dashboard needs in order to
        decide what to offer. ``server_ssh_key`` gates the fleet re-scan
        controls (Req 13.2, 13.3): without a server-managed key those scans
        have no credentials, so the UI hides the buttons rather than showing
        them and failing. ``demo_mode`` is reported per Req 15.4.

        Public, because container health checks and proxies call it without
        credentials. So it only describes the server's configuration to a
        caller who has signed in; everyone else gets status, version, demo mode
        and whether login is required (Req 16.1).
        """
        capabilities: dict[str, object] = {
            # The UI uses this to say so plainly and to stop offering
            # controls the server will refuse -- better than letting
            # someone fill in a scan form that always 403s.
            "demo_mode": config.demo_mode(),
            "login_required": login_required(),
            # Hours between automatic intel refreshes, or 0 when the deployment
            # drives it externally. Reported so an operator can tell "the feeds
            # are kept fresh for me" from "I still need a cron" without reading
            # the container's environment (Req 10.14).
            "feed_refresh_hours": config.feed_refresh_hours_in_effect(),
        }
        if not login_required() or resolve_principal(request) is not None:
            capabilities["server_ssh_key"] = config.default_ssh_key_path() is not None
            capabilities["default_ssh_user"] = config.default_ssh_user() is not None
        return {"status": "ok", "version": _VERSION, "capabilities": capabilities}

    # Every router except the public auth routes is protected here, at include
    # time, so a route added to any of them later is protected without anyone
    # remembering to ask (Req 16.1, Property 12).
    protected = [Depends(require_principal)]
    app.include_router(auth_routes.public_router)
    app.include_router(auth_routes.account_router)
    app.include_router(routes.router, dependencies=protected)
    app.include_router(actions.router, dependencies=protected)

    @app.get("/api/openapi.json", include_in_schema=False, dependencies=protected)
    def openapi_schema() -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/api/docs", include_in_schema=False, dependencies=protected)
    def api_docs():
        return get_swagger_ui_html(openapi_url="/api/openapi.json", title="CveDeck API")

    if wire_production:
        # Imported here so the bare application never pulls in deployment-only
        # wiring (and its paramiko/pywinrm transports).
        from . import wiring

        app.dependency_overrides[get_scanner_engine] = wiring.build_scanner_engine
        app.dependency_overrides[get_sync_service] = wiring.build_sync_service
        _configure_logging()
        _mount_frontend(app)

    return app


@asynccontextmanager
async def _open_database_at_startup(_: FastAPI):
    """Open the database when the process starts, not on the first request.

    Migrations run and the first-run setup code is printed as soon as the
    container starts, rather than when someone first loads the page.

    The periodic feed refresher starts here too, and is stopped on the way out
    (Req 10.14). It lives on this hook rather than its own because this hook is
    already the one that only runs for a wired production app -- a test app has
    no lifespan, so no test grows a background task it did not ask for.

    Demo mode switches the refresher off, alongside scanning, discovery and
    connection tests. Since 0.8.8 a refresh reapplies the feeds to stored
    findings (Req 10.15), and the demo fleet is seeded with findings whose
    exploitation status was deliberately never checked -- the unknown state the
    demo exists to show. An automatic refresh would enrich them on the first
    boot and quietly delete the illustration of the project's central
    invariant. Pressing "Refresh intel" still works, which is the demo's own
    intended sequence.
    """
    from ..services.feed_scheduler import (
        start_periodic_refresh,
        stop_periodic_refresh,
    )

    engine = get_engine()
    refresher = start_periodic_refresh(engine, config.feed_refresh_hours_in_effect())
    try:
        yield
    finally:
        await stop_periodic_refresh(refresher)


def _configure_logging() -> None:
    """Send the application's own log records to stderr, at INFO.

    uvicorn configures only its own loggers, so without this ``app.*`` records
    below WARNING -- sign-ins, token changes, demo seeding -- went nowhere.
    """
    app_logger = logging.getLogger("app")
    if app_logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)-7s [%(name)s] %(message)s"))
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False


class _CacheControlledStatic(StaticFiles):
    """StaticFiles that tells browsers which files may be cached.

    Without this, upgrading breaks the dashboard. The build emits
    content-hashed asset names (``index-Cm6R1LoG.js``), and ``index.html``
    names the current ones. A browser that caches ``index.html`` keeps asking
    for the hashes from the build it first saw; those files are gone after the
    next upgrade, so the page loads with no CSS and no JavaScript and renders
    blank. Nothing errors, the server logs 404s for files nobody recognises,
    and the only cure a user can find is clearing site data.

    The contract is the standard one for hashed builds, and the two halves are
    opposites on purpose:

    - ``index.html`` is revalidated on every load. It is small, and it is the
      only file that knows which assets are current.
    - Everything under ``/assets/`` is immutable for a year. The content hash
      is in the filename, so a changed file is a different URL and a cached one
      can never be stale.
    """

    def file_response(self, *args, **kwargs):  # type: ignore[override]
        response = super().file_response(*args, **kwargs)
        path = str(getattr(response, "path", ""))

        if path.endswith(".html"):
            # no-cache means "revalidate", not "do not store" -- a 304 keeps it
            # cheap while guaranteeing the asset names are current.
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        elif "/assets/" in path.replace("\\", "/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # Favicons and similar: cached, but not for a year, since their
            # names carry no hash.
            response.headers["Cache-Control"] = "public, max-age=3600"

        return response


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built frontend at the root when one is configured.

    The frontend calls ``/api/...`` relative to wherever it was served from, so
    serving it from this application is what makes a single-origin deployment
    work without a reverse proxy. Mounted after the routers so the API keeps
    precedence over the static files.
    """
    static_dir = config.static_dir()
    if static_dir is None or not static_dir.is_dir():
        return
    app.mount(
        "/",
        _CacheControlledStatic(directory=static_dir, html=True),
        name="frontend",
    )


# Module-level app for ASGI servers (e.g. `uvicorn app.api.app:app`).
app = create_app(wire_production=True)
