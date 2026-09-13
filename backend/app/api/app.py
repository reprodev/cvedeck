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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .. import config
from . import actions, routes
from .dependencies import get_scanner_engine, get_sync_service

# Keep in step with the newest released heading in CHANGELOG.md. This is what
# GET /api/health reports, and it sat at 0.1.0 through three releases.
_VERSION = "0.6.0"


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
    app = FastAPI(
        title="CveDeck API",
        version=_VERSION,
        description=(
            "Outward-facing API exposing scanned machines and CVE findings."
        ),
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
    def health() -> dict[str, object]:
        """Liveness probe for container orchestrators and reverse proxies.

        Also reports deployment capabilities the dashboard needs in order to
        decide what to offer. ``server_ssh_key`` gates the fleet re-scan
        controls (Req 13.2, 13.3): without a server-managed key those scans
        have no credentials, so the UI hides the buttons rather than showing
        them and failing. ``demo_mode`` is reported per Req 15.4.
        """
        from .. import config

        return {
            "status": "ok",
            "version": _VERSION,
            "capabilities": {
                "server_ssh_key": config.default_ssh_key_path() is not None,
                "default_ssh_user": config.default_ssh_user() is not None,
                # The UI uses this to say so plainly and to stop offering
                # controls the server will refuse -- better than letting
                # someone fill in a scan form that always 403s.
                "demo_mode": config.demo_mode(),
            },
        }

    app.include_router(routes.router)
    app.include_router(actions.router)

    if wire_production:
        # Imported here so the bare application never pulls in deployment-only
        # wiring (and its paramiko/pywinrm transports).
        from . import wiring

        app.dependency_overrides[get_scanner_engine] = wiring.build_scanner_engine
        app.dependency_overrides[get_sync_service] = wiring.build_sync_service
        _mount_frontend(app)

    return app


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
