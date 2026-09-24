"""Property 12: every API route outside the public allowlist refuses an anonymous caller.

Validates Req 16.1.

This walks the routes of the real application rather than listing endpoints by
hand, so a route added next month is covered the day it is written. The
application is built with no auth override -- the production gate, as deployed.

The allowlist is pinned in both directions: nothing outside it is reachable
anonymously, and everything on it still exists, so the list cannot quietly go
stale and start excusing a route that has been renamed into its place.
"""

from __future__ import annotations

import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api import actions, auth_routes, routes
from app.api.app import create_app

PUBLIC = {
    ("GET", "/api/health"),
    ("GET", "/api/auth/state"),
    ("POST", "/api/auth/setup"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
}


@pytest.fixture(autouse=True)
def _login_on(monkeypatch):
    monkeypatch.delenv("CVEDECK_AUTH", raising=False)
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)


def _api_routes(app) -> list[tuple[str, str]]:
    """Every (method, path) the application serves under /api.

    Two public sources, because FastAPI keeps included routers behind private
    types: the generated OpenAPI document, which lists every route of every
    included router -- including one added to ``create_app`` next month -- and
    the routes declared directly on the app and on each router object, which
    catches anything left out of the schema.
    """
    found: set[tuple[str, str]] = set()
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            found.add((method.upper(), path))
    for router in (app.router, routes.router, actions.router,
                   auth_routes.public_router, auth_routes.account_router):
        for route in router.routes:
            if isinstance(route, APIRoute) and route.path.startswith("/api"):
                for method in route.methods - {"HEAD", "OPTIONS"}:
                    found.add((method, route.path))
    return sorted(found)


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


def test_every_non_public_api_route_refuses_an_anonymous_request():
    app = create_app()
    client = TestClient(app)
    protected = [r for r in _api_routes(app) if r not in PUBLIC]
    assert len(protected) > 15, "route discovery found suspiciously few routes"

    open_routes = []
    for method, path in protected:
        response = client.request(method, _concrete(path), json={})
        if response.status_code != 401:
            open_routes.append((method, path, response.status_code))

    assert open_routes == [], f"reachable without signing in: {open_routes}"


def test_the_production_application_has_the_same_routes():
    # The deployed app is built with wire_production=True. Its API routes must
    # be exactly the ones the test above exercised; building it does not start
    # the lifespan, so no database is opened.
    assert sorted(_api_routes(create_app(wire_production=True))) == sorted(
        _api_routes(create_app())
    )


def test_every_allowlisted_route_still_exists():
    assert PUBLIC <= set(_api_routes(create_app()))


def test_the_api_schema_requires_sign_in():
    assert TestClient(create_app()).get("/api/openapi.json").status_code == 401


def test_there_is_no_interactive_api_page():
    """Req 16.21: Swagger UI loaded from a CDN; the page is gone, not moved."""
    from tests.auth_helpers import override_auth

    signed_in = TestClient(override_auth(create_app()))

    assert signed_in.get("/api/docs").status_code == 404
    assert signed_in.get("/api/openapi.json").status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_framework_default_documentation_is_not_served(path):
    assert TestClient(create_app()).get(path).status_code == 404


def test_health_describes_configuration_only_to_a_signed_in_caller():
    body = TestClient(create_app()).get("/api/health").json()

    assert body["status"] == "ok"
    assert body["capabilities"]["login_required"] is True
    assert "server_ssh_key" not in body["capabilities"]
    assert "default_ssh_user" not in body["capabilities"]
