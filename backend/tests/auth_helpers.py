"""Sign a test application in, for tests that are not about access control.

Only the dependency is overridden, per app, so the production gate stays the
default everywhere else. ``tests/test_auth_enforcement.py`` builds the
application without this and proves every route refuses an anonymous caller.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.auth.dependencies import require_principal
from app.auth.service import Principal

TEST_PRINCIPAL = Principal(kind="session", username="tester", session_token_hash=None)


def override_auth(app: FastAPI) -> FastAPI:
    app.dependency_overrides[require_principal] = lambda: TEST_PRINCIPAL
    return app
