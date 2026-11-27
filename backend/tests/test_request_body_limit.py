"""The whole-body limit that holds before sign-in (Req 16.22).

FastAPI reads and parses a body before it runs a route's dependencies, and
sign-in is one of them. The field bounds of Req 16.13 are therefore checked on
a body already held in memory -- they bound what is *acted on*, never what is
*read*. These tests pin the layer underneath: every route stops reading at its
limit and refuses with 413, signed in or not, before anything acts.

The route sweep walks the real application the way the sign-in sweep in
``test_auth_enforcement.py`` does, so a route added later is covered on the day
it is written, and a router included without a limit fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import schemas
from app.api.app import create_app
from app.api.dependencies import get_scanner_engine, get_session
from app.data.schema import Base
from tests.auth_helpers import override_auth
from tests.test_auth_enforcement import _api_routes, _concrete

MARKER = "do-not-echo-this-body"

#: The routes allowed a scan batch's worth of body. Pinned in both directions:
#: each must accept more than MAX_BODY, and nothing else may.
BATCH_ROUTES = {
    ("POST", "/api/scans"),
    ("POST", "/api/scans/jobs"),
    ("POST", "/api/discovery/enroll"),
}

JSON = {"content-type": "application/json"}


@pytest.fixture(autouse=True)
def _login_on(monkeypatch):
    monkeypatch.delenv("CVEDECK_AUTH", raising=False)
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)


def _padded(size: int) -> bytes:
    """A JSON body of exactly ``size`` bytes that carries the marker."""
    head = ('{"note":"' + MARKER).encode()
    tail = b'"}'
    return head + b"a" * (size - len(head) - len(tail)) + tail


def _chunks(size: int, chunk: int = 64 * 1024):
    """The same body sent without a Content-Length, in pieces."""
    body = _padded(size)
    for start in range(0, len(body), chunk):
        yield body[start : start + chunk]


def _write_routes(app) -> list[tuple[str, str]]:
    return [(m, p) for m, p in _api_routes(app) if m in {"POST", "PUT", "PATCH", "DELETE"}]


def _limit_for(route: tuple[str, str]) -> int:
    return schemas.MAX_BATCH_BODY if route in BATCH_ROUTES else schemas.MAX_BODY


@pytest.fixture()
def signed_in(monkeypatch):
    """A signed-in client on an in-memory database whose engine records use."""
    engines_built: list[object] = []
    app = override_auth(create_app())

    def engine():
        engines_built.append(object())
        return None

    app.dependency_overrides[get_scanner_engine] = engine
    db = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(db)
    app.dependency_overrides[get_session] = lambda: Session(db)
    client = TestClient(app)
    client.engines_built = engines_built  # type: ignore[attr-defined]
    return client


# --------------------------------------------------------------------------- #
# Every route, before sign-in
# --------------------------------------------------------------------------- #


def test_every_write_route_refuses_a_body_over_its_limit_before_sign_in():
    """Anonymous, login on: a body one byte over the limit is 413, never 401.

    401 here would mean sign-in ran first -- which is only possible once the
    body has been read, which is the thing this limit exists to prevent.
    """
    app = create_app()
    client = TestClient(app)
    write_routes = _write_routes(app)
    assert len(write_routes) > 15, "route discovery found suspiciously few routes"

    wrong = []
    for route in write_routes:
        method, path = route
        response = client.request(
            method, _concrete(path), content=_padded(_limit_for(route) + 1), headers=JSON
        )
        if response.status_code != 413:
            wrong.append((method, path, response.status_code))
    assert wrong == [], f"read a body over its limit: {wrong}"


def test_only_the_batch_routes_accept_more_than_the_default():
    """Over MAX_BODY but under MAX_BATCH_BODY: the batch routes read it (and
    then refuse the anonymous caller); every other route refuses its size."""
    app = create_app()
    client = TestClient(app)
    routes = set(_write_routes(app))
    assert BATCH_ROUTES <= routes, f"a batch route has gone: {BATCH_ROUTES - routes}"

    body = _padded(schemas.MAX_BODY + 1)
    statuses = {
        route: client.request(route[0], _concrete(route[1]), content=body, headers=JSON).status_code
        for route in routes
    }
    assert {r for r, status in statuses.items() if status != 413} == BATCH_ROUTES


def test_a_chunked_body_without_a_length_is_counted_as_it_arrives():
    client = TestClient(create_app())
    for path, limit in (("/api/auth/login", schemas.MAX_BODY), ("/api/scans", schemas.MAX_BATCH_BODY)):
        response = client.post(path, content=_chunks(limit + 1), headers=JSON)
        assert response.status_code == 413, path
        assert MARKER not in response.text


# --------------------------------------------------------------------------- #
# What the refusal says
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "limit", "label"),
    [
        ("/api/auth/login", schemas.MAX_BODY, "1 MiB"),
        ("/api/scans", schemas.MAX_BATCH_BODY, "16 MiB"),
    ],
)
@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_the_refusal_states_the_limit_and_never_the_body(path, limit, label, chunked):
    client = TestClient(create_app())
    content = _chunks(limit + 1) if chunked else _padded(limit + 1)

    response = client.post(path, content=content, headers=JSON)

    assert response.status_code == 413
    assert response.headers["content-type"] == "application/json"
    detail = response.json()["detail"]
    assert label in detail
    assert MARKER not in response.text
    # Still a CveDeck response: the security headers survive the rewrite.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_a_refused_scan_never_reaches_the_engine(signed_in):
    response = signed_in.post(
        "/api/scans", content=_padded(schemas.MAX_BATCH_BODY + 1), headers=JSON
    )
    assert response.status_code == 413
    assert signed_in.engines_built == []


def test_the_limit_is_given_in_bytes_when_it_is_not_whole_mebibytes():
    from app.api.security import body_too_large_detail, size_label

    assert size_label(16 * 1024 * 1024) == "16 MiB"
    assert size_label(1000) == "1,000 bytes"
    assert "accepts" in body_too_large_detail(None)


# --------------------------------------------------------------------------- #
# Honest bodies still pass
# --------------------------------------------------------------------------- #


def test_a_batch_over_the_default_size_is_read_and_then_refused_by_its_field_bound(signed_in):
    """4,097 targets padded past 1 MiB: 422 from the count bound, not 413.

    The body passed its route's limit and was parsed; Req 16.13's bound then
    refused it. No host is contacted, and no engine is built.
    """
    targets = [
        {"id": f"m{i}", "hostname": f"host-{i}.example.org", "platform": "linux",
         "username": "scan", "password": "p" * 300}
        for i in range(schemas.MAX_BATCH + 1)
    ]
    response = signed_in.post("/api/scans", json={"targets": targets})

    assert len(response.request.content) > schemas.MAX_BODY
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == "targets"


def test_an_enrolment_over_the_default_size_is_accepted(signed_in):
    hosts = [
        {"id": f"192.0.2.{i % 250}-{i}-" + "x" * 200, "hostname": f"h{i}.example.org", "platform": "linux"}
        for i in range(schemas.MAX_BATCH)
    ]
    response = signed_in.post("/api/discovery/enroll", json={"hosts": hosts})

    assert len(response.request.content) > schemas.MAX_BODY
    assert response.status_code == 201


def test_a_note_at_its_bound_in_four_byte_characters_is_under_the_default(signed_in):
    """The largest honest body on a default-limit route still gets through."""
    response = signed_in.post(
        "/api/machines/nope/cves/CVE-2026-0001/remediation",
        json={"status": "in_progress", "note": "\U0001F600" * schemas.MAX_NOTE},
    )
    assert response.status_code == 404  # unknown machine -- read, parsed, answered


# --------------------------------------------------------------------------- #
# The documented proxy agrees
# --------------------------------------------------------------------------- #


def test_the_nginx_example_allows_exactly_the_batch_limit():
    """The proxy and the app must refuse the same batches.

    A proxy limit below the app's refuses a batch the app documents as fine; one
    above it lets the proxy buffer what the app will refuse anyway.
    """
    conf = Path(__file__).resolve().parents[2] / "deploy" / "nginx" / "cvedeck.conf.example"
    match = re.search(r"^\s*client_max_body_size\s+(\d+)m;", conf.read_text(encoding="utf-8"), re.M)
    assert match, "client_max_body_size not found in the nginx example"
    assert int(match.group(1)) * 1024 * 1024 == schemas.MAX_BATCH_BODY
