"""Cache headers on the served frontend.

The build emits content-hashed asset names and index.html names the current
ones, so a cached index.html outlives the assets it points at: after an upgrade
the browser asks for hashes that no longer exist and the dashboard renders
blank. These pin the contract that prevents it.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    io.open(static / "index.html", "w", encoding="utf-8").write(
        '<!doctype html><script src="/assets/index-abc123.js"></script>'
    )
    io.open(static / "assets" / "index-abc123.js", "w", encoding="utf-8").write("//")
    io.open(static / "favicon.ico", "w", encoding="utf-8").write("x")
    monkeypatch.setenv("CVEDECK_STATIC_DIR", str(static))
    return TestClient(create_app(wire_production=True))


def test_index_is_revalidated_on_every_load(client):
    """index.html is the only file that knows which assets are current."""
    r = client.get("/")
    assert r.status_code == 200
    assert "no-cache" in r.headers["cache-control"]


def test_hashed_assets_are_immutable(client):
    """The hash is in the filename, so a changed file is a different URL."""
    r = client.get("/assets/index-abc123.js")
    assert r.status_code == 200
    assert "immutable" in r.headers["cache-control"]
    assert "max-age=31536000" in r.headers["cache-control"]


def test_unhashed_files_are_cached_briefly(client):
    """A favicon carries no hash, so it cannot be cached for a year."""
    r = client.get("/favicon.ico")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "public, max-age=3600"


def test_index_and_assets_do_not_share_a_policy(client):
    """The whole point: these two must be opposites.

    Caching them alike is what breaks an upgrade -- either the entry point goes
    stale and points at deleted files, or the assets are re-fetched on every
    load for no reason.
    """
    index = client.get("/").headers["cache-control"]
    asset = client.get("/assets/index-abc123.js").headers["cache-control"]
    assert index != asset
    assert "immutable" not in index
