"""Tests for the OSV client's *production* code path.

Every other OSV test injects an ``http_client``, which skips the branch in
``match_packages`` that constructs ``httpx.Client(...)`` itself -- the only
branch deployments ever take (``wiring.build_osv_client`` passes no client).
A missing module constant in that branch therefore went undetected while the
whole suite passed, and ``Matcher.match`` reported ``DATA_SOURCE_UNAVAILABLE``
with zero findings on every real scan.

These tests exercise the self-constructing branch with a recording double so
the pooling configuration and the surrounding code stay covered.
"""

from __future__ import annotations

import httpx
import pytest

from app.api import wiring
from app.enums import SourceStatus
from app.models import Inventory, OsInfo, Package
from app.scanner import osv_client as osv_module
from app.scanner.matcher import Matcher
from app.scanner.osv_client import OsvHttpClient


class _RecordingClient:
    """Stand-in for ``httpx.Client`` capturing how it was constructed."""

    instances: list["_RecordingClient"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.closed = False
        self.posts: list[tuple[str, dict]] = []
        _RecordingClient.instances.append(self)

    def post(self, url, json=None, **_kwargs):
        self.posts.append((url, json or {}))
        results = [{"vulns": []} for _ in (json or {}).get("queries", [])]
        return httpx.Response(
            200,
            json={"results": results},
            request=httpx.Request("POST", url),
        )

    def get(self, url, **_kwargs):
        return httpx.Response(
            200, json={}, request=httpx.Request("GET", url)
        )

    def close(self):
        self.closed = True


@pytest.fixture
def recording_httpx(monkeypatch):
    _RecordingClient.instances = []
    monkeypatch.setattr(osv_module.httpx, "Client", _RecordingClient)
    return _RecordingClient


def test_pool_size_constant_is_defined():
    """The live branch references _DEFAULT_POOL_SIZE; it must exist and be sane.

    Read via ``getattr`` rather than a module-level import so a missing
    constant surfaces as a targeted failure here instead of a collection
    error that hides every other test in this file.
    """
    pool_size = getattr(osv_module, "_DEFAULT_POOL_SIZE", None)
    assert isinstance(pool_size, int), "_DEFAULT_POOL_SIZE is missing"
    assert pool_size >= osv_module._DEFAULT_MAX_WORKERS


def test_match_packages_constructs_its_own_client_when_none_injected(recording_httpx):
    client = OsvHttpClient()  # no http_client -- the deployment path
    result = client.match_packages(
        [Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu:22.04:LTS")]
    )

    assert result == []
    assert len(recording_httpx.instances) == 1, "live branch did not run"

    constructed = recording_httpx.instances[0]
    pool_size = osv_module._DEFAULT_POOL_SIZE
    limits = constructed.kwargs["limits"]
    assert limits.max_keepalive_connections == pool_size
    assert limits.max_connections == pool_size * 2
    assert constructed.closed, "self-constructed client must be closed"


def test_matcher_reports_ok_not_unavailable_on_the_live_path(recording_httpx):
    """A working live client must yield SourceStatus.OK, not a laundered failure."""
    inventory = Inventory(
        machine_id="host-1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[Package(name="openssl", version="3.0.2", ecosystem="Ubuntu")],
    )

    result = Matcher().match(inventory, nvd=None, osv=OsvHttpClient())

    assert result.osv_status is SourceStatus.OK


def test_wiring_builds_a_usable_client(recording_httpx):
    """The production wiring seam must produce a client that survives a query."""
    client = wiring.build_osv_client()
    assert client.match_packages(
        [Package(name="curl", version="7.81.0", ecosystem="Ubuntu")]
    ) == []
    assert recording_httpx.instances, "wiring client did not take the live branch"


def test_matcher_reraises_programming_errors_instead_of_masking_them():
    """A defect in a source client must not look like an unreachable source."""

    class BrokenOsv:
        def match_packages(self, packages):
            raise NameError("_DEFAULT_POOL_SIZE is not defined")

    inventory = Inventory(
        machine_id="host-1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[Package(name="openssl", version="3.0.2", ecosystem="Ubuntu")],
    )

    with pytest.raises(NameError):
        Matcher().match(inventory, nvd=None, osv=BrokenOsv())


def test_matcher_still_degrades_on_genuine_source_outage():
    """Network/HTTP failures remain DATA_SOURCE_UNAVAILABLE (Property 5)."""

    class UnreachableOsv:
        def match_packages(self, packages):
            raise httpx.ConnectError("name resolution failed")

    inventory = Inventory(
        machine_id="host-1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[Package(name="openssl", version="3.0.2", ecosystem="Ubuntu")],
    )

    result = Matcher().match(inventory, nvd=None, osv=UnreachableOsv())
    assert result.osv_status is SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert result.findings == []
