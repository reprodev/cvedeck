"""The real OSV client must report failure, never convert it into "no findings".

Regression tests for a defect found in pre-publication review. OsvHttpClient
caught every per-query error and returned an empty advisory list, so an OSV
outage -- or a query OSV rejects, such as an ecosystem it does not have --
produced a scan with zero findings reported as complete and clean (Req 10.1,
Property 5).

The matcher's own degradation test passed the whole time because it drove the
matcher with a fake client that raised. These tests drive the *real* client
through a mocked transport, so the property is checked end to end rather than
assumed at a seam.
"""

from __future__ import annotations

import httpx
import pytest

from app.models import Inventory, OsInfo, Package
from app.scanner.matcher import Matcher, SourceStatus
from app.scanner.osv_client import OsvHttpClient, OsvUnavailableError

_PKG = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu")

_VULN = {
    "id": "UBUNTU-CVE-2024-0001",
    "aliases": ["CVE-2024-0001"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu"}}],
}


def _client(handler) -> OsvHttpClient:
    return OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def _healthy(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/querybatch"):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": _VULN["id"]}]}]})
    return httpx.Response(200, json={"vulns": [_VULN]})


def _unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def _server_error(request: httpx.Request) -> httpx.Response:
    return httpx.Response(503, json={"message": "unavailable"})


def _invalid_ecosystem(request: httpx.Request) -> httpx.Response:
    # OSV's real response to an ecosystem it does not recognise.
    return httpx.Response(400, json={"code": 3, "message": "invalid ecosystem"})


@pytest.mark.parametrize(
    "handler",
    [_unreachable, _server_error, _invalid_ecosystem],
    ids=["unreachable", "http-503", "invalid-ecosystem-400"],
)
def test_failed_queries_raise_instead_of_returning_no_findings(handler):
    """A lookup that could not be answered is an error, not a clean result (Req 10.1)."""
    with pytest.raises(OsvUnavailableError):
        _client(handler).match_packages([_PKG])


@pytest.mark.parametrize(
    "handler",
    [_unreachable, _server_error, _invalid_ecosystem],
    ids=["unreachable", "http-503", "invalid-ecosystem-400"],
)
def test_matcher_marks_real_client_failure_unavailable(handler):
    """End to end through the real client: the scan is partial, never clean (Req 10.1, Property 5)."""
    inventory = Inventory(
        machine_id="host-1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[_PKG],
    )
    result = Matcher().match(inventory, nvd=None, osv=_client(handler))
    assert result.osv_status is SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert result.findings == []


def test_a_failed_lookup_is_not_cached_as_clean():
    """After an outage, the same client asks again rather than remembering "no vulnerabilities" (Req 10.1)."""
    state = {"up": False}

    def flaky(request: httpx.Request) -> httpx.Response:
        if not state["up"]:
            return _unreachable(request)
        return _healthy(request)

    client = _client(flaky)
    with pytest.raises(OsvUnavailableError):
        client.match_packages([_PKG])

    state["up"] = True
    advisories = client.match_packages([_PKG])
    assert [a.cve_id for a in advisories] == ["CVE-2024-0001"]


def test_one_failed_query_among_many_still_fails_the_source():
    """A partial answer is not a complete one: any unanswered package fails the lookup (Req 10.1)."""
    other = Package(name="curl", version="7.81.0-1ubuntu1.15", ecosystem="Ubuntu")

    def one_bad(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "x"}]}, {"vulns": [{"id": "y"}]}]}
            )
        if b'"curl"' in request.content:
            return _server_error(request)
        return httpx.Response(200, json={"vulns": [_VULN]})

    with pytest.raises(OsvUnavailableError, match="1 of 2"):
        _client(one_bad).match_packages([_PKG, other])


def test_healthy_client_still_returns_findings():
    """The fix must not turn a working lookup into a failure (Req 2.2)."""
    advisories = _client(_healthy).match_packages([_PKG])
    assert [a.cve_id for a in advisories] == ["CVE-2024-0001"]
