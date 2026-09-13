"""Tests for the NVD 2.0 OS-level CVE client.

No live HTTP: the transport is mocked and the response parser is exercised
against recorded payload shapes.

Two behaviours get the most attention here, because both are ways this client
could quietly make the product worse rather than better:

- **It must not invent findings.** NVD answers a looser question than OSV, so a
  CVE with no usable CVSS score, or one that has been withdrawn, is dropped
  rather than given a plausible-looking default. A fabricated severity competes
  for attention with measured ones.
- **Throttling is an outage, not an error.** A 403 from NVD must surface as
  ``ConnectionError`` so the matcher records ``DATA_SOURCE_UNAVAILABLE`` and the
  scan is flagged partial, rather than completing and reading as clean.
"""

from __future__ import annotations

import httpx
import pytest

from app.models import OsInfo
from app.scanner.nvd_client import (
    NvdHttpClient,
    _cpe_name,
    _cpe_product,
    parse_nvd_response,
)


def _payload(*vulns) -> dict:
    return {"resultsPerPage": len(vulns), "vulnerabilities": list(vulns)}


def _vuln(
    cve_id: str,
    *,
    score: float | None = 7.5,
    vector: str | None = None,
    status: str = "Analyzed",
) -> dict:
    cvss_data: dict = {"version": "3.1"}
    if score is not None:
        cvss_data["baseScore"] = score
    if vector is not None:
        cvss_data["vectorString"] = vector
    return {
        "cve": {
            "id": cve_id,
            "vulnStatus": status,
            "metrics": {"cvssMetricV31": [{"cvssData": cvss_data}]},
        }
    }


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- #
# CPE mapping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "os_name,expected",
    [
        ("Ubuntu", "cpe:2.3:o:canonical:ubuntu_linux"),
        ("Debian GNU/Linux", "cpe:2.3:o:debian:debian_linux"),
        ("AlmaLinux", "cpe:2.3:o:almalinux:almalinux"),
        ("Rocky Linux", "cpe:2.3:o:rocky:rocky_linux"),
        ("Alpine Linux", "cpe:2.3:o:alpinelinux:alpine_linux"),
        ("Red Hat Enterprise Linux", "cpe:2.3:o:redhat:enterprise_linux"),
        ("Windows Server 2022", "cpe:2.3:o:microsoft:windows_server"),
    ],
)
def test_known_operating_systems_map_to_a_cpe_product(os_name, expected):
    assert _cpe_product(OsInfo(name=os_name, version="1")) == expected


def test_an_unmapped_os_yields_no_cpe():
    """Better no query than a broad one.

    A keyword fallback would attach loosely related CVEs to the host, which is
    exactly the noise this product's actionability model exists to avoid.
    """
    assert _cpe_product(OsInfo(name="SomeVendorOS", version="1")) is None


def test_the_cpe_name_pins_the_installed_version():
    """``ubuntu_linux`` alone matches every Ubuntu CVE ever published."""
    name = _cpe_name(OsInfo(name="Ubuntu", version="22.04"))
    assert name is not None
    assert name.startswith("cpe:2.3:o:canonical:ubuntu_linux:22.04:")


def test_an_os_without_a_version_yields_no_cpe_name():
    assert _cpe_name(OsInfo(name="Ubuntu", version="")) is None


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #


def test_parses_cve_ids_and_base_scores():
    results = parse_nvd_response(
        _payload(_vuln("CVE-2024-0001", score=9.8), _vuln("CVE-2024-0002", score=4.3))
    )
    by_id = {r.cve_id: r.cvss_score for r in results}
    assert by_id == {"CVE-2024-0001": 9.8, "CVE-2024-0002": 4.3}


def test_rejected_cves_are_dropped():
    """A withdrawn CVE assignment sends someone chasing a non-existent bug."""
    results = parse_nvd_response(
        _payload(
            _vuln("CVE-2024-0001", status="Rejected"),
            _vuln("CVE-2024-0002", status="Analyzed"),
        )
    )
    assert [r.cve_id for r in results] == ["CVE-2024-0002"]


def test_a_cve_with_no_usable_score_is_dropped_not_defaulted():
    """No invented severities: an unscored CVE contributes nothing."""
    results = parse_nvd_response(
        _payload(_vuln("CVE-2024-0001", score=None), _vuln("CVE-2024-0002", score=5.0))
    )
    assert [r.cve_id for r in results] == ["CVE-2024-0002"]


def test_an_out_of_range_score_falls_back_to_the_vector():
    """A nonsense baseScore must not become a finding at face value."""
    results = parse_nvd_response(
        _payload(
            _vuln(
                "CVE-2024-0001",
                score=99.0,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        )
    )
    assert len(results) == 1
    assert results[0].cvss_score == pytest.approx(9.8)


def test_falls_back_to_cvss_v2_when_no_v3_metric_exists():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2010-0001",
                    "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 6.8}}]},
                }
            }
        ]
    }
    results = parse_nvd_response(payload)
    assert [(r.cve_id, r.cvss_score) for r in results] == [("CVE-2010-0001", 6.8)]


def test_non_cve_identifiers_are_ignored():
    payload = {"vulnerabilities": [{"cve": {"id": "GHSA-xxxx", "metrics": {}}}]}
    assert parse_nvd_response(payload) == []


@pytest.mark.parametrize(
    "payload", [None, [], "text", {}, {"vulnerabilities": "nope"}]
)
def test_unusable_payloads_yield_no_results(payload):
    assert parse_nvd_response(payload) == []


def test_malformed_entries_do_not_discard_the_response():
    payload = {
        "vulnerabilities": [
            _vuln("CVE-2024-0001"),
            "garbage",
            None,
            {"no_cve_key": True},
            _vuln("CVE-2024-0002"),
        ]
    }
    assert {r.cve_id for r in parse_nvd_response(payload)} == {
        "CVE-2024-0001",
        "CVE-2024-0002",
    }


# --------------------------------------------------------------------------- #
# Client behaviour
# --------------------------------------------------------------------------- #


def test_match_os_queries_by_cpe_name():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(request.url.params))
        return httpx.Response(200, json=_payload(_vuln("CVE-2024-0001")))

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    client.match_os(OsInfo(name="Ubuntu", version="22.04"))

    assert seen["cpeName"].startswith("cpe:2.3:o:canonical:ubuntu_linux:22.04")


def test_an_unmapped_os_makes_no_request_at_all():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request should be made for an unmapped OS")

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    assert client.match_os(OsInfo(name="MysteryOS", version="1.0")) == []


@pytest.mark.parametrize("status_code", [403, 429, 503])
def test_throttling_surfaces_as_an_outage_not_a_silent_empty_result(status_code):
    """The matcher turns ConnectionError into DATA_SOURCE_UNAVAILABLE.

    Returning [] here instead would let a throttled scan report a clean host.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code)

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    with pytest.raises(ConnectionError):
        client.match_os(OsInfo(name="Ubuntu", version="22.04"))


def test_a_transport_error_surfaces_as_an_outage():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure")

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    with pytest.raises(ConnectionError):
        client.match_os(OsInfo(name="Ubuntu", version="22.04"))


def test_the_rate_limit_message_points_at_the_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    with pytest.raises(ConnectionError, match="CVEDECK_NVD_API_KEY"):
        client.match_os(OsInfo(name="Ubuntu", version="22.04"))


def test_repeat_queries_for_the_same_release_hit_the_cache():
    """A fleet is usually one or two OS releases; without this, one request
    per host burns the rate limit for no new information."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_payload(_vuln("CVE-2024-0001")))

    client = NvdHttpClient(
        "https://nvd.test/cves", http_client=_mock_client(handler)
    )
    for _ in range(5):
        client.match_os(OsInfo(name="Ubuntu", version="22.04"))

    assert calls["n"] == 1


def test_results_are_capped_keeping_the_most_severe():
    """When the cap bites it must drop the least severe, not an arbitrary tail."""

    def handler(request: httpx.Request) -> httpx.Response:
        vulns = [
            _vuln(f"CVE-2024-{i:04d}", score=float(i % 10) + 0.5) for i in range(50)
        ]
        return httpx.Response(200, json=_payload(*vulns))

    client = NvdHttpClient(
        "https://nvd.test/cves", max_findings=5, http_client=_mock_client(handler)
    )
    results = client.match_os(OsInfo(name="Ubuntu", version="22.04"))

    assert len(results) == 5
    assert all(r.cvss_score == pytest.approx(9.5) for r in results)


def test_the_api_key_is_sent_as_a_header_when_configured():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=_payload())

    client = NvdHttpClient(
        "https://nvd.test/cves",
        api_key="secret-key",
        http_client=_mock_client(handler),
    )
    client.match_os(OsInfo(name="Ubuntu", version="22.04"))

    assert seen.get("apikey") == "secret-key"
