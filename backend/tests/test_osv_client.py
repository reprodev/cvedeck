"""Unit tests for the OSV.dev HTTP client."""

from __future__ import annotations

import httpx
import pytest

from app.models import Package
from app.scanner.matcher import OsvClient
from app.scanner.osv_client import (
    OsvHttpClient,
    _parse_cvss_score,
    _parse_cvss_v3_vector,
    _resolve_cve_id,
)


def test_osv_client_satisfies_protocol():
    client = OsvHttpClient()
    assert isinstance(client, OsvClient)


def test_parse_cvss_v3_vector_standard_cases():
    # Critical 9.8
    crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert _parse_cvss_v3_vector(crit) == 9.8

    # Medium 5.3
    med = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
    assert _parse_cvss_v3_vector(med) == 5.3

    # High 8.6
    high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
    assert _parse_cvss_v3_vector(high) == 8.6

    # Low 3.4
    low = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"
    assert _parse_cvss_v3_vector(low) == 3.4

    # Malformed vector fallback
    assert _parse_cvss_v3_vector("INVALID_VECTOR") == 5.0


def test_parse_cvss_score_from_severity_list():
    vuln_vector = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"type": "Ubuntu", "score": "high"},
        ]
    }
    assert _parse_cvss_score(vuln_vector) == 9.8

    vuln_float = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert _parse_cvss_score(vuln_float) == 7.5


def test_parse_cvss_score_from_database_specific():
    assert _parse_cvss_score({"database_specific": {"severity": "CRITICAL"}}) == 9.5
    assert _parse_cvss_score({"database_specific": {"severity": "HIGH"}}) == 8.0
    assert _parse_cvss_score({"database_specific": {"severity": "MODERATE"}}) == 5.5
    assert _parse_cvss_score({"database_specific": {"severity": "LOW"}}) == 2.5
    assert _parse_cvss_score({}) == 5.0


def test_resolve_cve_id():
    # Direct CVE
    assert _resolve_cve_id({"id": "CVE-2024-1234"}) == "CVE-2024-1234"

    # From aliases
    assert (
        _resolve_cve_id({"id": "GHSA-xxxx-yyyy", "aliases": ["CVE-2024-5678"]})
        == "CVE-2024-5678"
    )

    # From upstream
    assert (
        _resolve_cve_id({"id": "USN-1234-1", "upstream": ["CVE-2024-9999"]})
        == "CVE-2024-9999"
    )

    # Embedded in prefix
    assert (
        _resolve_cve_id({"id": "UBUNTU-CVE-2024-11053"}) == "CVE-2024-11053"
    )

    # Non-CVE fallback
    assert _resolve_cve_id({"id": "GHSA-abcd-1234"}) == "GHSA-abcd-1234"


def test_match_packages_empty():
    client = OsvHttpClient()
    assert client.match_packages([]) == []
    assert client.match_packages([Package(name="", version="")]) == []


def test_match_packages_mocked_flow():
    def custom_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/querybatch"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "UBUNTU-CVE-2024-11053"}]},
                        {},
                    ]
                },
            )
        if url.endswith("/query"):
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "UBUNTU-CVE-2024-11053",
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
                                }
                            ],
                        }
                    ]
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(custom_handler)
    http_client = httpx.Client(transport=transport)

    client = OsvHttpClient(http_client=http_client)
    packages = [
        Package(name="curl", version="8.5.0-2ubuntu10", ecosystem="deb"),
        Package(name="clean-pkg", version="1.0.0", ecosystem="deb"),
    ]

    advisories = client.match_packages(packages)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.cve_id == "CVE-2024-11053"
    assert adv.cvss_score == 3.4
    assert adv.package_identifier == "deb:curl@8.5.0-2ubuntu10"
