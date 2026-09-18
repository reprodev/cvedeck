"""Unit tests for the OSV.dev HTTP client."""

from __future__ import annotations

import httpx
import pytest

from app.models import Package
from app.scanner.matcher import OsvClient
from app.enums import Severity
from app.scanner.matcher import RawAdvisory
from app.scanner.osv_client import (
    OsvHttpClient,
    _resolve_cve_id,
    parse_cvss,
)


def test_osv_client_satisfies_protocol():
    client = OsvHttpClient()
    assert isinstance(client, OsvClient)


def test_parse_cvss_from_severity_list():
    """A published vector or number is the score, and no band is claimed."""
    vuln_vector = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"type": "Ubuntu", "score": "high"},
        ]
    }
    assert parse_cvss(vuln_vector) == (9.8, None)

    vuln_float = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert parse_cvss(vuln_float) == (7.5, None)


def test_parse_cvss_reads_a_v4_vector():
    """A CVSS:4.0-only advisory scores, rather than falling through (Req 2.7).

    Before the v4 parser existed, the prefix check accepted only ``CVSS:3.``
    and every v4 advisory dropped to the 5.0 default -- reported as Medium
    whatever it actually was.
    """
    vuln = {
        "severity": [
            {
                "type": "CVSS_V4",
                "score": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"
                    "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                ),
            }
        ]
    }
    assert parse_cvss(vuln) == (9.3, None)


def test_parse_cvss_skips_an_unreadable_vector_for_a_usable_word():
    """An unparseable vector is skipped, not substituted (Req 2.6)."""
    vuln = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/GARBAGE"}],
        "database_specific": {"severity": "HIGH"},
    }
    assert parse_cvss(vuln) == (None, Severity.HIGH)


def test_parse_cvss_keeps_a_qualitative_band_without_inventing_a_score():
    """A word is a band, not a number (Req 2.6).

    These used to become 9.5 / 8.0 / 5.5 / 2.5 -- figures no feed published,
    indistinguishable afterwards from a measured score.
    """
    for word, band in [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MODERATE", Severity.MEDIUM),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
    ]:
        assert parse_cvss({"database_specific": {"severity": word}}) == (None, band)


def test_parse_cvss_reads_a_band_from_the_ecosystem_specific_block():
    """Several distribution feeds put their severity word here instead."""
    vuln = {
        "affected": [
            {"ecosystem_specific": {"severity": "Critical"}},
        ]
    }
    assert parse_cvss(vuln) == (None, Severity.CRITICAL)


def test_parse_cvss_reports_nothing_when_the_record_says_nothing():
    """The central case: no score, no band, and no substitute (Req 2.7).

    This returned 5.0 before, which ``derive_severity`` reported as Medium --
    a measurement-shaped answer to a question the advisory never answered.
    """
    assert parse_cvss({}) == (None, None)
    assert parse_cvss({"severity": [], "database_specific": {}}) == (None, None)


def _advisory(cve_id: str, score, band=None, pkg="deb:openssl@1.0"):
    return RawAdvisory(
        cve_id=cve_id, cvss_score=score, severity=band, package_identifier=pkg
    )


def test_deduplicate_findings_handles_an_absent_score_on_either_side():
    """Deduplication must not raise when a score is missing.

    ``adv.cvss_score > existing.cvss_score`` raised ``TypeError`` against a
    ``None``. ``Matcher`` treats ``TypeError`` as a defect rather than an
    outage and re-raises it, so ``ScannerEngine`` would have recorded the host
    as a connection failure -- one CVSS:4.0-only advisory making a reachable
    machine look unreachable.
    """
    client = OsvHttpClient()
    pairs = [
        (_advisory("CVE-2024-1", None), _advisory("CVE-2024-1", 7.5)),
        (_advisory("CVE-2024-2", 7.5), _advisory("CVE-2024-2", None)),
        (_advisory("CVE-2024-3", None), _advisory("CVE-2024-3", None)),
    ]
    for first, second in pairs:
        result = client._deduplicate_findings([first, second])
        assert len(result) == 1


def test_deduplicate_findings_prefers_the_more_severe_record():
    """Ranking is by band, so an unscored record outranks a Low one."""
    client = OsvHttpClient()

    scored = client._deduplicate_findings(
        [_advisory("CVE-2024-9", 2.0), _advisory("CVE-2024-9", 9.1)]
    )
    assert scored[0].cvss_score == 9.1

    # Unscored ranks above High, so it wins against one (Req 10.11).
    mixed = client._deduplicate_findings(
        [_advisory("CVE-2024-8", 7.5), _advisory("CVE-2024-8", None)]
    )
    assert mixed[0].cvss_score is None


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


# --------------------------------------------------------------------------- #
# Property 15: a finding's score is measured or absent, never substituted
# --------------------------------------------------------------------------- #

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from app.scanner.matcher import resolve_severity  # noqa: E402

_V3_VECTORS = [
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
]
_V4_VECTORS = [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
]
_JUNK_VECTORS = ["", "CVSS:3.1/GARBAGE", "not a vector", "CVSS:9.9/AV:N"]
_WORDS = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"]


@st.composite
def _osv_payloads(draw):
    """An OSV record that may or may not publish a score, a word, or neither."""
    payload: dict = {}
    kind = draw(st.sampled_from(["vector", "number", "junk", "none"]))
    if kind == "vector":
        payload["severity"] = [
            {"score": draw(st.sampled_from(_V3_VECTORS + _V4_VECTORS))}
        ]
    elif kind == "number":
        payload["severity"] = [
            {"score": str(draw(st.floats(min_value=0.0, max_value=10.0)))}
        ]
    elif kind == "junk":
        payload["severity"] = [{"score": draw(st.sampled_from(_JUNK_VECTORS))}]

    if draw(st.booleans()):
        payload["database_specific"] = {
            "severity": draw(st.sampled_from(_WORDS + ["", "unknown"]))
        }
    return payload


@settings(max_examples=300)
@given(_osv_payloads())
def test_property_15_a_score_is_measured_or_absent_never_substituted(payload):
    """Property 15 (Req 2.6, 2.7).

    For any OSV payload: a score comes back only when the payload carries one
    that parses under its own version's specification, the band is the payload's
    word when it has one and is derived from the score otherwise, and the
    severity is Unscored exactly when the payload carries neither.
    """
    score, band = parse_cvss(payload)

    if score is not None:
        # A score exists only if the payload published something parseable.
        assert 0.0 <= score <= 10.0
        published = payload.get("severity") or []
        assert published, "a score was returned for a payload carrying none"

    severity = resolve_severity(score, band)

    word = str((payload.get("database_specific") or {}).get("severity", "")).upper()
    names_a_band = any(
        needle in word for needle in ("CRIT", "HIGH", "MOD", "MED", "LOW")
    )
    if score is None and not names_a_band:
        assert severity is Severity.UNSCORED
    else:
        assert severity is not Severity.UNSCORED

    # The substituted 5.0 and the invented 9.5/8.0/5.5/2.5 are gone: a band
    # that came from a word never brings a number with it.
    if band is not None:
        assert score is None
