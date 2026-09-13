"""Unit tests for severity derivation in the Matcher module.

Covers the documented CVSS v3.x band boundaries and edge cases. The universal
property test lives separately (task 2.2, Property 4).
"""

import pytest

from app.enums import Severity
from app.scanner.matcher import derive_severity


@pytest.mark.parametrize(
    "score, expected",
    [
        # Low band: 0.0 - 3.9
        (0.0, Severity.LOW),
        (2.5, Severity.LOW),
        (3.9, Severity.LOW),
        # Medium band: 4.0 - 6.9
        (4.0, Severity.MEDIUM),
        (5.5, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        # High band: 7.0 - 8.9
        (7.0, Severity.HIGH),
        (8.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        # Critical band: 9.0 - 10.0
        (9.0, Severity.CRITICAL),
        (9.8, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_derive_severity_bands(score, expected):
    assert derive_severity(score) == expected


def test_lower_boundaries_are_inclusive():
    """Each band lower bound belongs to that band."""
    assert derive_severity(4.0) == Severity.MEDIUM
    assert derive_severity(7.0) == Severity.HIGH
    assert derive_severity(9.0) == Severity.CRITICAL


def test_fractional_gap_between_band_edges_is_total():
    """Scores in the gap above a band's upper edge round up to the next band."""
    # 3.95 sits between the documented 3.9 (Low) and 4.0 (Medium) edges.
    assert derive_severity(3.95) == Severity.LOW
    assert derive_severity(6.95) == Severity.MEDIUM
    assert derive_severity(8.95) == Severity.HIGH


@pytest.mark.parametrize("score", [-0.1, -1.0, 10.1, 11.0, 100.0])
def test_out_of_range_raises(score):
    with pytest.raises(ValueError):
        derive_severity(score)


# ---------------------------------------------------------------------------
# Property-based test
# Feature: cvedeck
# Property 4: Severity derivation is total and correct
# Validates: Requirements 2.4
# ---------------------------------------------------------------------------

from hypothesis import given, strategies as st


def _expected_severity(score: float) -> Severity:
    """Independent reference mapping from the documented CVSS bands.

    Bands (CVSS v3.x): 0.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High,
    9.0-10.0 Critical. Expressed as lower-bound thresholds so the mapping is
    total over the continuous [0.0, 10.0] range, including the fractional gaps
    between the one-decimal band edges (e.g. 3.95).
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@given(
    cvss_score=st.floats(
        min_value=0.0,
        max_value=10.0,
        allow_nan=False,
        allow_infinity=False,
    )
)
def test_property_4_severity_derivation_is_total_and_correct(cvss_score):
    """Property 4 (Requirements 2.4): for any CVSS score in 0.0-10.0,
    derive_severity returns exactly one Severity matching the documented band.
    """
    result = derive_severity(cvss_score)

    # Totality: a valid Severity is always returned (never raises in-range).
    assert isinstance(result, Severity)
    # Correctness: it matches the documented band boundaries.
    assert result == _expected_severity(cvss_score)



# --- Matcher unit tests ----------------------------------------------------

from app.enums import SourceStatus
from app.models import Inventory, OsInfo, Package
from app.scanner.matcher import (
    Finding,
    MatchResult,
    Matcher,
    RawAdvisory,
    RawCve,
)


class FakeNvdClient:
    """In-memory NvdClient returning a fixed list of OS-level CVEs."""

    def __init__(self, cves):
        self._cves = list(cves)
        self.calls = []

    def match_os(self, os_info):
        self.calls.append(os_info)
        return list(self._cves)


class FakeOsvClient:
    """In-memory OsvClient returning a fixed list of package advisories."""

    def __init__(self, advisories):
        self._advisories = list(advisories)
        self.calls = []

    def match_packages(self, packages):
        self.calls.append(list(packages))
        return list(self._advisories)


def _inventory():
    return Inventory(
        machine_id="m-1",
        os_info=OsInfo(name="ubuntu", version="22.04"),
        packages=[
            Package(name="requests", version="2.0.0", ecosystem="PyPI"),
            Package(name="left-pad", version="1.0.0", ecosystem="npm"),
        ],
    )


def test_match_os_inventory_produces_nvd_findings():
    inv = _inventory()
    nvd = FakeNvdClient([RawCve(cve_id="CVE-2024-0001", cvss_score=9.5)])
    osv = FakeOsvClient([])

    result = Matcher().match(inv, nvd, osv)

    assert isinstance(result, MatchResult)
    nvd_findings = [f for f in result.findings if f.source == "nvd"]
    assert len(nvd_findings) == 1
    finding = nvd_findings[0]
    assert finding.cve_id == "CVE-2024-0001"
    assert finding.cvss_score == 9.5
    assert finding.machine_id == "m-1"
    assert finding.severity == Severity.CRITICAL
    # OS-level findings carry no package identifier.
    assert finding.package_identifier is None
    # OS info was passed to the NVD client.
    assert nvd.calls == [inv.os_info]


def test_match_software_inventory_produces_osv_findings_with_package_id():
    inv = _inventory()
    nvd = FakeNvdClient([])
    osv = FakeOsvClient(
        [
            RawAdvisory(
                cve_id="CVE-2024-0002",
                cvss_score=5.0,
                package_identifier="PyPI:requests@2.0.0",
            )
        ]
    )

    result = Matcher().match(inv, nvd, osv)

    osv_findings = [f for f in result.findings if f.source == "osv"]
    assert len(osv_findings) == 1
    finding = osv_findings[0]
    assert finding.cve_id == "CVE-2024-0002"
    assert finding.cvss_score == 5.0
    assert finding.machine_id == "m-1"
    assert finding.severity == Severity.MEDIUM
    # Package-level findings carry the affected package identifier (Req 7.1).
    assert finding.package_identifier == "PyPI:requests@2.0.0"
    # The package list was passed to the OSV client.
    assert osv.calls == [inv.packages]


def test_every_finding_carries_cve_score_and_machine_ref():
    inv = _inventory()
    nvd = FakeNvdClient([RawCve(cve_id="CVE-2024-0001", cvss_score=7.2)])
    osv = FakeOsvClient(
        [
            RawAdvisory(
                cve_id="CVE-2024-0002",
                cvss_score=2.0,
                package_identifier="npm:left-pad@1.0.0",
            )
        ]
    )

    result = Matcher().match(inv, nvd, osv)

    assert len(result.findings) == 2
    for finding in result.findings:
        assert finding.cve_id
        assert isinstance(finding.cvss_score, float)
        assert finding.machine_id == "m-1"
        assert isinstance(finding.severity, Severity)
    assert result.nvd_status == SourceStatus.OK
    assert result.osv_status == SourceStatus.OK


def test_unreachable_nvd_records_unavailable_and_uses_osv():
    inv = _inventory()
    osv = FakeOsvClient(
        [
            RawAdvisory(
                cve_id="CVE-2024-0003",
                cvss_score=8.1,
                package_identifier="PyPI:requests@2.0.0",
            )
        ]
    )

    result = Matcher().match(inv, nvd=None, osv=osv)

    assert result.nvd_status == SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert result.osv_status == SourceStatus.OK
    # Matching still completes against the reachable OSV source (Req 2.5).
    assert [f.source for f in result.findings] == ["osv"]
    assert result.findings[0].cve_id == "CVE-2024-0003"


def test_unreachable_osv_records_unavailable_and_uses_nvd():
    inv = _inventory()
    nvd = FakeNvdClient([RawCve(cve_id="CVE-2024-0004", cvss_score=3.0)])

    result = Matcher().match(inv, nvd=nvd, osv=None)

    assert result.nvd_status == SourceStatus.OK
    assert result.osv_status == SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert [f.source for f in result.findings] == ["nvd"]
    assert result.findings[0].cve_id == "CVE-2024-0004"


def test_both_sources_unreachable_yields_no_findings():
    inv = _inventory()

    result = Matcher().match(inv, nvd=None, osv=None)

    assert result.findings == []
    assert result.nvd_status == SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert result.osv_status == SourceStatus.DATA_SOURCE_UNAVAILABLE


def test_fake_clients_satisfy_protocols():
    from app.scanner.matcher import NvdClient, OsvClient

    assert isinstance(FakeNvdClient([]), NvdClient)
    assert isinstance(FakeOsvClient([]), OsvClient)
