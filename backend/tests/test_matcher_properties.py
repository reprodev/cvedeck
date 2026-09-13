"""Property-based tests for the Matcher's matching correctness and completeness.

Feature: cvedeck
Property 3: Matching correctness and finding completeness
Validates: Requirements 2.1, 2.2, 2.3, 7.1

For any inventory and in-memory NVD/OSV fixtures, the Matcher produces exactly
the findings the fixtures deem applicable, every produced finding carries a CVE
identifier, a CVSS score, and the affected machine reference, and every
OSV-sourced (package-level) finding additionally carries a package identifier.

The applicability decision belongs to the data sources (NVD/OSV); here the
in-memory fake clients stand in for those sources by returning generated raw
records, so "exactly the applicable findings" means the produced findings
correspond one-to-one to the records the fixtures return.
"""

from __future__ import annotations

from collections import Counter

from hypothesis import given, strategies as st

from app.enums import Severity, SourceStatus
from app.models import Inventory, OsInfo, Package
from app.scanner.matcher import (
    Matcher,
    RawAdvisory,
    RawCve,
)


# --- In-memory fake data-source clients ------------------------------------


class FakeNvdClient:
    """In-memory NvdClient returning a fixed list of generated OS-level CVEs."""

    def __init__(self, cves):
        self._cves = list(cves)

    def match_os(self, os_info):
        return list(self._cves)


class FakeOsvClient:
    """In-memory OsvClient returning a fixed list of generated advisories."""

    def __init__(self, advisories):
        self._advisories = list(advisories)

    def match_packages(self, packages):
        return list(self._advisories)


# --- Strategies -------------------------------------------------------------

_identifiers = st.text(min_size=1, max_size=20)
_cvss = st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)


@st.composite
def _os_infos(draw):
    return OsInfo(name=draw(_identifiers), version=draw(_identifiers))


@st.composite
def _packages(draw):
    return Package(
        name=draw(_identifiers),
        version=draw(_identifiers),
        ecosystem=draw(st.none() | _identifiers),
    )


@st.composite
def _inventories(draw):
    return Inventory(
        machine_id=draw(_identifiers),
        os_info=draw(_os_infos()),
        packages=draw(st.lists(_packages(), max_size=6)),
    )


@st.composite
def _raw_cves(draw):
    return RawCve(cve_id=draw(_identifiers), cvss_score=draw(_cvss))


@st.composite
def _raw_advisories(draw):
    return RawAdvisory(
        cve_id=draw(_identifiers),
        cvss_score=draw(_cvss),
        package_identifier=draw(_identifiers),
    )


@given(
    inventory=_inventories(),
    raw_cves=st.lists(_raw_cves(), max_size=8),
    raw_advisories=st.lists(_raw_advisories(), max_size=8),
)
def test_property_3_matching_correctness_and_finding_completeness(
    inventory, raw_cves, raw_advisories
):
    """Property 3 (Requirements 2.1, 2.2, 2.3, 7.1).

    The Matcher produces exactly the findings the fixtures deem applicable, and
    every finding is complete: CVE id, CVSS score, and machine reference; every
    OSV-sourced finding also carries a package identifier.
    """
    nvd = FakeNvdClient(raw_cves)
    osv = FakeOsvClient(raw_advisories)

    result = Matcher().match(inventory, nvd, osv)

    # Both sources are reachable in this property.
    assert result.machine_id == inventory.machine_id
    assert result.nvd_status == SourceStatus.OK
    assert result.osv_status == SourceStatus.OK

    nvd_findings = [f for f in result.findings if f.source == "nvd"]
    osv_findings = [f for f in result.findings if f.source == "osv"]

    # Correctness/completeness of the finding set: exactly one finding per raw
    # record the fixtures return, no more and no less (Req 2.1, 2.2).
    assert len(result.findings) == len(raw_cves) + len(raw_advisories)
    assert len(nvd_findings) == len(raw_cves)
    assert len(osv_findings) == len(raw_advisories)

    # NVD findings correspond exactly to the returned RawCve records (cve_id +
    # cvss_score pairs), independent of ordering.
    assert Counter((c.cve_id, c.cvss_score) for c in raw_cves) == Counter(
        (f.cve_id, f.cvss_score) for f in nvd_findings
    )

    # OSV findings correspond exactly to the returned RawAdvisory records,
    # including the package identifier (Req 7.1).
    assert Counter(
        (a.cve_id, a.cvss_score, a.package_identifier) for a in raw_advisories
    ) == Counter(
        (f.cve_id, f.cvss_score, f.package_identifier) for f in osv_findings
    )

    # Every produced finding is complete (Req 2.3).
    for finding in result.findings:
        assert finding.cve_id  # carries a CVE identifier
        assert isinstance(finding.cvss_score, float)  # carries a CVSS score
        assert finding.machine_id == inventory.machine_id  # affected machine ref
        assert isinstance(finding.severity, Severity)

    # Every OSV-sourced (package-level) finding carries a package identifier;
    # OS-level (NVD) findings do not (Req 7.1, 2.3).
    for finding in osv_findings:
        assert finding.package_identifier is not None
        assert finding.package_identifier != ""
    for finding in nvd_findings:
        assert finding.package_identifier is None
