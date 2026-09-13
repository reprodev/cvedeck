"""Property-based test for graceful degradation on unavailable data sources.

Feature: cvedeck
Property 5: Graceful degradation on unavailable data sources
Validates: Requirements 2.5

For any combination of NVD and OSV availability, matching records
``DATA_SOURCE_UNAVAILABLE`` for each unreachable (``None``) source while still
producing findings from every reachable source. This test drives all four
present-or-None combinations of the two clients with arbitrary fixture
findings and asserts the per-source status and finding contribution invariants.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from app.enums import Severity, SourceStatus
from app.models import Inventory, OsInfo, Package
from app.scanner.matcher import (
    Matcher,
    RawAdvisory,
    RawCve,
)


class FakeNvdClient:
    """In-memory NvdClient returning a fixed list of OS-level CVEs."""

    def __init__(self, cves):
        self._cves = list(cves)

    def match_os(self, os_info):
        return list(self._cves)


class FakeOsvClient:
    """In-memory OsvClient returning a fixed list of package advisories."""

    def __init__(self, advisories):
        self._advisories = list(advisories)

    def match_packages(self, packages):
        return list(self._advisories)


# --- Generators ------------------------------------------------------------

_cve_ids = st.from_regex(r"CVE-20[0-9]{2}-[0-9]{4,7}", fullmatch=True)
_cvss_scores = st.floats(
    min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False
)
_names = st.text(
    alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=12
)
_versions = st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", fullmatch=True)


@st.composite
def _raw_cves(draw):
    return RawCve(cve_id=draw(_cve_ids), cvss_score=draw(_cvss_scores))


@st.composite
def _raw_advisories(draw):
    return RawAdvisory(
        cve_id=draw(_cve_ids),
        cvss_score=draw(_cvss_scores),
        package_identifier=draw(_names) + "@" + draw(_versions),
    )


@st.composite
def _inventories(draw):
    packages = draw(
        st.lists(
            st.builds(
                Package,
                name=_names,
                version=_versions,
                ecosystem=st.sampled_from([None, "PyPI", "npm", "deb"]),
            ),
            max_size=4,
        )
    )
    return Inventory(
        machine_id=draw(_names),
        os_info=OsInfo(name=draw(_names), version=draw(_versions)),
        packages=packages,
    )


@given(
    inventory=_inventories(),
    nvd_cves=st.lists(_raw_cves(), max_size=5),
    osv_advisories=st.lists(_raw_advisories(), max_size=5),
    nvd_available=st.booleans(),
    osv_available=st.booleans(),
)
def test_property_5_graceful_degradation_on_unavailable_sources(
    inventory,
    nvd_cves,
    osv_advisories,
    nvd_available,
    osv_available,
):
    """Property 5 (Requirements 2.5): for any combination of NVD/OSV
    availability, an unreachable (None) source is recorded
    DATA_SOURCE_UNAVAILABLE and contributes no findings, while each reachable
    source is recorded OK and its findings still appear.
    """
    nvd = FakeNvdClient(nvd_cves) if nvd_available else None
    osv = FakeOsvClient(osv_advisories) if osv_available else None

    result = Matcher().match(inventory, nvd, osv)

    nvd_findings = [f for f in result.findings if f.source == "nvd"]
    osv_findings = [f for f in result.findings if f.source == "osv"]

    # --- NVD invariants ---
    if nvd_available:
        assert result.nvd_status == SourceStatus.OK
        # Every reachable-source CVE still appears as a finding.
        assert len(nvd_findings) == len(nvd_cves)
        assert sorted(f.cve_id for f in nvd_findings) == sorted(
            c.cve_id for c in nvd_cves
        )
    else:
        # Unreachable source: recorded unavailable and contributes nothing.
        assert result.nvd_status == SourceStatus.DATA_SOURCE_UNAVAILABLE
        assert nvd_findings == []

    # --- OSV invariants ---
    if osv_available:
        assert result.osv_status == SourceStatus.OK
        assert len(osv_findings) == len(osv_advisories)
        assert sorted(f.cve_id for f in osv_findings) == sorted(
            a.cve_id for a in osv_advisories
        )
    else:
        assert result.osv_status == SourceStatus.DATA_SOURCE_UNAVAILABLE
        assert osv_findings == []

    # Findings come only from reachable sources; no others leak in.
    assert len(result.findings) == len(nvd_findings) + len(osv_findings)
    # Every produced finding carries a valid derived severity (sanity).
    for finding in result.findings:
        assert isinstance(finding.severity, Severity)
        assert finding.machine_id == inventory.machine_id
