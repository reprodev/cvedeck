"""Deduplication must not depend on the order advisories arrive in.

Feature: cvedeck, Property 18.

OSV can publish several records for one CVE and package -- a USN and the
Ubuntu CVE tracker entry, say -- and ``OsvHttpClient`` collapses them into one
finding. Up to 0.10.3 the record kept depended on arrival order: a record with
a fix was preferred, but a later record with a higher score and no fix replaced
it. Advisories arrive from a pool of worker threads, so the same host, scanned
twice with the same code, showed four, six, seven or eight openssh findings as
fixable. A finding moving between "Ready to fix" and "Pending vendor patch" for
no reason is a lie in one of the two scans.

The rule now: a fix in any record is kept, the worst rating in any record is
kept, and ties are broken by a fixed order, so arrival order changes nothing.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from app.enums import Severity
from app.scanner.matcher import RawAdvisory
from app.scanner.osv_client import OsvHttpClient, _severity_rank

_PACKAGES = ["openssh-client", "openssh-server", "libssl3"]


def _advisory(cve: str, package: str, score: float | None, band: Severity | None, fixed: str | None):
    identifier = f"Ubuntu:22.04:LTS:{package}@1:8.9p1-3ubuntu0.17"
    if fixed:
        identifier += f" (fixed in {fixed})"
    return RawAdvisory(cve_id=cve, cvss_score=score, severity=band, package_identifier=identifier)


advisories = st.lists(
    st.builds(
        _advisory,
        cve=st.sampled_from(["CVE-2026-1", "CVE-2026-2"]),
        package=st.sampled_from(_PACKAGES),
        score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
        band=st.one_of(st.none(), st.sampled_from([Severity.HIGH, Severity.CRITICAL])),
        fixed=st.one_of(st.none(), st.sampled_from(["1:8.9p1-3ubuntu0.18", "1:8.9p1-3ubuntu0.20"])),
    ),
    max_size=12,
)


def _by_key(found: list[RawAdvisory]) -> dict[tuple[str, str], RawAdvisory]:
    return {(a.cve_id, a.package_identifier.split("@")[0]): a for a in found}


@given(advisories, st.randoms(use_true_random=False))
def test_deduplication_ignores_arrival_order(records, rng):
    """Property 18: any order of the same advisories gives the same findings."""
    client = OsvHttpClient()
    shuffled = list(records)
    rng.shuffle(shuffled)

    assert _by_key(client._deduplicate_findings(records)) == _by_key(
        client._deduplicate_findings(shuffled)
    )


@given(advisories)
def test_deduplication_keeps_any_fix_and_the_worst_rating(records):
    """Property 18: neither a fix nor the worst rating in any record is lost."""
    found = _by_key(OsvHttpClient()._deduplicate_findings(records))

    for key, kept in found.items():
        group = [a for a in records if (a.cve_id, a.package_identifier.split("@")[0]) == key]
        assert ("fixed in" in kept.package_identifier) == any(
            "fixed in" in a.package_identifier for a in group
        )
        assert _severity_rank(kept) == min(_severity_rank(a) for a in group)


def test_the_openssh_case_that_flapped():
    """The pair the 0.10.4 end-to-end run caught, in both orders."""
    fixed = _advisory("CVE-2026-106587", "openssh-client", 7.5, None, "1:8.9p1-3ubuntu0.18")
    unfixed = _advisory("CVE-2026-106587", "openssh-client", 9.8, None, None)
    client = OsvHttpClient()

    for order in ([fixed, unfixed], [unfixed, fixed]):
        (kept,) = client._deduplicate_findings(order)
        assert kept.package_identifier.endswith("(fixed in 1:8.9p1-3ubuntu0.18)")
        assert kept.cvss_score == 9.8
