"""Deduplication must not depend on the order advisories arrive in.

Feature: cvedeck, Properties 18 and 20.

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
from app.package_identifier import parse_fix
from app.scanner import debian_version, rpm_version

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


def test_a_named_band_and_a_derived_one_do_not_tie_on_arrival_order():
    """The case Hypothesis found after 0.10.4 shipped: two records alike but for
    one naming its band (High) and the other leaving it to its 7.0 score. They
    rank alike and share an identifier, so the first to arrive used to win."""
    named = _advisory("CVE-2026-2", "openssh-server", 7.0, Severity.HIGH, None)
    derived = _advisory("CVE-2026-2", "openssh-server", 7.0, None, None)
    client = OsvHttpClient()

    assert client._deduplicate_findings([named, derived]) == client._deduplicate_findings(
        [derived, named]
    )


# --- Property 20: the earliest fix, by the distribution's ordering (Req 2.11) --

_RPM_FIXES = ["1.21.1-1.el9", "1.21.1-10.el9_8", "1.9-1.el9", "1.10-1.el9", "1:1.0-1.el9", "1.21.1-2.el9"]
_DEB_FIXES = ["1:8.9p1-3ubuntu0.18", "1:8.9p1-3ubuntu0.2", "1:8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.99", "1:8.9p1-3ubuntu0.18~esm1"]

_FAMILIES = {
    "Rocky Linux:9:nginx@1.20.1-14.el9": (_RPM_FIXES, rpm_version.compare),
    "Ubuntu:22.04:LTS:openssh-client@1:8.9p1-3ubuntu0.1": (_DEB_FIXES, debian_version.compare),
}


@st.composite
def fixed_group(draw):
    base = draw(st.sampled_from(sorted(_FAMILIES)))
    fixes, _compare = _FAMILIES[base]
    records = draw(
        st.lists(
            st.builds(
                lambda fix, score: RawAdvisory(
                    cve_id="CVE-2026-9",
                    cvss_score=score,
                    severity=None,
                    package_identifier=f"{base} (fixed in {fix})",
                ),
                st.sampled_from(fixes),
                st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
            ),
            min_size=1,
            max_size=8,
        )
    )
    return base, records


@given(fixed_group(), st.randoms(use_true_random=False))
def test_the_fix_kept_is_the_earliest_the_distribution_orders_first(group, rng):
    """Property 20: no other record's fix precedes the one kept, in any order."""
    base, records = group
    compare = _FAMILIES[base][1]
    shuffled = list(records)
    rng.shuffle(shuffled)
    client = OsvHttpClient()

    (kept,) = client._deduplicate_findings(records)
    (again,) = client._deduplicate_findings(shuffled)

    assert kept == again
    _status, _release, chosen = parse_fix(kept.package_identifier)
    for record in records:
        assert compare(parse_fix(record.package_identifier)[2], chosen) >= 0


def _rocky(fix: str, score: float | None = 7.5) -> RawAdvisory:
    return RawAdvisory(
        cve_id="CVE-2026-9",
        cvss_score=score,
        severity=None,
        package_identifier=f"Rocky Linux:9:nginx@1.20.1-14.el9 (fixed in {fix})",
    )


def test_a_two_digit_release_is_not_read_as_text():
    """Text order took 1.10 before 1.9; rpm takes 1.9. Equal ratings, so only the
    version can decide."""
    client = OsvHttpClient()
    early, late = _rocky("1:1.9-1.el9"), _rocky("1:1.10-1.el9")

    for order in ([early, late], [late, early]):
        (kept,) = client._deduplicate_findings(order)
        assert kept.package_identifier.endswith("(fixed in 1:1.9-1.el9)")


def test_the_worst_rating_still_wins_when_the_earliest_fix_rates_lower():
    client = OsvHttpClient()
    (kept,) = client._deduplicate_findings([_rocky("1.21.1-1.el9", 4.0), _rocky("1.21.1-10.el9_8", 9.1)])
    assert kept.package_identifier.endswith("(fixed in 1.21.1-1.el9)")
    assert kept.cvss_score == 9.1


def test_an_ecosystem_without_an_ordering_keeps_the_fixed_text_order():
    """Alpine has no ordering here: the 0.10.4 rule, stable whatever the order."""
    def alpine(fix):
        return RawAdvisory(
            cve_id="CVE-2026-9", cvss_score=7.5, severity=None,
            package_identifier=f"Alpine:v3.20:busybox@1.36.1-r28 (fixed in {fix})",
        )

    client = OsvHttpClient()
    a, b = alpine("1.36.1-r9"), alpine("1.36.1-r10")
    (kept,) = client._deduplicate_findings([a, b])
    assert client._deduplicate_findings([b, a]) == [kept]
    assert kept.package_identifier.endswith("(fixed in 1.36.1-r10)")  # text order


def test_a_mixture_of_orderings_falls_back_to_the_fixed_order():
    """A universal-fallback group can mix ecosystems; neither ordering applies to both."""
    deb = RawAdvisory(
        cve_id="CVE-2026-9", cvss_score=7.5, severity=None,
        package_identifier="Debian:12:zlib@1.2.13 (fixed in 1:1.3-1)",
    )
    rpm = RawAdvisory(
        cve_id="CVE-2026-9", cvss_score=7.5, severity=None,
        package_identifier="Rocky Linux:9:zlib@1.2.11-40.el9 (fixed in 1.2.11-41.el9)",
    )
    client = OsvHttpClient()
    (kept,) = client._deduplicate_findings([deb, rpm])
    assert client._deduplicate_findings([rpm, deb]) == [kept]


def test_a_different_fix_is_still_the_same_finding_between_scans():
    """Req 18.2: a scan choosing an earlier fix than the last one did reports
    nothing new and nothing resolved -- the diff keys on CVE and package name."""
    from app.data.repository import finding_key

    before = _rocky("1.21.1-10.el9_8").package_identifier
    after = _rocky("1.21.1-1.el9").package_identifier
    assert finding_key("CVE-2026-9", before) == finding_key("CVE-2026-9", after)
