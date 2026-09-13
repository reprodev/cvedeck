"""Tests for the demo fleet seed.

The seed exists to be looked at -- in screenshots, and by strangers evaluating
the tool. That makes it a place where a comfortable-looking lie is easy to
introduce and hard to notice, so these tests mostly assert that it does *not*
misrepresent anything: that the three-valued KEV field keeps all three of its
states, that hosts which never scanned successfully carry no findings, and that
the "Ready to Fix" split is driven by data the API can actually parse.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.routes import _parse_fixed_version
from app.data.demo_seed import fleet_is_empty, seed_demo_fleet
from app.data.schema import Base, CveFinding, Inventory, TargetMachine
from app.enums import ScanStatus


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_seeds_a_non_trivial_fleet(session):
    assert fleet_is_empty(session)

    count = seed_demo_fleet(session)

    assert count >= 10
    assert not fleet_is_empty(session)
    assert session.query(CveFinding).count() > 0


def test_kev_listed_keeps_all_three_states(session):
    """The invariant this project is built around (AGENTS.md section 3).

    NULL is "not checked", False is "checked and genuinely absent", True is
    "listed". A demo containing only True and False would be quietly claiming
    the fleet was fully enriched; one containing only NULL and True would never
    exercise the honest negative. Both states have to be present, and they must
    never be collapsed into each other.
    """
    seed_demo_fleet(session)

    states = {f.kev_listed for f in session.query(CveFinding).all()}

    assert None in states, "no unenriched findings: 'unknown' would never render"
    assert False in states, "no checked-and-absent findings"
    assert True in states, "no actively-exploited findings"


def test_unenriched_findings_are_null_across_all_enrichment_columns(session):
    """A finding cannot be half-enriched.

    If kev_listed is NULL because the feed never ran, an EPSS score on the same
    row would be incoherent -- and worse, would make the row look answered.
    """
    seed_demo_fleet(session)

    for finding in session.query(CveFinding).filter(CveFinding.kev_listed.is_(None)):
        assert finding.epss_score is None
        assert finding.epss_percentile is None
        assert finding.kev_due_date is None


def test_kev_listed_findings_carry_a_due_date(session):
    seed_demo_fleet(session)

    listed = session.query(CveFinding).filter(CveFinding.kev_listed.is_(True)).all()

    assert listed
    assert all(f.kev_due_date for f in listed)


def test_hosts_that_never_scanned_successfully_have_no_findings(session):
    """A host that failed to authenticate cannot also have produced results."""
    seed_demo_fleet(session)

    unscanned = (
        session.query(TargetMachine)
        .filter(TargetMachine.last_scan_status != ScanStatus.SUCCESS)
        .all()
    )

    assert unscanned, "the fleet should include failure states"
    for machine in unscanned:
        assert session.query(CveFinding).filter_by(machine_id=machine.id).count() == 0
        assert session.query(Inventory).filter_by(machine_id=machine.id).count() == 0


def test_never_scanned_host_has_no_timestamp(session):
    seed_demo_fleet(session)

    never = (
        session.query(TargetMachine)
        .filter(TargetMachine.last_scan_status == ScanStatus.NEVER_SCANNED)
        .all()
    )

    assert never
    assert all(m.last_scanned_at is None for m in never)


def test_fleet_includes_a_partial_scan(session):
    """A scan that ran against an unreachable source is reported as partial."""
    seed_demo_fleet(session)

    partial = (
        session.query(TargetMachine)
        .filter(TargetMachine.last_scan_sources_ok.is_(False))
        .count()
    )

    assert partial > 0


def test_package_identifiers_parse_back_through_the_real_api_helper(session):
    """The seed builds identifiers; the API parses them. They must agree.

    This is the coupling most likely to rot silently: if the seed's format
    drifts from ``_parse_fixed_version``, every demo finding quietly becomes
    "Pending Vendor Patch" and the Ready-to-Fix tab empties out, with nothing
    failing.
    """
    seed_demo_fleet(session)

    findings = session.query(CveFinding).all()
    fixable = [f for f in findings if _parse_fixed_version(f.package_identifier)]
    pending = [f for f in findings if not _parse_fixed_version(f.package_identifier)]

    assert fixable, "no findings resolve to a fix: the Ready to Fix tab would be empty"
    assert pending, "no findings await a vendor patch: that tab would be empty"


def test_seeding_is_guarded_by_emptiness_not_repeated(session):
    """Restarting a demo container must not accumulate duplicate fleets."""
    seed_demo_fleet(session)
    session.commit()
    first = session.query(TargetMachine).count()

    assert not fleet_is_empty(session)

    # The caller checks fleet_is_empty before seeding; confirm that check is
    # what stops a second run, since the seed itself is unconditional.
    if fleet_is_empty(session):  # pragma: no cover - guard, should not fire
        seed_demo_fleet(session)

    assert session.query(TargetMachine).count() == first


def test_hostnames_are_obviously_fictional(session):
    """Nothing here should look like it came from a real network."""
    seed_demo_fleet(session)

    for machine in session.query(TargetMachine).all():
        assert machine.hostname.endswith(".lan")


def test_package_names_survive_the_api_parser(session):
    """No demo package name may contain a space.

    ``_parse_pkg_name`` takes the first whitespace-delimited token, which it has
    to: a space in the name is indistinguishable from the start of the
    " (fixed in ...)" suffix. The first Windows catalogue used real product
    names, so "Windows SmartScreen" reached the UI as "Windows".
    """
    from app.api.routes import _parse_pkg_name

    seed_demo_fleet(session)

    for finding in session.query(CveFinding).all():
        parsed = _parse_pkg_name(finding.package_identifier)
        assert parsed, finding.package_identifier
        # The parsed name must be the whole name, not a truncation of it.
        assert f":{parsed}@" in finding.package_identifier


def test_windows_hosts_are_enrolled_but_never_shown_as_scanned(session):
    """The demo must not imply Windows scanning works (Req 10.8, 15.5).

    Windows scans are refused because collected Windows inventory cannot yet be
    matched. A demo Windows host with findings -- or with a scan failure, which
    implies a scan was attempted -- would advertise exactly the capability that
    was withheld. Enrolled and never scanned is the only honest state.
    """
    seed_demo_fleet(session)

    from app.enums import Platform

    windows = session.query(TargetMachine).filter(
        TargetMachine.platform == Platform.WINDOWS
    ).all()
    assert windows, "the roster should still show that Windows hosts can be enrolled"
    for machine in windows:
        assert machine.last_scan_status is ScanStatus.NEVER_SCANNED
        assert machine.last_scanned_at is None
        assert session.query(CveFinding).filter_by(machine_id=machine.id).count() == 0
        assert session.query(Inventory).filter_by(machine_id=machine.id).count() == 0


def test_fleet_is_dense_enough_to_need_prioritising(session):
    """The demo has to reproduce the problem the product claims to solve.

    The README's argument is that a fleet produces several hundred findings and
    sorting by CVSS gives you no way to choose. Four findings per host quietly
    refutes that, because four items need no ranking.
    """
    seed_demo_fleet(session)

    findings = session.query(CveFinding).all()
    exploited = [f for f in findings if f.kev_listed is True]

    assert len(findings) >= 100
    assert len(exploited) >= 10
    # And the exploited ones must not be everywhere, or ranking by them is moot.
    assert len(exploited) < len(findings) / 2
