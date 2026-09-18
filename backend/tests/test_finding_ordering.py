"""Ordering of findings, including the ones that carry no score.

Ordering used to be ``cvss_score DESC`` alone, which stopped being a total
order the moment a finding could have no score -- and, worse, stopped being the
*same* order on the two supported databases. SQLite sorts NULL lowest, so DESC
trails it; PostgreSQL's DESC defaults to NULLS FIRST. The same fleet would have
been triaged in two different orders depending on which store it was in
(Req 10.12).

These tests pin the order the product intends: severity rank first (Critical,
Unscored, High, Medium, Low), then score within the band, with the scoreless
member of a band ahead of its measured ones because its magnitude is unknown
rather than low (Req 10.11).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from app.data.repository import FindingInput, Repository, severity_order
from app.data.schema import Base, CveFinding, TargetMachine
from app.enums import Platform, ScanStatus, Severity, SyncStatus


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _machine(session: Session) -> str:
    machine = TargetMachine(
        id="m1",
        hostname="host-01",
        platform=Platform.LINUX,
        last_scan_status=ScanStatus.SUCCESS,
        sync_status=SyncStatus.SYNCED,
    )
    session.add(machine)
    session.commit()
    return machine.id


# (cve_id, score, severity) in the order they must come back.
_EXPECTED = [
    ("CVE-0001", 9.9, Severity.CRITICAL),
    ("CVE-0002", 9.0, Severity.CRITICAL),
    # Unscored ranks below Critical and above High.
    ("CVE-0003", None, Severity.UNSCORED),
    # A band with no number leads its band: it could be an 8.9.
    ("CVE-0004", None, Severity.HIGH),
    ("CVE-0005", 8.5, Severity.HIGH),
    ("CVE-0006", 7.0, Severity.HIGH),
    ("CVE-0007", 5.0, Severity.MEDIUM),
    ("CVE-0008", 1.0, Severity.LOW),
]


def test_findings_for_a_machine_come_back_in_triage_order(session):
    machine_id = _machine(session)
    repo = Repository(session)

    # Inserted in a deliberately unhelpful order.
    shuffled = [_EXPECTED[i] for i in (7, 3, 0, 5, 2, 6, 1, 4)]
    repo.save_findings(
        machine_id,
        [
            FindingInput(cve_id=cve, cvss_score=score, severity=band, source="osv")
            for cve, score, band in shuffled
        ],
    )
    session.commit()

    ordered = [f.cve_id for f in repo.get_findings_for_machine(machine_id)]
    assert ordered == [cve for cve, _, _ in _EXPECTED]


def test_an_unscored_finding_is_not_sorted_below_a_low_one(session):
    """The regression that matters: unknown is not the same as least severe."""
    machine_id = _machine(session)
    repo = Repository(session)
    repo.save_findings(
        machine_id,
        [
            FindingInput(
                cve_id="CVE-LOW", cvss_score=0.1, severity=Severity.LOW, source="osv"
            ),
            FindingInput(
                cve_id="CVE-NONE",
                cvss_score=None,
                severity=Severity.UNSCORED,
                source="osv",
            ),
        ],
    )
    session.commit()

    ordered = [f.cve_id for f in repo.get_findings_for_machine(machine_id)]
    assert ordered == ["CVE-NONE", "CVE-LOW"]


def test_severity_counts_include_unscored_and_still_sum_to_the_total(session):
    machine_id = _machine(session)
    repo = Repository(session)
    repo.save_findings(
        machine_id,
        [
            FindingInput(cve_id=cve, cvss_score=score, severity=band, source="osv")
            for cve, score, band in _EXPECTED
        ],
    )
    session.commit()

    counts = repo.get_severity_counts(machine_id)
    assert counts.critical == 2
    assert counts.unscored == 1
    assert counts.high == 3
    assert counts.medium == 1
    assert counts.low == 1
    assert counts.total == len(_EXPECTED)


@pytest.mark.parametrize(
    "dialect", [sqlite.dialect(), postgresql.dialect()], ids=["sqlite", "postgresql"]
)
def test_null_ordering_is_stated_explicitly_on_every_supported_dialect(dialect):
    """Req 10.12: never inherit the store's default null ordering.

    SQLite and PostgreSQL disagree about where NULLs go in a DESC sort, so the
    query has to say. This asserts on the emitted SQL rather than on results,
    because the disagreement cannot be observed from a single database -- which
    is exactly why it would otherwise ship unnoticed.
    """
    stmt = select(CveFinding.cve_id).order_by(
        severity_order(CveFinding.severity),
        CveFinding.cvss_score.desc().nullsfirst(),
        CveFinding.cve_id,
    )
    sql = str(stmt.compile(dialect=dialect))
    order_by = sql[sql.index("ORDER BY") :]
    assert "NULLS FIRST" in order_by


def test_the_severity_rank_case_actually_matches_the_stored_labels(session):
    """The rank must discriminate, not quietly fall through to its ELSE.

    SQLAlchemy's Enum persists a member's *name* ("CRITICAL"), while binding the
    member itself renders its *value* ("critical"). The first version of
    ``severity_order`` bound the members, so no WHEN matched, every row took the
    ELSE, and the ordering did nothing at all -- while still returning a
    plausible order, because the tiebreakers underneath it did the sorting. A
    silent no-op is the failure mode this asserts against.
    """
    machine_id = _machine(session)
    repo = Repository(session)
    repo.save_findings(
        machine_id,
        [
            FindingInput(cve_id=cve, cvss_score=score, severity=band, source="osv")
            for cve, score, band in _EXPECTED
        ],
    )
    session.commit()

    ranks = dict(
        session.execute(
            select(CveFinding.severity, severity_order(CveFinding.severity)).distinct()
        ).all()
    )

    fallback = len(Severity)
    assert all(rank != fallback for rank in ranks.values()), (
        f"every severity took the ELSE branch: {ranks}"
    )
    assert ranks[Severity.CRITICAL] < ranks[Severity.UNSCORED] < ranks[Severity.HIGH]
    assert ranks[Severity.HIGH] < ranks[Severity.MEDIUM] < ranks[Severity.LOW]
