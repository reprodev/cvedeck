"""The EPSS cache is rewritten in parts behind a generation swap (Req 13.12, Property 26).

Before 0.19.0 the whole EPSS set -- 413,901 rows when measured -- was deleted
and reinserted in one transaction, which held SQLite's only write lock for
9.4 s on a fast disk and 15.7 s at 5 MB/s. Now it is written in parts, each
committed, under a generation no reader looks at, and one small commit makes
it live. These tests hold the part that makes that safe: whatever happens
between the parts, a reader sees one whole set.

The tests run against a SQLite *file*, not ``:memory:``: the point is what a
second connection sees between the first one's commits.
"""

from __future__ import annotations

import itertools
import pathlib
import tempfile
from datetime import datetime, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app.data.repository import EPSS_FEED_NAME, FindingInput, Repository
from app.data.schema import Base, EpssScore, FeedGeneration
from app.enums import FeedStatus, Severity
from app.scanner.epss_client import EpssRecord
from app.services.enrichment import EPSS_FEED, FeedRefreshService, FindingEnricher

_NOW = datetime(2026, 11, 27, tzinfo=timezone.utc)


class _Stop(Exception):
    """A refresh stopping partway: a crash, a full disk, a killed process."""


class _Db:
    def __init__(self, directory: str) -> None:
        path = pathlib.Path(directory) / "cvedeck.db"
        self.engine = create_engine(
            f"sqlite:///{path.as_posix()}", connect_args={"timeout": 5.0}
        )
        Base.metadata.create_all(self.engine)

    def view(self) -> tuple[dict[str, float], int, int]:
        """What a reader on its own connection sees: scores, count, live generation."""
        with Session(self.engine) as session:
            repo = Repository(session)
            every_id = set(session.execute(select(EpssScore.cve_id)).scalars())
            scores = {c: row.score for c, row in repo.get_epss_map(every_id).items()}
            return scores, repo.count_epss_scores(), repo._live_generation(EPSS_FEED_NAME)

    def generations(self) -> set[int]:
        with Session(self.engine) as session:
            return set(session.execute(select(EpssScore.generation).distinct()).scalars())

    def refresh(self, scores: dict[str, float], *, chunk_size: int = 2, hook=None) -> int | None:
        """Rewrite the cache as the service does: commit after each part.

        ``hook(i, commit)`` replaces the plain commit at the i-th part, so a
        test can stop the refresh before or after that commit, or run another
        refresh while this one holds no lock.
        """
        counter = itertools.count()
        with Session(self.engine) as session:
            def on_chunk() -> None:
                if hook is None:
                    session.commit()
                else:
                    hook(next(counter), session.commit)

            written = Repository(session).replace_epss_scores(
                _scores(scores), on_chunk=on_chunk, chunk_size=chunk_size
            )
            session.commit()
            return written


def _scores(scores: dict[str, float]) -> list[EpssScore]:
    return [
        EpssScore(cve_id=c, score=s, percentile=s, scored_at=_NOW) for c, s in scores.items()
    ]


_CVES = [f"CVE-2026-{n:04d}" for n in range(1, 13)]
_SETS = st.dictionaries(
    st.sampled_from(_CVES), st.integers(0, 1000).map(lambda n: n / 1000), min_size=1, max_size=8
)


# Feature: cvedeck, Property 26: The EPSS cache is always one whole set
@given(
    old=st.one_of(st.just({}), _SETS),
    first=_SETS,
    second=st.one_of(st.none(), _SETS),
    second_at=st.integers(-1, 25),
    stop_at=st.one_of(st.none(), st.integers(0, 25)),
    stop_before_commit=st.booleans(),
    chunk_size=st.integers(1, 3),
)
def test_a_reader_always_sees_one_whole_set(
    old, first, second, second_at, stop_at, stop_before_commit, chunk_size
):
    """Validates: Requirements 13.12 (Property 26).

    A refresh (``first``) is stopped at any part, before or after that part's
    commit, and a second refresh may run before it, between any two of its
    parts, or after it. After every part a reader on its own connection must
    see exactly one of the sets, whole; the live generation must never go
    backwards; and the set left live must be the one the rules say.
    """
    with tempfile.TemporaryDirectory() as directory:
        db = _Db(directory)
        try:
            _scenario(db, old, first, second, second_at, stop_at, stop_before_commit, chunk_size)
        finally:
            db.engine.dispose()


def _scenario(db, old, first, second, second_at, stop_at, stop_before_commit, chunk_size):
    if old:
        db.refresh(old)
    candidates = [old, first] + ([second] if second is not None else [])
    lives = [db.view()[2]]
    ran_second = {"when": None}

    def check() -> None:
        scores, count, live = db.view()
        assert scores in candidates, scores
        assert count == len(scores)
        assert live >= lives[-1], (live, lives)
        lives.append(live)

    def run_second(when: str) -> None:
        ran_second["when"] = when
        assert db.refresh(second, chunk_size=chunk_size) == len(second)
        check()

    def hook(i: int, commit) -> None:
        if stop_at == i and stop_before_commit:
            raise _Stop
        commit()
        check()
        if second is not None and ran_second["when"] is None and i == second_at:
            run_second("during")
        if stop_at == i:
            raise _Stop

    if second is not None and second_at == -1:
        run_second("before")
    stopped = False
    try:
        db.refresh(first, chunk_size=chunk_size, hook=hook)
    except _Stop:
        stopped = True
    if second is not None and ran_second["when"] is None:
        run_second("after")
    check()

    if ran_second["when"] in ("during", "after"):
        expected = second  # claimed later, so it wins whatever ``first`` did
    elif stopped:
        expected = second if ran_second["when"] == "before" else old
    else:
        expected = first
    assert db.view()[0] == expected

    # Two clean refreshes later, only the live set and the one before it remain.
    db.refresh({"CVE-2026-9001": 0.5})
    before = db.view()[2]
    db.refresh({"CVE-2026-9002": 0.25})
    assert db.view()[0] == {"CVE-2026-9002": 0.25}
    assert db.generations() == {before, db.view()[2]}


def test_a_set_missing_rows_never_goes_live(tmp_path):
    """The publish step counts the rows: a set that lost some is not shown."""
    db = _Db(str(tmp_path))
    db.refresh({"CVE-2026-0001": 0.1})

    def lose_a_row(i: int, commit) -> None:
        commit()
        if i == 1:
            with db.engine.begin() as conn:
                conn.execute(
                    EpssScore.__table__.delete().where(
                        EpssScore.generation > db.view()[2],
                        EpssScore.cve_id == "CVE-2026-0002",
                    )
                )

    assert db.refresh({"CVE-2026-0002": 0.2, "CVE-2026-0003": 0.3}, chunk_size=1, hook=lose_a_row) is None
    assert db.view()[0] == {"CVE-2026-0001": 0.1}


def test_the_live_generation_never_moves_backwards(tmp_path):
    """A refresh that claimed earlier but finishes later is not used."""
    db = _Db(str(tmp_path))
    with Session(db.engine) as early, Session(db.engine) as late:
        early_repo, late_repo = Repository(early), Repository(late)
        g_early = early_repo._claim_generation(EPSS_FEED_NAME)
        early.commit()
        g_late = late_repo._claim_generation(EPSS_FEED_NAME)
        late.commit()
        assert g_late > g_early

        late.add_all(_scores({"CVE-2026-0002": 0.2}))
        for row in late.new:
            row.generation = g_late
        late.flush()
        assert late_repo._publish_generation(g_late, 1)
        late.commit()

        early.add_all(_scores({"CVE-2026-0001": 0.1}))
        for row in early.new:
            row.generation = g_early
        early.flush()
        assert not early_repo._publish_generation(g_early, 1)
        early.commit()

    assert db.view()[0] == {"CVE-2026-0002": 0.2}


def test_without_a_checkpoint_the_rewrite_is_one_transaction(tmp_path):
    """The tests' default and any caller passing none: nothing commits partway."""
    db = _Db(str(tmp_path))
    db.refresh({"CVE-2026-0001": 0.1})
    with Session(db.engine) as session:
        Repository(session).replace_epss_scores(
            _scores({"CVE-2026-0002": 0.2, "CVE-2026-0003": 0.3}), chunk_size=1
        )
        session.rollback()
    assert db.view()[0] == {"CVE-2026-0001": 0.1}


def test_a_scan_enriched_mid_refresh_gets_the_previous_scores(tmp_path, monkeypatch):
    """The service end to end: a finding enriched between two parts of the
    rewrite is stamped from yesterday's set, never from half of today's."""
    db = _Db(str(tmp_path))
    with Session(db.engine) as session:
        repo = Repository(session)
        repo.replace_epss_scores(_scores({"CVE-2026-0001": 0.1, "CVE-2026-0002": 0.2}))
        repo.record_feed_refresh(EPSS_FEED, status=FeedStatus.OK, record_count=2)
        session.commit()

    seen: list[tuple[float | None, float | None]] = []

    def enrich_now() -> None:
        with Session(db.engine) as reader:
            found = FindingEnricher(Repository(reader)).enrich(
                [
                    FindingInput(
                        cve_id=c, cvss_score=7.5, severity=Severity.HIGH, source="osv",
                        package_identifier=f"Debian:12:pkg@1.0 ({c})",
                    )
                    for c in ("CVE-2026-0001", "CVE-2026-0002")
                ]
            )
            seen.append(tuple(f.epss_score for f in found))

    class _Source:
        def fetch(self):
            return [EpssRecord("CVE-2026-0001", 0.9, 0.9), EpssRecord("CVE-2026-0002", 0.8, 0.8)]

    original = Repository.replace_epss_scores
    monkeypatch.setattr(
        Repository,
        "replace_epss_scores",
        lambda self, scores, **kw: original(self, scores, **{**kw, "chunk_size": 1}),
    )
    with Session(db.engine) as session:
        def checkpoint() -> None:
            session.commit()
            enrich_now()

        outcomes = FeedRefreshService(
            Repository(session), epss_source=_Source(), checkpoint=checkpoint
        ).refresh_all()
        session.commit()

    assert [o.ok for o in outcomes] == [True]
    # Every enrichment before the final commit saw the old set; the last one, the new.
    assert seen[:-1] and all(s == (0.1, 0.2) for s in seen[:-1]), seen
    assert seen[-1] == (0.9, 0.8)


def test_a_superseded_refresh_reports_ok_and_records_nothing(tmp_path, monkeypatch):
    db = _Db(str(tmp_path))
    monkeypatch.setattr(Repository, "_publish_generation", lambda self, g, n: False)

    class _Source:
        def fetch(self):
            return [EpssRecord("CVE-2026-0001", 0.9, 0.9)]

    with Session(db.engine) as session:
        (outcome,) = FeedRefreshService(
            Repository(session), epss_source=_Source(), checkpoint=session.commit
        ).refresh_all()
        session.commit()
        assert outcome.ok and outcome.unchanged
        assert Repository(session).get_feed_refresh(EPSS_FEED) is None


def test_old_generations_are_deleted_in_parts(tmp_path):
    """The delete is chunked too: a whole old set in one statement is the
    same long write the rewrite was split up to avoid."""
    db = _Db(str(tmp_path))
    first = {c: 0.1 for c in _CVES}
    db.refresh(first, chunk_size=5)
    db.refresh({"CVE-2026-0001": 0.2}, chunk_size=5)
    commits = []
    with Session(db.engine) as session:
        def on_chunk() -> None:
            commits.append(1)
            session.commit()

        Repository(session).replace_epss_scores(
            _scores({"CVE-2026-0002": 0.3}), on_chunk=on_chunk, chunk_size=5
        )
        session.commit()
    # Claim, three deletes of 12 rows in fives plus the empty one that ends
    # the loop, then one insert part.
    assert len(commits) == 1 + 4 + 1
    assert len(db.generations()) == 2


def test_a_refresh_that_stops_does_not_cost_an_overlapping_one_its_set(tmp_path):
    """Clean-up deletes only generations *older* than live. A refresh that
    starts while another is writing, and then stops, must leave the first
    one's half-written set alone -- it is not stale, it is in progress."""
    db = _Db(str(tmp_path))
    db.refresh({"CVE-2026-0001": 0.1})

    def second_stops(i: int, commit) -> None:
        commit()
        if i == 1:
            raise _Stop

    def first(i: int, commit) -> None:
        commit()
        if i == 1:
            with pytest.raises(_Stop):
                db.refresh({"CVE-2026-0009": 0.9}, chunk_size=1, hook=second_stops)

    wanted = {"CVE-2026-0002": 0.2, "CVE-2026-0003": 0.3, "CVE-2026-0004": 0.4}
    assert db.refresh(wanted, chunk_size=1, hook=first) == 3
    assert db.view()[0] == wanted


def test_the_new_set_is_inserted_in_parts(tmp_path):
    """Twelve rows in fives: the claim, then three insert commits."""
    db = _Db(str(tmp_path))
    commits = []
    with Session(db.engine) as session:
        def on_chunk() -> None:
            commits.append(1)
            session.commit()

        Repository(session).replace_epss_scores(
            _scores({c: 0.1 for c in _CVES}), on_chunk=on_chunk, chunk_size=5
        )
        session.commit()
    assert len(commits) == 1 + 3
    assert db.view()[1] == 12


def test_the_claim_renders_for_postgresql():
    """The claim is the one dialect-specific statement; PostgreSQL must accept it."""
    from sqlalchemy.dialects.postgresql import insert

    stmt = (
        insert(FeedGeneration)
        .values(feed_name="epss", live=0, claimed=1)
        .on_conflict_do_update(
            index_elements=[FeedGeneration.feed_name],
            set_={"claimed": FeedGeneration.claimed + 1},
        )
        .returning(FeedGeneration.claimed)
    )
    sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (feed_name) DO UPDATE SET claimed = (feed_generations.claimed + " in sql
    assert "RETURNING feed_generations.claimed" in sql


@pytest.mark.parametrize("live", [None, 0])
def test_a_database_with_no_generation_row_reads_generation_zero(tmp_path, live):
    """What an upgraded 0.18 database and the demo seed both have."""
    db = _Db(str(tmp_path))
    with Session(db.engine) as session:
        session.add_all(_scores({"CVE-2026-0001": 0.1}))
        if live is not None:
            session.add(FeedGeneration(feed_name="epss", live=live, claimed=live))
        session.commit()
    assert db.view()[:2] == ({"CVE-2026-0001": 0.1}, 1)
