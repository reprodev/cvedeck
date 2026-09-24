"""Tests for threat-intel enrichment and feed cache refresh.

The invariant under test throughout this file is the one that makes enrichment
safe to act on: **an unenriched finding must be visibly unenriched.**

``kev_listed=None`` means "we did not check". ``kev_listed=False`` means "we
checked, and this CVE is genuinely not in CISA's catalogue". Collapsing the two
would present a stale or failed feed as "nothing here is being exploited" --
a silent false negative, and the worst failure mode a vulnerability scanner
has. Several tests below exist only to pin that distinction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import FindingInput, Repository
from app.data.schema import Base, EpssScore, KevEntry
from app.enums import FeedStatus, Severity
from app.scanner.epss_client import EpssRecord
from app.scanner.kev_client import KevRecord
from app.services.enrichment import (
    EPSS_FEED,
    KEV_FEED,
    FeedRefreshService,
    FindingEnricher,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture()
def repo(session):
    return Repository(session)


def _finding(cve_id: str, score: float = 7.5) -> FindingInput:
    return FindingInput(
        cve_id=cve_id,
        cvss_score=score,
        severity=Severity.HIGH,
        source="osv",
        package_identifier=f"Ubuntu:22.04:pkg@1.0 ({cve_id})",
    )


class _StubSource:
    """A feed source that returns a canned result or raises."""

    def __init__(self, records=None, error: Exception | None = None) -> None:
        self._records = records or []
        self._error = error
        self.calls = 0

    def fetch(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._records


def _seed_kev(repo: Repository, *cve_ids: str) -> None:
    repo.replace_kev_entries(
        [KevEntry(cve_id=c, due_date="2026-01-01") for c in cve_ids]
    )
    repo.record_feed_refresh(
        KEV_FEED, status=FeedStatus.OK, record_count=len(cve_ids)
    )


def _seed_epss(repo: Repository, scores: dict[str, tuple[float, float]]) -> None:
    now = datetime.now(timezone.utc)
    repo.replace_epss_scores(
        [
            EpssScore(cve_id=c, score=s, percentile=p, scored_at=now)
            for c, (s, p) in scores.items()
        ]
    )
    repo.record_feed_refresh(
        EPSS_FEED, status=FeedStatus.OK, record_count=len(scores)
    )


# --------------------------------------------------------------------------- #
# The unknown-vs-negative invariant
# --------------------------------------------------------------------------- #


def test_unrefreshed_kev_leaves_findings_unenriched_not_marked_safe(repo):
    """With no KEV cache, kev_listed stays None -- never False.

    This is the whole point of the feature. Returning False here would tell a
    user that nothing in their fleet is being actively exploited, on the basis
    of a catalogue that was never downloaded.
    """
    enricher = FindingEnricher(repo)
    [result] = enricher.enrich([_finding("CVE-2021-44228")])

    assert result.kev_listed is None
    assert result.kev_due_date is None
    assert result.epss_score is None


def test_populated_kev_marks_absent_cves_as_checked_and_absent(repo):
    """With a usable cache, absence is a real answer and is recorded as False."""
    _seed_kev(repo, "CVE-2021-44228")
    enricher = FindingEnricher(repo)

    listed, absent = enricher.enrich(
        [_finding("CVE-2021-44228"), _finding("CVE-2019-0001")]
    )

    assert listed.kev_listed is True
    assert listed.kev_due_date == "2026-01-01"
    assert absent.kev_listed is False
    assert absent.kev_due_date is None


def test_a_failed_refresh_does_not_invalidate_a_previously_good_cache(repo):
    """Yesterday's KEV answer beats no answer.

    A failed download must leave the cache intact, so enrichment keeps working
    (with data the dashboard reports as stale) rather than falling back to
    "unknown" for the whole fleet.
    """
    _seed_kev(repo, "CVE-2021-44228")
    service = FeedRefreshService(
        repo, kev_source=_StubSource(error=RuntimeError("upstream down"))
    )

    outcome = service.refresh_kev()

    assert outcome.status is FeedStatus.FAILED
    assert "upstream down" in (outcome.error_detail or "")
    [result] = FindingEnricher(repo).enrich([_finding("CVE-2021-44228")])
    assert result.kev_listed is True


def test_one_feed_being_usable_does_not_imply_the_other_is(repo):
    """EPSS present, KEV absent: each field reflects only its own feed."""
    _seed_epss(repo, {"CVE-2021-44228": (0.94, 0.99)})

    [result] = FindingEnricher(repo).enrich([_finding("CVE-2021-44228")])

    assert result.epss_score == pytest.approx(0.94)
    assert result.epss_percentile == pytest.approx(0.99)
    assert result.kev_listed is None


# --------------------------------------------------------------------------- #
# Enrichment behaviour
# --------------------------------------------------------------------------- #


def test_enrichment_preserves_order_and_every_original_field(repo):
    _seed_kev(repo, "CVE-2000-0002")
    findings = [_finding(f"CVE-2000-000{i}", score=float(i)) for i in range(1, 5)]

    enriched = FindingEnricher(repo).enrich(findings)

    assert [f.cve_id for f in enriched] == [f.cve_id for f in findings]
    for before, after in zip(findings, enriched):
        assert after.cvss_score == before.cvss_score
        assert after.severity == before.severity
        assert after.source == before.source
        assert after.package_identifier == before.package_identifier


def test_enrichment_matches_cve_ids_case_insensitively(repo):
    """Findings and feeds disagree on case often enough to matter."""
    _seed_kev(repo, "CVE-2021-44228")

    [result] = FindingEnricher(repo).enrich([_finding("cve-2021-44228")])

    assert result.kev_listed is True


def test_enrichment_of_an_empty_finding_list_is_empty(repo):
    assert FindingEnricher(repo).enrich([]) == []


def test_enrichment_handles_more_findings_than_the_in_clause_chunk(repo):
    """A fleet-wide pass exceeds SQLite's bound-parameter ceiling.

    Unchunked, this raises OperationalError on the first real fleet while
    passing every small fixture-sized test.
    """
    cve_ids = [f"CVE-2020-{i:05d}" for i in range(1500)]
    _seed_kev(repo, *cve_ids[:750])

    enriched = FindingEnricher(repo).enrich([_finding(c) for c in cve_ids])

    assert len(enriched) == 1500
    assert sum(1 for f in enriched if f.kev_listed) == 750
    assert all(f.kev_listed is not None for f in enriched)


# --------------------------------------------------------------------------- #
# Feed health / staleness
# --------------------------------------------------------------------------- #


def test_a_never_refreshed_feed_reports_stale_and_unusable(repo):
    health = FindingEnricher(repo).feed_health(KEV_FEED)

    assert health.status is FeedStatus.NEVER_REFRESHED
    assert health.stale is True
    assert health.usable is False


def test_a_fresh_feed_is_neither_stale_nor_unusable(repo):
    _seed_kev(repo, "CVE-2021-44228")

    health = FindingEnricher(repo).feed_health(KEV_FEED)

    assert health.status is FeedStatus.OK
    assert health.stale is False
    assert health.usable is True
    assert health.record_count == 1


def test_an_old_cache_is_reported_stale_but_stays_usable(repo, session):
    """Stale data still enriches; staleness is a warning, not a withdrawal.

    Refusing to enrich from a two-day-old KEV cache would throw away a nearly
    complete answer to avoid a marginally incomplete one.
    """
    _seed_kev(repo, "CVE-2021-44228")
    row = repo.get_feed_refresh(KEV_FEED)
    row.last_refreshed_at = datetime.now(timezone.utc) - timedelta(hours=100)
    session.flush()

    health = FindingEnricher(repo, max_age_hours=48.0).feed_health(KEV_FEED)

    assert health.stale is True
    assert health.usable is True
    [result] = FindingEnricher(repo).enrich([_finding("CVE-2021-44228")])
    assert result.kev_listed is True


def test_refresh_age_tracks_the_data_not_the_last_attempt(repo):
    """A failing feed must report the age of its data, not of its retry.

    Advancing last_refreshed_at on a failed attempt would make a feed that has
    been broken for a week look freshly updated.
    """
    _seed_kev(repo, "CVE-2021-44228")
    before = repo.get_feed_refresh(KEV_FEED).last_refreshed_at

    FeedRefreshService(
        repo, kev_source=_StubSource(error=RuntimeError("down"))
    ).refresh_kev()

    row = repo.get_feed_refresh(KEV_FEED)
    assert row.last_refreshed_at == before
    assert row.last_attempted_at is not None
    assert row.last_status is FeedStatus.FAILED


def test_all_feed_health_always_reports_both_feeds(repo):
    """A feed that has never run is reported, not omitted.

    Omitting it would imply the signal does not exist, rather than that it has
    not been fetched.
    """
    names = [h.feed_name for h in FindingEnricher(repo).all_feed_health()]
    assert names == [KEV_FEED, EPSS_FEED]


# --------------------------------------------------------------------------- #
# Feed refresh service
# --------------------------------------------------------------------------- #


def test_refresh_replaces_rather_than_merges_the_catalogue(repo):
    """A withdrawn KEV entry must stop being reported as known-exploited."""
    _seed_kev(repo, "CVE-2000-0001", "CVE-2000-0002")
    service = FeedRefreshService(
        repo, kev_source=_StubSource([KevRecord(cve_id="CVE-2000-0002")])
    )

    outcome = service.refresh_kev()

    assert outcome.record_count == 1
    listed = repo.get_kev_map({"CVE-2000-0001", "CVE-2000-0002"})
    assert set(listed) == {"CVE-2000-0002"}


def test_an_empty_feed_response_is_treated_as_a_failure(repo):
    """A 200 with no rows means the feed changed shape, not that KEV is empty.

    Writing it would erase every KEV flag in the fleet.
    """
    _seed_kev(repo, "CVE-2021-44228")
    service = FeedRefreshService(repo, kev_source=_StubSource([]))

    outcome = service.refresh_kev()

    assert outcome.status is FeedStatus.FAILED
    assert repo.get_kev_map({"CVE-2021-44228"})


def test_one_feed_failing_does_not_prevent_the_other_refreshing(repo):
    """KEV and EPSS are unrelated upstreams; one outage must not cost both."""
    service = FeedRefreshService(
        repo,
        kev_source=_StubSource(error=RuntimeError("cisa down")),
        epss_source=_StubSource(
            [EpssRecord(cve_id="CVE-2021-44228", score=0.9, percentile=0.99)]
        ),
    )

    outcomes = {o.feed_name: o for o in service.refresh_all()}

    assert outcomes[KEV_FEED].status is FeedStatus.FAILED
    assert outcomes[EPSS_FEED].status is FeedStatus.OK
    assert repo.get_epss_map({"CVE-2021-44228"})


def test_refresh_records_epss_scores_with_their_percentiles(repo):
    service = FeedRefreshService(
        repo,
        epss_source=_StubSource(
            [EpssRecord(cve_id="CVE-2021-44228", score=0.944, percentile=0.9995)]
        ),
    )

    assert service.refresh_epss().status is FeedStatus.OK
    stored = repo.get_epss_map({"CVE-2021-44228"})["CVE-2021-44228"]
    assert stored.score == pytest.approx(0.944)
    assert stored.percentile == pytest.approx(0.9995)


def test_an_unconfigured_feed_is_recorded_as_never_refreshed(repo):
    """Not "failed": nothing was attempted, so nothing broke."""
    outcome = FeedRefreshService(repo).refresh_kev()

    assert outcome.status is FeedStatus.NEVER_REFRESHED
    assert repo.get_feed_refresh(KEV_FEED).last_status is FeedStatus.NEVER_REFRESHED


def test_refresh_all_skips_feeds_with_no_configured_source(repo):
    service = FeedRefreshService(repo, kev_source=_StubSource([KevRecord("CVE-1")]))
    assert [o.feed_name for o in service.refresh_all()] == [KEV_FEED]


def test_a_defect_in_a_feed_source_is_not_disguised_as_an_outage(repo):
    """A TypeError is a bug, not CISA being down.

    Recording it as a feed outage would send someone to check the network for
    a defect that lives in this codebase -- the same reasoning as the
    programming-error re-raise in app.scanner.matcher.
    """
    service = FeedRefreshService(
        repo, kev_source=_StubSource(error=TypeError("bad call"))
    )
    with pytest.raises(TypeError):
        service.refresh_kev()


# --------------------------------------------------------------------------- #
# Properties
# --------------------------------------------------------------------------- #


def test_an_empty_catalogue_is_not_treated_as_a_usable_answer(repo):
    """Zero records with an OK status still enriches to None, not False.

    ``FeedRefreshService`` refuses to write an empty catalogue, so this state
    should be unreachable in production -- but if it ever is reached, the safe
    reading is "we know nothing", not "nothing in your fleet is exploited".
    """
    repo.record_feed_refresh(KEV_FEED, status=FeedStatus.OK, record_count=0)

    [result] = FindingEnricher(repo).enrich([_finding("CVE-2021-44228")])

    assert result.kev_listed is None


@given(
    listed=st.lists(
        st.integers(min_value=0, max_value=40),
        min_size=1,
        max_size=20,
        unique=True,
    ),
    queried=st.lists(
        st.integers(min_value=0, max_value=40), max_size=20, unique=True
    ),
)
def test_kev_flag_is_exactly_membership_of_the_cache(listed, queried):
    """With a usable cache, kev_listed is true iff the CVE is in it.

    Never None, for any query -- a usable cache always yields an answer.

    ``listed`` is non-empty because a zero-record cache is deliberately *not*
    usable; that case is pinned separately above.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        repo = Repository(session)
        _seed_kev(repo, *(f"CVE-2020-{i:05d}" for i in listed))

        findings = [_finding(f"CVE-2020-{i:05d}") for i in queried]
        enriched = FindingEnricher(repo).enrich(findings)

        listed_set = set(listed)
        for index, result in zip(queried, enriched):
            assert result.kev_listed is (index in listed_set)


@given(
    scores=st.dictionaries(
        st.integers(min_value=0, max_value=30),
        st.tuples(
            st.floats(min_value=0.0, max_value=1.0),
            st.floats(min_value=0.0, max_value=1.0),
        ),
        max_size=15,
    )
)
def test_enrichment_never_invents_an_epss_score(scores):
    """A CVE absent from the EPSS cache keeps a None score, not a zero.

    Zero would be indistinguishable from a genuinely measured near-zero
    probability and would sort as though it had been assessed.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        repo = Repository(session)
        _seed_epss(
            repo, {f"CVE-2020-{i:05d}": v for i, v in scores.items()}
        )

        findings = [_finding(f"CVE-2020-{i:05d}") for i in range(31)]
        enriched = FindingEnricher(repo).enrich(findings)

        for index, result in enumerate(enriched):
            if index in scores:
                assert result.epss_score == pytest.approx(scores[index][0])
            else:
                assert result.epss_score is None


# --------------------------------------------------------------------------- #
# Reapplying the feeds to findings already stored (Req 10.15)
# --------------------------------------------------------------------------- #
#
# ``enrich`` runs once per finding, at the scan that produced it. Until 0.8.8
# nothing re-read the cache afterwards, so a refresh updated the catalogue and
# left every stored finding asserting the exploitation status of a catalogue the
# system no longer held. These tests pin the reapply -- and, more importantly,
# pin that it obeys the same unknown-vs-negative invariant as the rest of this
# file, because a pass that writes to every finding in the fleet is exactly
# where a feed outage could quietly become reassurance.


def _store(session, repo, *cve_ids: str) -> None:
    """Persist findings for one machine, the way a scan would."""
    from app.data.schema import TargetMachine
    from app.enums import Platform, ScanStatus, SyncStatus

    session.add(
        TargetMachine(
            id="m1",
            hostname="host.example.com",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.SUCCESS,
            last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sync_status=SyncStatus.PENDING_SYNC,
        )
    )
    session.flush()
    repo.save_findings("m1", [_finding(c) for c in cve_ids])


def _stored(repo):
    """The stored findings, keyed by CVE id."""
    return {f.cve_id: f for f in repo.get_findings_for_machine("m1")}


def test_reapply_marks_a_newly_catalogued_cve_without_a_rescan(session, repo):
    """The point of the feature: KEV moves, the stored finding follows."""
    _store(session, repo, "CVE-2021-44228")
    assert _stored(repo)["CVE-2021-44228"].kev_listed is None

    _seed_kev(repo, "CVE-2021-44228")
    assert FindingEnricher(repo).reapply_to_stored() == 1

    finding = _stored(repo)["CVE-2021-44228"]
    assert finding.kev_listed is True
    assert finding.kev_due_date == "2026-01-01"


def test_reapply_clears_a_cve_that_left_the_catalogue(session, repo):
    """A usable catalogue is authoritative in both directions.

    Unlike a missing catalogue, one that has been downloaded and does not list
    the CVE is a real answer, so False is the honest value.
    """
    _store(session, repo, "CVE-2021-44228")
    _seed_kev(repo, "CVE-2021-44228")
    FindingEnricher(repo).reapply_to_stored()

    _seed_kev(repo, "CVE-2099-0001")  # a later catalogue, without the old CVE
    assert FindingEnricher(repo).reapply_to_stored() == 1
    assert _stored(repo)["CVE-2021-44228"].kev_listed is False


def test_a_kev_cache_this_instance_lacks_never_clears_a_stored_flag(
    session, repo
):
    """The invariant, on the reapply path.

    This is the test that matters in this section. A fleet-wide pass that runs
    after every refresh is the one place an outage could rewrite every finding
    at once -- turning "we know this is being exploited" into "we checked and
    it is not" on the strength of a catalogue the instance does not hold.

    The state modelled is a database carried onto an instance whose feeds have
    never been fetched: a restored backup, or a first boot against existing
    data. The findings still carry what the scan that produced them learned,
    and an empty catalogue is not evidence against it.

    Note this is *not* the same as a failed download. ``record_feed_refresh``
    deliberately leaves the previous cache and its record in place on failure,
    so a transient outage keeps serving yesterday's answer and the feed stays
    usable. The dangerous state is having no catalogue at all.
    """
    _store(session, repo, "CVE-2021-44228")
    _seed_kev(repo, "CVE-2021-44228")
    FindingEnricher(repo).reapply_to_stored()
    assert _stored(repo)["CVE-2021-44228"].kev_listed is True

    repo.replace_kev_entries([])
    repo.record_feed_refresh(KEV_FEED, status=FeedStatus.OK, record_count=0)
    assert not FindingEnricher(repo).feed_health(KEV_FEED).usable

    assert FindingEnricher(repo).reapply_to_stored() == 0
    finding = _stored(repo)["CVE-2021-44228"]
    assert finding.kev_listed is True
    assert finding.kev_due_date == "2026-01-01"


def test_reapply_does_not_drop_a_score_for_a_cve_epss_does_not_rank(
    session, repo
):
    """A usable EPSS set only writes scores it has, as ``enrich`` does."""
    _store(session, repo, "CVE-2021-44228")
    _seed_epss(repo, {"CVE-2021-44228": (0.42, 0.97)})
    FindingEnricher(repo).reapply_to_stored()
    assert _stored(repo)["CVE-2021-44228"].epss_score == pytest.approx(0.42)

    _seed_epss(repo, {"CVE-2099-0001": (0.1, 0.5)})  # no longer ranks ours
    FindingEnricher(repo).reapply_to_stored()
    assert _stored(repo)["CVE-2021-44228"].epss_score == pytest.approx(0.42)


def test_reapply_touches_nothing_when_neither_feed_is_usable(session, repo):
    """No cache, no writes, no count -- and no findings marked for sync."""
    from app.enums import SyncStatus

    _store(session, repo, "CVE-2021-44228")
    stored = _stored(repo)["CVE-2021-44228"]
    stored.sync_status = SyncStatus.SYNCED
    session.flush()

    assert FindingEnricher(repo).reapply_to_stored() == 0
    assert _stored(repo)["CVE-2021-44228"].sync_status is SyncStatus.SYNCED


def test_a_changed_finding_goes_back_to_pending_sync(session, repo):
    """Otherwise the Online_Database keeps the old exploitation status.

    The sync propagates what is pending. A finding already marked SYNCED whose
    KEV flag has just flipped would never be picked up again by anything.
    """
    from app.enums import SyncStatus

    _store(session, repo, "CVE-2021-44228")
    stored = _stored(repo)["CVE-2021-44228"]
    stored.sync_status = SyncStatus.SYNCED
    session.flush()

    _seed_kev(repo, "CVE-2021-44228")
    assert FindingEnricher(repo).reapply_to_stored() == 1
    assert _stored(repo)["CVE-2021-44228"].sync_status is SyncStatus.PENDING_SYNC


def test_reapply_counts_only_findings_that_actually_changed(session, repo):
    """A refresh that brings no news reports zero, not the fleet size."""
    _store(session, repo, "CVE-2021-44228", "CVE-2099-0001")
    _seed_kev(repo, "CVE-2021-44228")

    assert FindingEnricher(repo).reapply_to_stored() == 2  # both learn an answer
    assert FindingEnricher(repo).reapply_to_stored() == 0  # nothing moved


# --------------------------------------------------------------------------- #
# A refresh that carries no news (Req 10.14)
# --------------------------------------------------------------------------- #
#
# Both feeds publish daily and are downloaded whole. Most days nothing a
# deployment stores has actually moved, and until 0.8.9 every refresh still
# deleted and re-inserted the entire catalogue -- roughly 270k rows for EPSS --
# and then re-read it onto every stored finding.


def test_an_unchanged_catalogue_is_not_rewritten(repo):
    """The second refresh of identical records writes nothing."""
    source = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    service = FeedRefreshService(repo, kev_source=source, epss_source=None)

    first = service.refresh_kev()
    assert first.ok and not first.unchanged

    second = service.refresh_kev()

    assert second.ok
    assert second.unchanged
    assert second.record_count == first.record_count
    # Still a success, and still current: the cache genuinely was checked
    # against the upstream just now. Reporting it as stale because nothing had
    # changed would invert the meaning of the age the dashboard shows.
    assert FindingEnricher(repo).feed_health(KEV_FEED).stale is False
    assert source.calls == 2


def test_a_changed_catalogue_is_rewritten(repo):
    """One added entry is enough to make it a real refresh again."""
    source = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    service = FeedRefreshService(repo, kev_source=source, epss_source=None)
    service.refresh_kev()

    source._records = [
        KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01"),
        KevRecord(cve_id="CVE-2024-3094", due_date="2026-04-01"),
    ]
    third = service.refresh_kev()

    assert third.ok
    assert not third.unchanged
    assert third.record_count == 2
    assert set(repo.get_kev_map({"CVE-2021-44228", "CVE-2024-3094"})) == {
        "CVE-2021-44228",
        "CVE-2024-3094",
    }


def test_reordered_but_identical_records_still_count_as_unchanged(repo):
    """Neither upstream promises an order, so order must not force a rewrite."""
    a = KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")
    b = KevRecord(cve_id="CVE-2024-3094", due_date="2026-04-01")
    source = _StubSource([a, b])
    service = FeedRefreshService(repo, kev_source=source, epss_source=None)
    service.refresh_kev()

    source._records = [b, a]

    assert service.refresh_kev().unchanged


def test_a_failed_refresh_does_not_clear_the_digest(repo):
    """Or the next real download would be skipped against a stale cache.

    The digest describes the catalogue actually held. An outage changes nothing
    about that, so it must survive one -- and the refresh after it, carrying the
    same records, is genuinely unchanged.
    """
    source = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    service = FeedRefreshService(repo, kev_source=source, epss_source=None)
    service.refresh_kev()

    failing = FeedRefreshService(
        repo,
        kev_source=_StubSource(error=RuntimeError("connection refused")),
        epss_source=None,
    )
    assert not failing.refresh_kev().ok
    assert repo.get_feed_refresh(KEV_FEED).payload_digest is not None

    assert service.refresh_kev().unchanged


def test_an_emptied_cache_is_rewritten_even_when_the_digest_matches(repo):
    """A digest with nothing behind it must not be trusted.

    The catalogue is emptied and the refresh row is left **exactly as it was**,
    still claiming one record -- a partial restore, or a prune that did not know
    about ``feed_refreshes``. This is the shape the real failure takes, and the
    earlier version of this test did not have it: it reset ``record_count`` to 0
    by hand, so it passed against a guard that only ever read that column and
    could witness nothing. Trusting the column let an empty catalogue report
    itself usable, and every finding was then stamped *not exploited* on the
    authority of no catalogue at all.
    """
    source = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    service = FeedRefreshService(repo, kev_source=source, epss_source=None)
    service.refresh_kev()

    repo.replace_kev_entries([])
    assert repo.get_feed_refresh(KEV_FEED).record_count == 1, "the stale claim stands"

    outcome = service.refresh_kev()

    assert not outcome.unchanged
    assert repo.get_kev_map({"CVE-2021-44228"})
    assert repo.count_kev_entries() == 1


def test_an_emptied_epss_cache_is_rewritten_even_when_the_digest_matches(repo):
    """The same guard, on the feed whose catalogue is 270,000 rows."""
    source = _StubSource([EpssRecord(cve_id="CVE-2021-44228", score=0.42, percentile=0.97)])
    service = FeedRefreshService(repo, kev_source=None, epss_source=source)
    service.refresh_epss()

    repo.replace_epss_scores([])

    assert not service.refresh_epss().unchanged
    assert repo.count_epss_scores() == 1


def test_epss_ignores_its_write_timestamp_when_deciding(repo):
    """``scored_at`` is stamped at write time, not carried by the feed.

    Including it in the digest would make every refresh differ from the last
    and the short-circuit would never fire.
    """
    source = _StubSource([EpssRecord(cve_id="CVE-2021-44228", score=0.42, percentile=0.97)])
    service = FeedRefreshService(repo, kev_source=None, epss_source=source)

    assert not service.refresh_epss().unchanged
    assert service.refresh_epss().unchanged


# ---------------------------------------------------------------------------
# refresh_feeds_and_reapply: the joined sequence
#
# Everything above tests the two halves separately. These test the function
# that joins them, which is where 0.8.9's demo guard was placed one call too
# late -- after the download and the wholesale catalogue rewrite, so it skipped
# only the reapply. Nothing in this file mentioned demo mode at all, which is
# the hole that let a guard land downstream of the side effect it was written
# to prevent.
# ---------------------------------------------------------------------------


class _ExplodingSource:
    """A feed source that fails the test if anything reaches for it.

    Asserting on the return value is not enough: the bug being pinned here did
    return ``([], 0)`` truthfully, having already downloaded both feeds and
    replaced both catalogues on the way. Only refusing to be called can witness
    that the network was never touched.
    """

    def fetch(self):  # pragma: no cover - the point is that it never runs
        raise AssertionError("demo mode reached for a feed")


@pytest.fixture()
def demo(monkeypatch):
    monkeypatch.setenv("CVEDECK_DEMO_MODE", "true")


def test_demo_mode_refreshes_nothing_and_downloads_nothing(repo, demo, monkeypatch):
    """The guard is before the download, not after it (Req 15.6)."""
    from app.services import enrichment

    monkeypatch.setattr(
        enrichment,
        "build_feed_refresh_service",
        lambda repository: FeedRefreshService(
            repository, kev_source=_ExplodingSource(), epss_source=_ExplodingSource()
        ),
    )

    outcomes, updated = enrichment.refresh_feeds_and_reapply(repo)

    assert updated == 0
    assert {o.feed_name for o in outcomes} == {KEV_FEED, EPSS_FEED}
    assert all(o.status is FeedStatus.SKIPPED for o in outcomes)
    assert all(not o.ok for o in outcomes), "skipped is not success"


def test_a_demo_refresh_leaves_the_seeded_catalogue_intact(repo, demo, monkeypatch):
    """The fixture survives. Re-seeding is guarded on an empty fleet, so a
    catalogue overwritten here is gone permanently."""
    from app.services import enrichment

    repo.replace_kev_entries(
        [KevEntry(cve_id="CVE-2021-44228", due_date="2026-01-01")]
    )
    repo.replace_epss_scores(
        [EpssScore(cve_id="CVE-2021-44228", score=0.97, percentile=0.99,
                   scored_at=datetime.now(timezone.utc))]
    )
    monkeypatch.setattr(
        enrichment,
        "build_feed_refresh_service",
        lambda repository: FeedRefreshService(
            repository, kev_source=_ExplodingSource(), epss_source=_ExplodingSource()
        ),
    )

    enrichment.refresh_feeds_and_reapply(repo)

    assert repo.count_kev_entries() == 1
    assert repo.count_epss_scores() == 1
    assert repo.get_kev_map({"CVE-2021-44228"})


def test_a_demo_refresh_records_no_digest(repo, demo, monkeypatch):
    """A digest written with no reapply behind it suppresses the first real
    refresh after demo mode is switched off, and it self-heals only when
    upstream next changes."""
    from app.services import enrichment

    monkeypatch.setattr(
        enrichment,
        "build_feed_refresh_service",
        lambda repository: FeedRefreshService(
            repository, kev_source=_ExplodingSource(), epss_source=_ExplodingSource()
        ),
    )

    enrichment.refresh_feeds_and_reapply(repo)

    assert repo.get_feed_refresh(KEV_FEED) is None
    assert repo.get_feed_refresh(EPSS_FEED) is None


def test_both_feeds_unchanged_skips_the_reapply(repo, monkeypatch):
    """The short-circuit, at the level that owns it."""
    from app.services import enrichment

    kev = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    epss = _StubSource([EpssRecord(cve_id="CVE-2021-44228", score=0.42, percentile=0.97)])
    monkeypatch.setattr(
        enrichment,
        "build_feed_refresh_service",
        lambda repository: FeedRefreshService(
            repository, kev_source=kev, epss_source=epss
        ),
    )
    enrichment.refresh_feeds_and_reapply(repo)  # first pass: rewrites and reapplies

    called = []
    monkeypatch.setattr(
        enrichment.FindingEnricher,
        "reapply_to_stored",
        lambda self: called.append(True) or 0,
    )
    outcomes, updated = enrichment.refresh_feeds_and_reapply(repo)

    assert all(o.unchanged for o in outcomes)
    assert updated == 0
    assert called == [], "nothing changed, so nothing needed reapplying"


def test_one_unchanged_feed_still_reapplies(repo, monkeypatch):
    """One feed unchanged and the other rewritten still needs the pass -- the
    branch that decides this had no test of its own."""
    from app.services import enrichment

    kev = _StubSource([KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")])
    epss = _StubSource([EpssRecord(cve_id="CVE-2021-44228", score=0.42, percentile=0.97)])
    monkeypatch.setattr(
        enrichment,
        "build_feed_refresh_service",
        lambda repository: FeedRefreshService(
            repository, kev_source=kev, epss_source=epss
        ),
    )
    enrichment.refresh_feeds_and_reapply(repo)

    # EPSS moves; KEV does not.
    epss._records = [EpssRecord(cve_id="CVE-2021-44228", score=0.88, percentile=0.99)]

    called = []
    monkeypatch.setattr(
        enrichment.FindingEnricher,
        "reapply_to_stored",
        lambda self: called.append(True) or 0,
    )
    outcomes, _ = enrichment.refresh_feeds_and_reapply(repo)

    by_feed = {o.feed_name: o for o in outcomes}
    assert by_feed[KEV_FEED].unchanged
    assert not by_feed[EPSS_FEED].unchanged
    assert called == [True], "a rewritten feed must reach the stored findings"


def test_an_oversized_download_is_a_failed_refresh_and_the_cache_stands(repo):
    """Req 10.18: a feed over its size limit is an outage, not an empty catalogue.

    Driven through the real KEV client and a transport that sends too much, so
    the breach is raised by the code that enforces the limit.
    """
    import httpx

    from app.scanner.kev_client import KevHttpClient

    _seed_kev(repo, "CVE-2021-44228")
    too_big = b"[" + b"{}," * 20_000 + b"{}]"
    source = KevHttpClient(
        "https://feed.test/kev.json",
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=too_big))
        ),
    )
    import app.scanner.kev_client as kev_module

    original = kev_module._MAX_CATALOGUE
    kev_module._MAX_CATALOGUE = 1024
    try:
        outcome = FeedRefreshService(repo, kev_source=source).refresh_kev()
    finally:
        kev_module._MAX_CATALOGUE = original

    assert outcome.status is FeedStatus.FAILED
    assert "MiB" in (outcome.error_detail or "")
    [result] = FindingEnricher(repo).enrich([_finding("CVE-2021-44228")])
    assert result.kev_listed is True
