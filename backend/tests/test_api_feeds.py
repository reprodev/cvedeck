"""API tests for the threat-intel feed endpoints.

``GET /api/feeds`` exists so the dashboard can distinguish "no findings are
known-exploited" from "the KEV feed has not refreshed in three weeks". Without
it, a feed that has been failing silently is indistinguishable from a healthy
fleet -- so several tests here assert on what the endpoint *reveals* rather
than only on its shape.

``POST /api/feeds/refresh`` is covered against a stubbed source; nothing in this
file touches the network.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import FindingInput, Repository
from app.data.schema import Base, EpssScore, KevEntry, TargetMachine
from app.enums import (
    FeedStatus,
    Platform,
    ScanStatus,
    Severity,
    SyncStatus,
)
from app.services.enrichment import EPSS_FEED, KEV_FEED


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def client(session):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


@pytest.fixture()
def repo(session):
    return Repository(session)


def _feeds_by_name(client: TestClient) -> dict[str, dict]:
    resp = client.get("/api/feeds")
    assert resp.status_code == 200
    return {row["feed_name"]: row for row in resp.json()}


# --------------------------------------------------------------------------- #
# GET /api/feeds
# --------------------------------------------------------------------------- #


def test_both_feeds_are_reported_before_either_has_ever_run(client):
    """A never-fetched feed is reported, not omitted.

    Omitting it would imply the signal does not exist rather than that nobody
    has fetched it, and the dashboard would have nothing to prompt with.
    """
    feeds = _feeds_by_name(client)

    assert set(feeds) == {KEV_FEED, EPSS_FEED}
    for row in feeds.values():
        assert row["status"] == FeedStatus.NEVER_REFRESHED.value
        assert row["stale"] is True
        assert row["usable"] is False
        assert row["record_count"] == 0
        assert row["last_refreshed_at"] is None


def test_a_refreshed_feed_reports_fresh_usable_and_counted(client, repo, session):
    repo.replace_kev_entries([KevEntry(cve_id="CVE-2021-44228")])
    repo.record_feed_refresh(KEV_FEED, status=FeedStatus.OK, record_count=1)
    session.commit()

    kev = _feeds_by_name(client)[KEV_FEED]

    assert kev["status"] == FeedStatus.OK.value
    assert kev["stale"] is False
    assert kev["usable"] is True
    assert kev["record_count"] == 1
    assert kev["last_refreshed_at"] is not None


def test_a_stale_cache_is_flagged_while_remaining_usable(client, repo, session):
    """Staleness is a warning to show, not a reason to withhold the signal."""
    repo.replace_kev_entries([KevEntry(cve_id="CVE-2021-44228")])
    row = repo.record_feed_refresh(KEV_FEED, status=FeedStatus.OK, record_count=1)
    row.last_refreshed_at = datetime.now(timezone.utc) - timedelta(days=30)
    session.commit()

    kev = _feeds_by_name(client)[KEV_FEED]

    assert kev["stale"] is True
    assert kev["usable"] is True


def test_a_failed_refresh_surfaces_its_error_detail(client, repo, session):
    """The dashboard has to be able to say *why* enrichment is degraded."""
    repo.record_feed_refresh(
        KEV_FEED, status=FeedStatus.FAILED, error_detail="upstream 503"
    )
    session.commit()

    kev = _feeds_by_name(client)[KEV_FEED]

    assert kev["status"] == FeedStatus.FAILED.value
    assert kev["error_detail"] == "upstream 503"
    assert kev["last_attempted_at"] is not None
    assert kev["last_refreshed_at"] is None


# --------------------------------------------------------------------------- #
# Enrichment as seen through the findings API
# --------------------------------------------------------------------------- #


def _seed_machine_with_finding(repo: Repository, session: Session, **finding_kwargs):
    session.add(
        TargetMachine(
            id="m1",
            hostname="host-1",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.SUCCESS,
            last_scanned_at=datetime.now(timezone.utc),
            sync_status=SyncStatus.SYNCED,
        )
    )
    session.flush()
    repo.save_findings(
        "m1",
        [
            FindingInput(
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                severity=Severity.CRITICAL,
                source="osv",
                package_identifier="Ubuntu:22.04:log4j@2.14 (fixed in 2.17)",
                **finding_kwargs,
            )
        ],
    )
    session.commit()


def test_an_unenriched_finding_reports_null_not_false(client, repo, session):
    """The invariant, end to end.

    A client receiving ``kev_listed: null`` must render "unknown". Receiving
    ``false`` here would let the UI tell a user that a Log4Shell finding is not
    being exploited, on the basis of a catalogue nobody downloaded.
    """
    _seed_machine_with_finding(repo, session)

    [finding] = client.get("/api/machines/m1/cves").json()

    assert finding["kev_listed"] is None
    assert finding["kev_due_date"] is None
    assert finding["epss_score"] is None
    assert finding["epss_percentile"] is None


def test_enrichment_values_reach_the_findings_response(client, repo, session):
    _seed_machine_with_finding(
        repo,
        session,
        kev_listed=True,
        kev_due_date="2021-12-24",
        epss_score=0.944,
        epss_percentile=0.9995,
    )

    [finding] = client.get("/api/machines/m1/cves").json()

    assert finding["kev_listed"] is True
    assert finding["kev_due_date"] == "2021-12-24"
    assert finding["epss_score"] == pytest.approx(0.944)
    assert finding["epss_percentile"] == pytest.approx(0.9995)


def test_a_checked_and_absent_finding_reports_false(client, repo, session):
    """False is a real answer and must survive the round trip distinctly."""
    _seed_machine_with_finding(repo, session, kev_listed=False)

    [finding] = client.get("/api/machines/m1/cves").json()

    assert finding["kev_listed"] is False


def test_enrichment_reaches_the_fleet_wide_cve_listing(client, repo, session):
    """/api/cves is the CVE-first pivot; it must carry the same signals."""
    _seed_machine_with_finding(repo, session, kev_listed=True, epss_score=0.5)

    [finding] = client.get("/api/cves").json()

    assert finding["kev_listed"] is True
    assert finding["epss_score"] == pytest.approx(0.5)


# --------------------------------------------------------------------------- #
# POST /api/feeds/refresh
# --------------------------------------------------------------------------- #


def test_refresh_reports_per_feed_outcomes(client, session, monkeypatch):
    """Both feeds report independently so a partial refresh is legible."""
    from app.scanner.epss_client import EpssRecord
    from app.scanner.kev_client import KevRecord

    monkeypatch.setattr(
        "app.api.actions.KevHttpClient",
        lambda *a, **k: type(
            "S", (), {"fetch": lambda self: [KevRecord(cve_id="CVE-2021-44228")]}
        )(),
    )
    monkeypatch.setattr(
        "app.api.actions.EpssHttpClient",
        lambda *a, **k: type(
            "S",
            (),
            {
                "fetch": lambda self: [
                    EpssRecord(cve_id="CVE-2021-44228", score=0.9, percentile=0.99)
                ]
            },
        )(),
    )

    resp = client.post("/api/feeds/refresh")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    by_name = {r["feed_name"]: r for r in body["results"]}
    assert by_name[KEV_FEED]["record_count"] == 1
    assert by_name[EPSS_FEED]["record_count"] == 1


def test_refresh_reports_not_ok_when_one_feed_fails(client, session, monkeypatch):
    from app.scanner.epss_client import EpssRecord

    def _boom(self):
        raise RuntimeError("cisa unreachable")

    monkeypatch.setattr(
        "app.api.actions.KevHttpClient",
        lambda *a, **k: type("S", (), {"fetch": _boom})(),
    )
    monkeypatch.setattr(
        "app.api.actions.EpssHttpClient",
        lambda *a, **k: type(
            "S",
            (),
            {
                "fetch": lambda self: [
                    EpssRecord(cve_id="CVE-2021-44228", score=0.9, percentile=0.99)
                ]
            },
        )(),
    )

    body = client.post("/api/feeds/refresh").json()

    assert body["ok"] is False
    by_name = {r["feed_name"]: r for r in body["results"]}
    assert by_name[KEV_FEED]["status"] == FeedStatus.FAILED.value
    assert "cisa unreachable" in by_name[KEV_FEED]["error_detail"]
    # The healthy feed still updated: one upstream outage must not cost both.
    assert by_name[EPSS_FEED]["status"] == FeedStatus.OK.value


def test_a_successful_refresh_is_visible_through_the_feeds_endpoint(
    client, session, monkeypatch
):
    """The write and the read agree -- the refresh actually committed."""
    from app.scanner.kev_client import KevRecord

    monkeypatch.setattr(
        "app.api.actions.KevHttpClient",
        lambda *a, **k: type(
            "S", (), {"fetch": lambda self: [KevRecord(cve_id="CVE-2021-44228")]}
        )(),
    )
    monkeypatch.setattr(
        "app.api.actions.EpssHttpClient",
        lambda *a, **k: type("S", (), {"fetch": lambda self: []})(),
    )

    client.post("/api/feeds/refresh")

    kev = _feeds_by_name(client)[KEV_FEED]
    assert kev["usable"] is True
    assert kev["record_count"] == 1
