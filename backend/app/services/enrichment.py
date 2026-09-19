"""Threat-intel enrichment: attaching KEV and EPSS signals to findings.

A CVSS score describes how bad a vulnerability would be *if* exploited. It says
nothing about whether anyone is exploiting it. A fleet of thirty hosts routinely
produces several hundred High and Critical findings, and ranking those by CVSS
alone gives no way to tell the three that matter this week from the rest.

This module adds the two signals that do:

- **KEV** -- CISA's catalogue of vulnerabilities observed being exploited in the
  wild, each with a federal remediation due date.
- **EPSS** -- FIRST's modelled probability of exploitation in the next 30 days,
  plus that probability's percentile rank among all scored CVEs.

Two responsibilities live here, deliberately separated:

- :class:`FeedRefreshService` pulls the KEV and EPSS feeds into the local cache
  and records the outcome. This is periodic, network-bound, and failable.
- :class:`FindingEnricher` joins already-collected findings against that cache.
  This is per-scan, purely local, and cannot fail.

Enrichment runs *after* matching rather than inside it. ``Matcher.match`` is
pure and heavily property-tested; threading a database session and two feed
lookups through it would trade that away for no benefit, since enrichment
depends only on a finding's CVE id.

**The invariant that matters here** (mirroring ``AGENTS.md`` §3): an unenriched
finding must be visibly unenriched. ``kev_listed=None`` means "not checked";
``kev_listed=False`` means "checked, and genuinely not in the catalogue". These
are never collapsed. Treating a stale or failed feed as "nothing is exploited"
would be a silent false negative -- the worst failure mode a vulnerability
scanner has, and precisely what ``last_scan_sources_ok`` was added to prevent
for scan sources.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol, Sequence

from ..data.repository import FindingInput, Repository
from ..data.schema import EpssScore, KevEntry
from ..enums import FeedStatus
from ..scanner.epss_client import EpssRecord
from ..scanner.kev_client import KevRecord

_LOGGER = logging.getLogger(__name__)

KEV_FEED = "kev"
EPSS_FEED = "epss"

# Exceptions that mean "this code is broken", not "this feed is down". Mirrors
# the same list in app.scanner.matcher: laundering a defect into a recorded
# feed outage hides it behind a plausible-looking failure that a user will
# reasonably blame on the network.
_PROGRAMMING_ERRORS = (NameError, TypeError, AttributeError, ImportError)


class _KevSource(Protocol):
    """The subset of :class:`~app.scanner.kev_client.KevHttpClient` used here."""

    def fetch(self) -> list[KevRecord]:
        ...


class _EpssSource(Protocol):
    """The subset of :class:`~app.scanner.epss_client.EpssHttpClient` used here."""

    def fetch(self) -> list[EpssRecord]:
        ...


@dataclass(frozen=True)
class FeedRefreshOutcome:
    """The result of refreshing one feed."""

    feed_name: str
    status: FeedStatus
    record_count: int = 0
    error_detail: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the refresh succeeded."""
        return self.status is FeedStatus.OK


@dataclass(frozen=True)
class FeedHealth:
    """A feed's cache state as the dashboard needs to present it."""

    feed_name: str
    status: FeedStatus
    last_refreshed_at: datetime | None
    last_attempted_at: datetime | None
    record_count: int
    error_detail: str | None
    #: True when the cache is older than the configured maximum age, or has
    #: never been populated. A stale feed still enriches -- with old data --
    #: so this is a warning to surface, not a reason to withhold the signal.
    stale: bool

    @property
    def usable(self) -> bool:
        """Whether this feed holds data that can enrich findings at all.

        A feed that has never successfully refreshed holds nothing, so
        enrichment against it must report "unknown" rather than "absent".
        """
        return self.last_refreshed_at is not None and self.record_count > 0


class FeedRefreshService:
    """Pulls the KEV and EPSS feeds into the local cache.

    Each feed is refreshed independently: a KEV outage must not prevent EPSS
    from updating, since the two are unrelated upstream services and losing
    both because one is down doubles the blast radius of someone else's
    incident.

    The caller owns the transaction, matching the convention in
    :class:`~app.data.repository.Repository`. On failure the cache is left
    exactly as it was -- a failed download never overwrites good data with an
    empty catalogue.
    """

    def __init__(
        self,
        repository: Repository,
        *,
        kev_source: _KevSource | None = None,
        epss_source: _EpssSource | None = None,
    ) -> None:
        self._repository = repository
        self._kev_source = kev_source
        self._epss_source = epss_source

    def refresh_all(self) -> list[FeedRefreshOutcome]:
        """Refresh every configured feed, returning one outcome per feed."""
        outcomes: list[FeedRefreshOutcome] = []
        if self._kev_source is not None:
            outcomes.append(self.refresh_kev())
        if self._epss_source is not None:
            outcomes.append(self.refresh_epss())
        return outcomes

    def refresh_kev(self) -> FeedRefreshOutcome:
        """Download the KEV catalogue and replace the cached copy."""
        if self._kev_source is None:
            return self._record_unconfigured(KEV_FEED)
        try:
            records = self._kev_source.fetch()
        except _PROGRAMMING_ERRORS:
            _LOGGER.exception("KEV refresh failed due to a defect, not an outage")
            raise
        except Exception as exc:
            return self._record_failure(KEV_FEED, exc)

        # An empty catalogue from a 200 response means the feed changed shape
        # under us. Writing it would erase every KEV flag in the fleet, so it
        # is recorded as a failure and the previous cache is kept.
        if not records:
            return self._record_failure(
                KEV_FEED,
                ValueError("KEV feed returned no entries; keeping previous cache"),
            )

        count = self._repository.replace_kev_entries(
            [
                KevEntry(
                    cve_id=record.cve_id,
                    vendor_project=record.vendor_project,
                    product=record.product,
                    vulnerability_name=record.vulnerability_name,
                    date_added=record.date_added,
                    due_date=record.due_date,
                    known_ransomware_use=record.known_ransomware_use,
                    notes=record.notes,
                )
                for record in records
            ]
        )
        self._repository.record_feed_refresh(
            KEV_FEED, status=FeedStatus.OK, record_count=count
        )
        return FeedRefreshOutcome(KEV_FEED, FeedStatus.OK, record_count=count)

    def refresh_epss(self) -> FeedRefreshOutcome:
        """Download the EPSS score set and replace the cached copy."""
        if self._epss_source is None:
            return self._record_unconfigured(EPSS_FEED)
        try:
            records = self._epss_source.fetch()
        except _PROGRAMMING_ERRORS:
            _LOGGER.exception("EPSS refresh failed due to a defect, not an outage")
            raise
        except Exception as exc:
            return self._record_failure(EPSS_FEED, exc)

        if not records:
            return self._record_failure(
                EPSS_FEED,
                ValueError("EPSS feed returned no rows; keeping previous cache"),
            )

        scored_at = datetime.now(timezone.utc)
        count = self._repository.replace_epss_scores(
            [
                EpssScore(
                    cve_id=record.cve_id,
                    score=record.score,
                    percentile=record.percentile,
                    scored_at=scored_at,
                )
                for record in records
            ]
        )
        self._repository.record_feed_refresh(
            EPSS_FEED, status=FeedStatus.OK, record_count=count
        )
        return FeedRefreshOutcome(EPSS_FEED, FeedStatus.OK, record_count=count)

    def _record_failure(self, feed: str, exc: Exception) -> FeedRefreshOutcome:
        """Record a failed refresh, leaving the existing cache untouched."""
        detail = str(exc).strip() or type(exc).__name__
        _LOGGER.warning("%s feed refresh failed: %s", feed, detail)
        self._repository.record_feed_refresh(
            feed, status=FeedStatus.FAILED, error_detail=detail
        )
        return FeedRefreshOutcome(feed, FeedStatus.FAILED, error_detail=detail)

    def _record_unconfigured(self, feed: str) -> FeedRefreshOutcome:
        """Record that a feed has no configured source to pull from."""
        detail = f"{feed} feed is not configured"
        self._repository.record_feed_refresh(
            feed, status=FeedStatus.NEVER_REFRESHED, error_detail=detail
        )
        return FeedRefreshOutcome(
            feed, FeedStatus.NEVER_REFRESHED, error_detail=detail
        )


class FindingEnricher:
    """Attaches cached KEV and EPSS signals to a set of findings.

    Purely local: two indexed lookups against the feed cache, no network. It is
    therefore safe to run inline at the end of every scan without adding a
    failure mode to scanning.

    When a feed has never successfully refreshed, findings are left with
    ``None`` in that feed's fields rather than being marked as absent from it.
    """

    def __init__(self, repository: Repository, *, max_age_hours: float = 48.0) -> None:
        self._repository = repository
        self._max_age_hours = max_age_hours

    def enrich(self, findings: Sequence[FindingInput]) -> list[FindingInput]:
        """Return ``findings`` with KEV and EPSS fields populated where known.

        Args:
            findings: The findings to enrich. Not mutated -- ``FindingInput``
                is frozen, so enriched copies are returned.

        Returns:
            A new list in the same order, each entry enriched from whichever
            feeds hold usable data. Findings are returned unchanged when no
            feed is usable, so a scan still produces results with the
            enrichment fields honestly empty.
        """
        if not findings:
            return []

        kev_health = self.feed_health(KEV_FEED)
        epss_health = self.feed_health(EPSS_FEED)
        if not kev_health.usable and not epss_health.usable:
            return list(findings)

        cve_ids = {f.cve_id.upper() for f in findings if f.cve_id}
        kev_map = self._repository.get_kev_map(cve_ids) if kev_health.usable else {}
        epss_map = self._repository.get_epss_map(cve_ids) if epss_health.usable else {}

        enriched: list[FindingInput] = []
        for finding in findings:
            key = finding.cve_id.upper() if finding.cve_id else ""
            updates: dict[str, object] = {}

            if kev_health.usable:
                kev = kev_map.get(key)
                # False, not None: the catalogue is present and this CVE is not
                # in it, which is a real answer rather than a missing one.
                updates["kev_listed"] = kev is not None
                updates["kev_due_date"] = kev.due_date if kev is not None else None

            if epss_health.usable:
                epss = epss_map.get(key)
                if epss is not None:
                    updates["epss_score"] = epss.score
                    updates["epss_percentile"] = epss.percentile

            enriched.append(replace(finding, **updates) if updates else finding)

        return enriched

    def feed_health(self, feed_name: str) -> FeedHealth:
        """Report one feed's cache state, including whether it is stale."""
        row = self._repository.get_feed_refresh(feed_name)
        if row is None:
            return FeedHealth(
                feed_name=feed_name,
                status=FeedStatus.NEVER_REFRESHED,
                last_refreshed_at=None,
                last_attempted_at=None,
                record_count=0,
                error_detail=None,
                stale=True,
            )
        return FeedHealth(
            feed_name=feed_name,
            status=row.last_status,
            last_refreshed_at=row.last_refreshed_at,
            last_attempted_at=row.last_attempted_at,
            record_count=row.record_count,
            error_detail=row.error_detail,
            stale=self._is_stale(row.last_refreshed_at),
        )

    def all_feed_health(self) -> list[FeedHealth]:
        """Report the state of both intel feeds, in a stable order.

        Both are always reported, including one that has never been attempted,
        so the dashboard can say "KEV has never been fetched" rather than
        omitting the row and implying the signal simply does not exist.
        """
        return [self.feed_health(KEV_FEED), self.feed_health(EPSS_FEED)]

    def _is_stale(self, last_refreshed_at: datetime | None) -> bool:
        """Whether a cache refreshed at ``last_refreshed_at`` is too old."""
        if last_refreshed_at is None:
            return True
        # Rows read back from SQLite carry no timezone; treat a naive timestamp
        # as UTC, which is what record_feed_refresh wrote.
        stamped = last_refreshed_at
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - stamped
        return age > timedelta(hours=self._max_age_hours)


def build_feed_refresh_service(repository: Repository) -> FeedRefreshService:
    """A refresh service wired to the configured upstream feeds.

    One factory rather than three copies of the same construction. It was
    already written out identically in ``api/actions.py`` (the HTTP route) and
    ``auth/cli.py`` (the CLI); the periodic refresher added in 0.8.7 would have
    been a third, and a fourth caller that forgot one source would silently
    refresh only half the intel (Req 10.14).
    """
    from ..config import epss_feed_url, feed_timeout, kev_feed_url
    from ..scanner.epss_client import EpssHttpClient
    from ..scanner.kev_client import KevHttpClient

    timeout = feed_timeout()
    return FeedRefreshService(
        repository,
        kev_source=KevHttpClient(kev_feed_url(), timeout=timeout),
        epss_source=EpssHttpClient(epss_feed_url(), timeout=timeout),
    )
