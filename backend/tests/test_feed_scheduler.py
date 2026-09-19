"""Tests for the periodic intel-feed refresher (Req 10.14).

No test here sleeps. The loop takes its sleep as an argument precisely so the
suite can assert the schedule without waiting for it -- a test that really slept
24 hours would never run, and one that slept a "short" interval would be a slow
test that proves less.

Each test drives its own event loop with ``asyncio.run`` rather than depending
on pytest-asyncio: six tests are not worth a new test dependency in a project
that pins and audits everything it installs.
"""

from __future__ import annotations

import asyncio
import logging
import threading

import pytest

from app import config
from app.services import feed_scheduler
from app.services.feed_scheduler import (
    refresh_feeds_once,
    run_periodic_refresh,
    start_periodic_refresh,
    stop_periodic_refresh,
)


class _RecordingSleep:
    """An awaitable sleep that records its delays instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def test_refreshes_immediately_then_on_the_interval():
    """The first refresh does not wait out an interval.

    A container that has been down a week would otherwise serve a week-old
    catalogue until tomorrow.
    """
    calls: list[int] = []
    sleep = _RecordingSleep()

    asyncio.run(
        run_periodic_refresh(
            6.0,
            refresh=lambda: (calls.append(1), ["kev: ok, 1 records"])[1],
            sleep=sleep,
            iterations=3,
        )
    )

    assert len(calls) == 3
    # Two sleeps for three refreshes: the first is immediate, and the loop does
    # not sleep after the final one.
    assert sleep.delays == [6 * 3600.0, 6 * 3600.0]


def test_a_failed_refresh_does_not_end_the_loop(caplog):
    """One bad cycle must not stop the next.

    ``refresh_all`` keeps the previous cache when a download fails, so a
    transient outage should cost a log line and nothing else.
    """
    attempts: list[int] = []

    def flaky() -> list[str]:
        attempts.append(len(attempts))
        if len(attempts) == 1:
            raise RuntimeError("KEV upstream is down")
        return ["kev: ok, 1200 records"]

    with caplog.at_level(logging.ERROR):
        asyncio.run(
            run_periodic_refresh(
                1.0, refresh=flaky, sleep=_RecordingSleep(), iterations=2
            )
        )

    assert len(attempts) == 2, "the loop stopped after the failure"
    assert "keeping the cache" in caplog.text


def test_the_refresh_does_not_run_on_the_event_loop():
    """A multi-megabyte synchronous download must not block the loop.

    ``refresh_all`` is blocking httpx over the whole EPSS score set; awaiting it
    inline would freeze every request for the duration. Asserted by observing
    which thread it runs on, because that is the actual requirement.
    """
    seen: list[int] = []

    async def drive() -> int:
        await run_periodic_refresh(
            1.0,
            refresh=lambda: (seen.append(threading.get_ident()), [])[1],
            sleep=_RecordingSleep(),
            iterations=1,
        )
        return threading.get_ident()

    loop_thread = asyncio.run(drive())

    assert seen and seen[0] != loop_thread


def test_cancellation_stops_the_loop_promptly():
    async def drive() -> asyncio.Task:
        started = asyncio.Event()

        async def forever(_delay: float) -> None:
            started.set()
            await asyncio.sleep(3600)

        task = asyncio.create_task(
            run_periodic_refresh(1.0, refresh=lambda: [], sleep=forever)
        )
        await asyncio.wait_for(started.wait(), timeout=5)
        await stop_periodic_refresh(task)
        return task

    task = asyncio.run(drive())

    assert task.done()


def test_a_zero_interval_starts_nothing(caplog):
    """Disabled means no task, and says so rather than failing quietly."""
    with caplog.at_level(logging.INFO):
        assert start_periodic_refresh(object(), 0) is None
    assert "disabled" in caplog.text
    # Stopping a refresher that was never started is safe.
    asyncio.run(stop_periodic_refresh(None))


def test_a_negative_interval_is_rejected_rather_than_looping_hot():
    with pytest.raises(ValueError, match="must be positive"):
        asyncio.run(
            run_periodic_refresh(
                -1.0, refresh=lambda: [], sleep=_RecordingSleep()
            )
        )


def test_refresh_feeds_once_uses_its_own_session(monkeypatch):
    """It cannot borrow a request session, so it must open one and commit."""
    from sqlalchemy import create_engine

    from app.data.schema import Base
    from app.enums import FeedStatus
    from app.services.enrichment import FeedRefreshOutcome

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    class _Service:
        def refresh_all(self):
            return [FeedRefreshOutcome("kev", FeedStatus.OK, record_count=7)]

    monkeypatch.setattr(
        feed_scheduler, "build_feed_refresh_service", lambda repo: _Service()
    )

    lines = refresh_feeds_once(engine)

    assert len(lines) == 1
    assert lines[0].startswith("kev: ")
    assert "7 records" in lines[0]


def test_the_default_interval_is_on_and_daily(monkeypatch):
    """Default on, because off-by-default was the silent-staleness trap."""
    monkeypatch.delenv("CVEDECK_FEED_REFRESH_HOURS", raising=False)
    assert config.feed_refresh_hours() == 24.0

    monkeypatch.setenv("CVEDECK_FEED_REFRESH_HOURS", "0")
    assert config.feed_refresh_hours() == 0.0

    monkeypatch.setenv("CVEDECK_FEED_REFRESH_HOURS", "-3")
    with pytest.raises(ValueError, match="must not be negative"):
        config.feed_refresh_hours()

    monkeypatch.setenv("CVEDECK_FEED_REFRESH_HOURS", "nonsense")
    with pytest.raises(ValueError, match="must be a float"):
        config.feed_refresh_hours()
