"""Periodic refresh of the cached threat-intel feeds (Req 10.14).

Until 0.8.7 the only way to refresh the KEV catalogue and the EPSS score set was
an operator's own cron calling ``POST /api/feeds/refresh`` or
``cvedeck-admin refresh-feeds``. DEPLOYMENT.md said so, and a deployment whose
owner never read that far ran on a cache that aged silently. Every day of ageing
under-reports exploitation, which is the one signal the whole ranking is built
on -- and unlike a failed scan, nothing about it looks wrong: the dashboard
renders a confident "0 actively exploited" from a catalogue nobody fetched.

This is deliberately the smallest thing that removes that trap: one task, no
job table, no worker pool. The refresh is already idempotent, already owns no
transaction, and already leaves the previous cache intact when a download fails,
so there is nothing to coordinate and nothing to recover.

Not a general scheduler. When scans move off the request thread (0.9.0) they
need a job model, a queue and progress reporting; a feed refresh needs none of
those, and building the general thing first would have delayed the honest fix.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Protocol

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..data.repository import Repository
from .enrichment import build_feed_refresh_service

_LOGGER = logging.getLogger(__name__)

_SECONDS_PER_HOUR = 3600.0


class _Sleeper(Protocol):
    def __call__(self, delay: float) -> Awaitable[None]: ...


def refresh_feeds_once(engine: Engine) -> list[str]:
    """Refresh both feeds in their own session, returning one line per feed.

    Synchronous and blocking on purpose: it is the same call the HTTP route and
    the CLI make. The caller is responsible for keeping it off the event loop.

    Opens its own session rather than taking one, because there is no request to
    borrow a session from -- ``Depends(get_session)`` has no meaning here.
    """
    with Session(engine) as session:
        outcomes = build_feed_refresh_service(Repository(session)).refresh_all()
        session.commit()
    return [
        f"{o.feed_name}: {o.status}, {o.record_count} records"
        + (f" ({o.error_detail})" if o.error_detail else "")
        for o in outcomes
    ]


async def run_periodic_refresh(
    interval_hours: float,
    *,
    refresh: Callable[[], list[str]],
    sleep: _Sleeper | None = None,
    iterations: int | None = None,
) -> None:
    """Refresh now, then every ``interval_hours``, until cancelled.

    Refreshes immediately rather than waiting out the first interval: a
    container that has been down for a week would otherwise serve a week-old
    catalogue until tomorrow, which is the failure this exists to prevent.

    The refresh runs in a worker thread. It is synchronous httpx over a
    multi-megabyte download, and awaiting it on the event loop would freeze
    every request for the duration.

    A failure is logged and the loop continues. ``refresh_all`` already keeps the
    previous cache on a failed download, so a transient outage costs nothing but
    a log line -- and a refresh that collides with a user-triggered one, or with
    SQLite's single writer, degrades the same way rather than needing a lock
    this process could not enforce across others anyway.

    Args:
        interval_hours: Hours between refreshes. Must be positive; the caller
            decides not to start the task at all when it is zero.
        refresh: The blocking refresh to run, injected for testing.
        sleep: Awaitable sleep, injected for testing. Defaults to
            ``asyncio.sleep``.
        iterations: Stop after this many cycles. For tests only; ``None`` runs
            until cancelled, which is what production does.
    """
    if interval_hours <= 0:
        raise ValueError(f"interval_hours must be positive, got {interval_hours}")

    delay = interval_hours * _SECONDS_PER_HOUR
    nap = sleep if sleep is not None else asyncio.sleep
    completed = 0

    while iterations is None or completed < iterations:
        try:
            for line in await asyncio.to_thread(refresh):
                _LOGGER.info("Periodic feed refresh -- %s", line)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let one bad cycle end the loop: the next one may succeed,
            # and the cache it would have replaced is still the good one.
            _LOGGER.exception("Periodic feed refresh failed; keeping the cache")
        completed += 1
        if iterations is not None and completed >= iterations:
            break
        await nap(delay)


def start_periodic_refresh(
    engine: Engine, interval_hours: float
) -> asyncio.Task | None:
    """Start the refresher, or return ``None`` when it is switched off."""
    if interval_hours <= 0:
        _LOGGER.info(
            "Periodic feed refresh is disabled; refresh with "
            "'cvedeck-admin refresh-feeds' or POST /api/feeds/refresh"
        )
        return None
    _LOGGER.info("Refreshing threat-intel feeds every %s hour(s)", interval_hours)
    return asyncio.create_task(
        run_periodic_refresh(
            interval_hours, refresh=lambda: refresh_feeds_once(engine)
        )
    )


async def stop_periodic_refresh(task: asyncio.Task | None) -> None:
    """Cancel the refresher and wait for it to actually stop.

    Awaited rather than fired and forgotten: a task cancelled but not awaited
    can still be mid-write when the process exits, and the CancelledError it
    raises on the way out would surface as an "exception was never retrieved"
    warning on shutdown.
    """
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
