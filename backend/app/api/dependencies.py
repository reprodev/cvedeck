"""Database wiring and FastAPI dependencies for the Backend_API.

The API reads from the Local_Database through a per-request SQLAlchemy
:class:`~sqlalchemy.orm.Session`. :func:`get_session` is the FastAPI dependency
that yields a session for the lifetime of a request and closes it afterwards.

By default the session is backed by a process-wide engine created from the
``CVEDECK_DB_URL`` environment variable (falling back to a local SQLite
file). Tests override the ``get_session`` dependency on the app to inject an
in-memory SQLite session instead, so no real database is required.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from .. import config
from ..data.migrations_runtime import upgrade_to_head

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine for the Local_Database.

    The URL is resolved by :func:`app.config.database_url` -- a SQLite file
    under the configured data directory unless ``CVEDECK_DB_URL`` overrides
    it. The engine is created once and reused across requests. The schema is
    brought to head on first use (see :mod:`app.data.migrations_runtime`), so a
    fresh database is usable immediately and an existing one is migrated.
    """
    url = config.database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        # A mounted volume may be empty on first boot; make sure the directory
        # the SQLite file lives in exists before SQLAlchemy opens it.
        config.data_dir().mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args=connect_args)
    upgrade_to_head(engine)
    _seed_demo_if_requested(engine)
    return engine


def _seed_demo_if_requested(engine: Engine) -> None:
    """Populate a demo fleet, when demo mode is on and the fleet is empty.

    Guarded on emptiness rather than on a marker row, so restarting a demo
    container does not accumulate duplicate fleets, and so pointing demo mode
    at a database that already holds real scan results is a no-op instead of a
    surprise (Req 15.1, 15.2).

    A failure here must not stop the API coming up: the consequence of an
    unseeded demo is an empty dashboard, which is strictly better than a
    dashboard that will not load at all.
    """
    if not config.demo_mode():
        return

    from ..data.demo_seed import fleet_is_empty, seed_demo_fleet

    try:
        with Session(engine) as session:
            if not fleet_is_empty(session):
                return
            count = seed_demo_fleet(session)
            session.commit()
        logger.info("Demo mode: seeded %d machines.", count)
    except Exception:
        logger.exception("Demo mode: seeding failed; starting with an empty fleet.")


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session.

    Override this on the app (``app.dependency_overrides[get_session] = ...``)
    to inject a test session backed by an in-memory database.
    """
    with Session(get_engine()) as session:
        yield session


def get_scanner_engine():
    """FastAPI dependency providing the :class:`ScannerEngine` for scans.

    The default implementation is intentionally unconfigured: a real scan
    requires collectors that reach live SSH/WinRM hosts, which cannot be wired
    up generically here. Deployments (and tests) override this on the app
    (``app.dependency_overrides[get_scanner_engine] = ...``) to inject a
    concrete engine — tests supply one with stubbed collectors so no real host
    is contacted.
    """
    raise NotImplementedError(
        "No ScannerEngine configured. Override get_scanner_engine on the app "
        "to provide an engine wired to collectors and data-source clients."
    )


def get_sync_service():
    """FastAPI dependency providing the :class:`SyncService` for sync runs.

    The default implementation is intentionally unconfigured: synchronization
    needs an Online_Database session factory that is environment specific.
    Deployments (and tests) override this on the app
    (``app.dependency_overrides[get_sync_service] = ...``) to inject a concrete
    service — tests supply one backed by an in-memory online store so no online
    database is contacted.
    """
    raise NotImplementedError(
        "No SyncService configured. Override get_sync_service on the app to "
        "provide a service wired to a local session and an online session "
        "factory."
    )
