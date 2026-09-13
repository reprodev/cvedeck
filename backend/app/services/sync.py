"""Synchronization service between the Local_Database and Online_Database.

The Local_Database is the source of truth. Locally written rows carry
``sync_status = PENDING_SYNC`` (Req 5.2); :class:`SyncService` propagates those
pending rows to the Online_Database so the two stores converge (Req 5.4). The
schema is identical on both sides, so synchronization is a direct row
propagation (Req 5.5).

Failure handling (Req 5.3): the Online_Database is modeled as a separate
SQLAlchemy session/engine. If it is unreachable, the entire propagation is
rolled back and the local rows are left ``PENDING_SYNC`` untouched, so a later
:meth:`SyncService.sync` retries them once connectivity returns (Req 5.4). On
success every pending local row becomes ``SYNCED`` and is inserted/updated in
the Online_Database with matching state.

Field preservation (Req 7.3): each syncable row is copied column-for-column,
so a ``CveFinding``'s ``package_identifier`` (Req 7.1) and ``dependency_path_id``
(Req 5.5, 7.2) survive the round trip to the Online_Database unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from ..data.schema import (
    Base,
    CveFinding,
    DependencyPath,
    Inventory,
    Package,
    RemediationRecord,
    TargetMachine,
)
from ..enums import SyncStatus

# Syncable ORM tables in FK-safe propagation order. Parents precede children so
# online inserts never violate foreign-key constraints. ``Package`` has no
# ``sync_status`` of its own; it is propagated together with its parent
# ``Inventory`` (see ``_sync_inventory_packages``).
_SYNC_ORDER: tuple[type[Base], ...] = (
    TargetMachine,
    Inventory,
    DependencyPath,
    CveFinding,
    RemediationRecord,
)


@dataclass
class SyncReport:
    """Outcome of a :meth:`SyncService.sync` run.

    Attributes:
        propagated: Count of rows moved from ``PENDING_SYNC`` to ``SYNCED`` and
            written to the Online_Database, keyed by table name.
        pending: Count of rows still ``PENDING_SYNC`` after the run, keyed by
            table name. Empty on success; equal to the attempted counts when the
            Online_Database was unreachable (Req 5.3).
        online_reachable: ``True`` when propagation committed to the
            Online_Database; ``False`` when it was unreachable and everything
            was retained locally.
    """

    propagated: dict[str, int] = field(default_factory=dict)
    pending: dict[str, int] = field(default_factory=dict)
    online_reachable: bool = True

    @property
    def total_propagated(self) -> int:
        """Total rows propagated across all tables."""
        return sum(self.propagated.values())

    @property
    def total_pending(self) -> int:
        """Total rows still pending across all tables."""
        return sum(self.pending.values())


def _copy_row(source: Base) -> Base:
    """Build a detached copy of an ORM row carrying every mapped column value.

    Copies columns verbatim (including ``package_identifier`` and
    ``dependency_path_id`` on findings, Req 7.3) so the Online_Database row is a
    faithful replica of the local one. Relationships are not traversed; children
    are propagated explicitly in FK-safe order.
    """
    mapper = inspect(type(source))
    values = {col.key: getattr(source, col.key) for col in mapper.column_attrs}
    return type(source)(**values)


class SyncService:
    """Propagate ``PENDING_SYNC`` rows from the Local_Database to the online one.

    The service holds a local :class:`~sqlalchemy.orm.Session` (the source of
    truth) and a factory that produces an online :class:`~sqlalchemy.orm.Session`.
    The factory is only invoked inside :meth:`sync`, so an unreachable online
    store surfaces as an exception there and leaves local state untouched.
    """

    def __init__(
        self,
        local_session: Session,
        online_session_factory,
    ) -> None:
        """Create a sync service.

        Args:
            local_session: Session bound to the Local_Database (source of truth).
            online_session_factory: Zero-argument callable returning a
                :class:`~sqlalchemy.orm.Session` bound to the Online_Database.
                It may raise (e.g. on connect) to simulate/represent an
                unreachable Online_Database.
        """
        self._local = local_session
        self._online_session_factory = online_session_factory

    def enqueue(self, entity: Base) -> None:
        """Mark a syncable entity ``PENDING_SYNC`` in the Local_Database (Req 5.2).

        The entity must already belong to (or be addable to) the local session.
        Marking is a no-op flag flip; the row is actually propagated on the next
        :meth:`sync`.
        """
        if entity not in self._local:
            self._local.add(entity)
        entity.sync_status = SyncStatus.PENDING_SYNC
        self._local.flush()

    def sync(self) -> SyncReport:
        """Propagate all ``PENDING_SYNC`` rows to the Online_Database.

        Reads every pending row per table (FK-safe order), then opens an online
        session and upserts each row with ``SYNCED`` status. On success the
        online transaction commits, local rows are flipped to ``SYNCED``, and the
        local transaction commits so the two stores converge (Req 5.4).

        If the Online_Database is unreachable at any point, the online work is
        rolled back, local rows are left ``PENDING_SYNC``, and the returned report
        marks ``online_reachable = False`` (Req 5.3). A subsequent call retries
        the still-pending rows.
        """
        pending: dict[type[Base], list[Base]] = {}
        for model in _SYNC_ORDER:
            rows = list(
                self._local.execute(
                    select(model).where(model.sync_status == SyncStatus.PENDING_SYNC)
                )
                .scalars()
                .all()
            )
            pending[model] = rows

        attempted = {
            model.__tablename__: len(rows)
            for model, rows in pending.items()
            if rows
        }

        try:
            online = self._online_session_factory()
        except Exception:
            # Online DB unreachable before we could even open a session.
            return SyncReport(
                propagated={},
                pending=dict(attempted),
                online_reachable=False,
            )

        try:
            with online:
                for model in _SYNC_ORDER:
                    for row in pending[model]:
                        self._upsert_online(online, row)
                        if model is Inventory:
                            self._sync_inventory_packages(online, row)
                online.commit()
        except Exception:
            # Any failure reaching/writing the online DB: retain locally.
            return SyncReport(
                propagated={},
                pending=dict(attempted),
                online_reachable=False,
            )

        # Online converged; flip local rows to SYNCED and commit locally.
        for model in _SYNC_ORDER:
            for row in pending[model]:
                row.sync_status = SyncStatus.SYNCED
        self._local.commit()

        return SyncReport(
            propagated=dict(attempted),
            pending={},
            online_reachable=True,
        )

    @staticmethod
    def _upsert_online(online: Session, local_row: Base) -> None:
        """Insert or update ``local_row`` in the Online_Database as ``SYNCED``.

        Copies all columns (preserving field associations, Req 7.3). If a row
        with the same primary key already exists online it is updated in place;
        otherwise a fresh copy is added.
        """
        model = type(local_row)
        pk = inspect(local_row).identity_key[1]
        existing = online.get(model, pk[0] if len(pk) == 1 else pk)
        mapper = inspect(model)
        if existing is None:
            copy = _copy_row(local_row)
            copy.sync_status = SyncStatus.SYNCED
            online.add(copy)
        else:
            for col in mapper.column_attrs:
                setattr(existing, col.key, getattr(local_row, col.key))
            existing.sync_status = SyncStatus.SYNCED
        online.flush()

    @staticmethod
    def _sync_inventory_packages(online: Session, local_inventory: Inventory) -> None:
        """Propagate an inventory's child ``Package`` rows to the online store.

        ``Package`` has no ``sync_status`` of its own, so its rows ride along with
        their parent ``Inventory``. Existing online packages for the inventory are
        replaced to mirror the local set exactly.
        """
        online.execute(
            Package.__table__.delete().where(
                Package.inventory_id == local_inventory.id
            )
        )
        for pkg in local_inventory.packages:
            online.add(
                Package(
                    id=pkg.id,
                    inventory_id=pkg.inventory_id,
                    name=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                )
            )
        online.flush()
