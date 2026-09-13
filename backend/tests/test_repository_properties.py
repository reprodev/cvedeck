"""Property-based tests for the persistence-layer repository (task 3.3).

Feature: cvedeck
Property 2: Inventory persistence round-trip
Validates: Requirements 1.6, 5.1

For any collected inventory for a machine, persisting it to the Local_Database
and then reading it back yields an inventory equivalent to the one persisted.
"""

from collections import Counter
from datetime import datetime, timezone

import pytest
from hypothesis import given, strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import Base, TargetMachine
from app.enums import Platform, ScanStatus, SyncStatus
from app.models import Inventory as DomainInventory
from app.models import OsInfo
from app.models import Package as DomainPackage


# --------------------------------------------------------------------------- #
# Hypothesis strategies
# --------------------------------------------------------------------------- #
# Non-empty text so required string columns (os_name/os_version, package
# name/version) carry meaningful, distinguishable values.
_names = st.text(min_size=1, max_size=40)

_packages = st.builds(
    DomainPackage,
    name=_names,
    version=_names,
    # ecosystem is optional (nullable column); exercise both present and absent.
    ecosystem=st.one_of(st.none(), _names),
)


@st.composite
def _inventories(draw):
    """Generate an arbitrary domain Inventory with a fixed machine id.

    ``collected_at`` is drawn as a UTC-aware datetime so the round-trip
    comparison is deterministic (the repository would otherwise default a
    missing timestamp to ``now()``).
    """
    dt = draw(
        st.datetimes(
            min_value=datetime(2000, 1, 1),
            max_value=datetime(2100, 1, 1),
        )
    )
    return DomainInventory(
        machine_id="m1",
        os_info=OsInfo(name=draw(_names), version=draw(_names)),
        packages=draw(st.lists(_packages, max_size=8)),
        collected_at=dt.replace(tzinfo=timezone.utc),
    )


def _package_multiset(inventory: DomainInventory) -> Counter:
    """Order-independent representation of an inventory's packages."""
    return Counter(
        (p.name, p.version, p.ecosystem) for p in inventory.packages
    )


# --------------------------------------------------------------------------- #
# Property 2: Inventory persistence round-trip
# --------------------------------------------------------------------------- #
@given(inventory=_inventories())
def test_property_2_inventory_persistence_round_trip(inventory):
    """Property 2 (Requirements 1.6, 5.1): persisting an inventory and reading
    it back yields an equivalent inventory.

    A fresh in-memory SQLite engine and a machine row are created per example so
    each case is isolated.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            session.add(
                TargetMachine(
                    id="m1",
                    hostname="host.example.com",
                    platform=Platform.LINUX,
                    last_scan_status=ScanStatus.SUCCESS,
                    last_scanned_at=None,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
            session.flush()

            repo = Repository(session)
            row = repo.save_inventory(inventory)
            session.commit()

            loaded = repo.get_inventory(row.id)

            assert loaded is not None
            assert loaded.machine_id == inventory.machine_id
            assert loaded.os_info == inventory.os_info
            # SQLite persists naive datetimes; compare the same wall-clock instant.
            assert (
                loaded.collected_at.replace(tzinfo=timezone.utc)
                == inventory.collected_at
            )
            # Package order is not guaranteed; compare as a multiset.
            assert _package_multiset(loaded) == _package_multiset(inventory)

            # The latest-for-machine read path must agree with the round-trip.
            latest = repo.get_latest_inventory_for_machine("m1")
            assert latest is not None
            assert latest.os_info == inventory.os_info
            assert _package_multiset(latest) == _package_multiset(inventory)
    finally:
        engine.dispose()
