"""Property-based tests for the ScannerEngine's per-target fault isolation.

Feature: cvedeck
Property 1: Per-target fault isolation
Validates: Requirements 1.4, 1.5

For any batch of target machines where each target is assigned a random outcome
(reachable, unreachable, or auth-failure), scanning the batch records
CONNECTION_FAILURE for every unreachable target, AUTH_FAILURE for every
auth-failing target, and still produces a completed scan result for every
reachable target.

The engine selects a collector per target via ``collector_factory(platform)``,
so the fake factory hands out a per-target fake keyed by the target id. Each
fake either returns a canned inventory (reachable), raises the built-in
``ConnectionError`` (unreachable), or raises ``AuthError`` (auth-failure). A
fake matcher and fake repository stand in for the data sources and database so
no real host, source, or DB is touched.
"""

from __future__ import annotations

from enum import Enum

from hypothesis import given, strategies as st
from pydantic import SecretStr

from app.data.repository import FindingInput
from app.enums import Platform, ScanStatus, SourceStatus
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.engine import ScannerEngine
from app.scanner.exceptions import AuthError
from app.scanner.matcher import MatchResult


class Outcome(str, Enum):
    """The outcome randomly assigned to a target for a scan."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    AUTH_FAILURE = "auth_failure"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeCollector:
    """Collector that returns a canned inventory or raises a canned error."""

    def __init__(
        self,
        inventory: Inventory | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self._inventory = inventory
        self._error = error

    def collect(
        self, target: TargetMachine, credentials: Credentials
    ) -> Inventory:
        if self._error is not None:
            raise self._error
        assert self._inventory is not None
        return self._inventory


class FakeMatcher:
    """Matcher that returns an empty match result for any inventory."""

    def match(self, inventory, nvd, osv) -> MatchResult:
        return MatchResult(
            machine_id=inventory.machine_id,
            findings=[],
            nvd_status=SourceStatus.OK,
            osv_status=SourceStatus.OK,
        )


class FakeRepository:
    """Records inventory and finding writes without a database."""

    def __init__(self) -> None:
        self.saved_inventories: list[Inventory] = []
        self.saved_findings: dict[str, list[FindingInput]] = {}

    def save_inventory(self, inventory: Inventory):
        self.saved_inventories.append(inventory)
        return inventory

    def save_findings(self, machine_id: str, findings: list[FindingInput]):
        self.saved_findings.setdefault(machine_id, []).extend(findings)
        return findings


def _creds(_target: TargetMachine) -> Credentials:
    return Credentials(username="admin", password=SecretStr("secret"))


def _inventory(machine_id: str) -> Inventory:
    return Inventory(
        machine_id=machine_id,
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[Package(name="openssl", version="3.0.2", ecosystem="deb")],
    )


def _collector_for(outcome: Outcome, machine_id: str) -> FakeCollector:
    """Build the per-target fake collector for its assigned outcome."""
    if outcome is Outcome.UNREACHABLE:
        return FakeCollector(error=ConnectionError("host unreachable"))
    if outcome is Outcome.AUTH_FAILURE:
        return FakeCollector(error=AuthError("bad credentials"))
    return FakeCollector(inventory=_inventory(machine_id))


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
_platforms = st.sampled_from(list(Platform))
_outcomes = st.sampled_from(list(Outcome))


@st.composite
def _target_batches(draw):
    """A batch of targets, each with a distinct id and a random outcome.

    Returns a list of ``(TargetMachine, Outcome)`` pairs. Ids are made unique
    per batch so a per-target collector can be keyed by id.
    """
    size = draw(st.integers(min_value=0, max_value=8))
    batch: list[tuple[TargetMachine, Outcome]] = []
    for index in range(size):
        machine_id = f"m-{index}"
        target = TargetMachine(
            id=machine_id,
            hostname=f"host-{index}",
            platform=draw(_platforms),
        )
        batch.append((target, draw(_outcomes)))
    return batch


# --------------------------------------------------------------------------- #
# Property 1: Per-target fault isolation
# --------------------------------------------------------------------------- #
@given(batch=_target_batches())
def test_property_1_per_target_fault_isolation(batch):
    """Property 1 (Requirements 1.4, 1.5).

    Every unreachable target is recorded as CONNECTION_FAILURE, every
    auth-failing target as AUTH_FAILURE, and every reachable target produces a
    completed (SUCCESS) scan result. A failure never aborts the batch, so the
    engine returns exactly one outcome per input target.
    """
    outcome_by_id = {target.id: outcome for target, outcome in batch}
    collectors = {
        target.id: _collector_for(outcome, target.id)
        for target, outcome in batch
    }

    repo = FakeRepository()
    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher(),
        # The engine calls the factory once per target, in scan order, so pop
        # the collector for the corresponding target id.
        collector_factory=_make_ordered_factory(
            [target.id for target, _ in batch], collectors
        ),
    )

    result = engine.scan([target for target, _ in batch])

    # Fault isolation: exactly one outcome per input target, none dropped.
    assert len(result.machine_scans) == len(batch)
    assert [scan.machine_id for scan in result.machine_scans] == [
        target.id for target, _ in batch
    ]

    expected_status = {
        Outcome.UNREACHABLE: ScanStatus.CONNECTION_FAILURE,
        Outcome.AUTH_FAILURE: ScanStatus.AUTH_FAILURE,
        Outcome.REACHABLE: ScanStatus.SUCCESS,
    }

    for scan in result.machine_scans:
        outcome = outcome_by_id[scan.machine_id]
        assert scan.status is expected_status[outcome]

        if outcome is Outcome.REACHABLE:
            # A completed scan result carries its inventory and match result.
            assert scan.inventory is not None
            assert scan.match_result is not None
            assert scan.error is None
        elif outcome is Outcome.UNREACHABLE:
            # Connection failure recorded, batch not aborted (Req 1.4).
            assert isinstance(scan.error, ConnectionError)
            assert scan.inventory is None
        else:  # AUTH_FAILURE
            # Auth failure recorded, batch not aborted (Req 1.5).
            assert isinstance(scan.error, AuthError)
            assert scan.inventory is None

    # by_status aggregates match the assigned outcomes.
    reachable_ids = {mid for mid, o in outcome_by_id.items() if o is Outcome.REACHABLE}
    unreachable_ids = {mid for mid, o in outcome_by_id.items() if o is Outcome.UNREACHABLE}
    auth_ids = {mid for mid, o in outcome_by_id.items() if o is Outcome.AUTH_FAILURE}

    assert {s.machine_id for s in result.by_status(ScanStatus.SUCCESS)} == reachable_ids
    assert {
        s.machine_id for s in result.by_status(ScanStatus.CONNECTION_FAILURE)
    } == unreachable_ids
    assert {
        s.machine_id for s in result.by_status(ScanStatus.AUTH_FAILURE)
    } == auth_ids

    # Only reachable targets had their inventory persisted (Req 1.6 side-effect).
    assert {inv.machine_id for inv in repo.saved_inventories} == reachable_ids


def _make_ordered_factory(order, collectors):
    """Return a collector_factory yielding the per-target fake in scan order.

    The engine invokes ``collector_factory(platform)`` once per target in the
    order targets are scanned; this closure walks that order and returns the
    collector keyed by the corresponding target id.
    """
    state = {"index": 0}

    def factory(_platform):
        machine_id = order[state["index"]]
        state["index"] += 1
        return collectors[machine_id]

    return factory
