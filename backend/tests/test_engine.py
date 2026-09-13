"""Unit tests for the ScannerEngine (task 5.3).

These verify the engine's per-target fault isolation and success path using
fake collectors, a fake matcher, and a fake repository so no real host, data
source, or database is touched:

- a target whose collector raises ``ConnectionError`` is recorded as
  ``CONNECTION_FAILURE`` and does not abort the batch (Req 1.4),
- a target whose collector raises ``AuthError`` is recorded as
  ``AUTH_FAILURE`` and does not abort the batch (Req 1.5), and
- a successful target has its inventory persisted (Req 1.6) and its matched
  findings persisted (Req 2.3).
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import SecretStr

from app.data.repository import FindingInput
from app.enums import Platform, ScanStatus, Severity, SourceStatus
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.engine import ScannerEngine
from app.scanner.exceptions import AuthError
from app.scanner.matcher import Finding, MatchResult


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
        self.calls: list[TargetMachine] = []

    def collect(
        self, target: TargetMachine, credentials: Credentials
    ) -> Inventory:
        self.calls.append(target)
        if self._error is not None:
            raise self._error
        assert self._inventory is not None
        return self._inventory


class FakeMatcher:
    """Matcher that returns canned findings for whatever inventory it is given."""

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings
        self.calls: list[Inventory] = []

    def match(self, inventory, nvd, osv) -> MatchResult:
        self.calls.append(inventory)
        return MatchResult(
            machine_id=inventory.machine_id,
            findings=[f for f in self._findings if f.machine_id == inventory.machine_id],
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


def _finding(machine_id: str, cve_id: str) -> Finding:
    return Finding(
        machine_id=machine_id,
        cve_id=cve_id,
        cvss_score=9.1,
        severity=Severity.CRITICAL,
        source="osv",
        package_identifier="deb:openssl",
    )


# --------------------------------------------------------------------------- #
# Collector selection
# --------------------------------------------------------------------------- #
def test_selects_collector_by_platform():
    seen: list[Platform] = []
    linux_collector = FakeCollector(inventory=_inventory("m-linux"))
    windows_collector = FakeCollector(inventory=_inventory("m-win"))

    def factory(platform: Platform):
        seen.append(platform)
        return linux_collector if platform is Platform.LINUX else windows_collector

    engine = ScannerEngine(
        repository=FakeRepository(),
        credentials_for=_creds,
        matcher=FakeMatcher([]),
        collector_factory=factory,
    )
    engine.scan(
        [
            TargetMachine(id="m-linux", hostname="a", platform=Platform.LINUX),
            TargetMachine(id="m-win", hostname="b", platform=Platform.WINDOWS),
        ]
    )

    assert seen == [Platform.LINUX, Platform.WINDOWS]


# --------------------------------------------------------------------------- #
# Success path
# --------------------------------------------------------------------------- #
def test_success_collects_persists_matches_and_persists_findings():
    repo = FakeRepository()
    inv = _inventory("m1")
    matcher = FakeMatcher([_finding("m1", "CVE-2024-0001")])
    statuses: list[tuple[str, ScanStatus]] = []

    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=matcher,
        collector_factory=lambda platform: FakeCollector(inventory=inv),
        record_status=lambda t, scan: statuses.append((t.id, scan.status)),
    )
    target = TargetMachine(id="m1", hostname="host", platform=Platform.LINUX)
    result = engine.scan([target])

    scan = result.machine_scans[0]
    assert scan.status is ScanStatus.SUCCESS
    # Inventory persisted (Req 1.6).
    assert repo.saved_inventories == [inv]
    # Matcher ran against the collected inventory.
    assert matcher.calls == [inv]
    # Findings persisted for the machine, mapped to FindingInput (Req 2.3).
    saved = repo.saved_findings["m1"]
    assert len(saved) == 1
    assert isinstance(saved[0], FindingInput)
    assert saved[0].cve_id == "CVE-2024-0001"
    assert saved[0].severity is Severity.CRITICAL
    assert saved[0].package_identifier == "deb:openssl"
    # Status recorded.
    assert statuses == [("m1", ScanStatus.SUCCESS)]
    # Findings surfaced on the outcome.
    assert [f.cve_id for f in scan.findings] == ["CVE-2024-0001"]


def test_success_with_no_findings_persists_empty_list():
    repo = FakeRepository()
    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher([]),
        collector_factory=lambda platform: FakeCollector(inventory=_inventory("m1")),
    )
    target = TargetMachine(id="m1", hostname="host", platform=Platform.LINUX)
    result = engine.scan([target])

    assert result.machine_scans[0].status is ScanStatus.SUCCESS
    assert repo.saved_findings.get("m1", []) == []


# --------------------------------------------------------------------------- #
# Per-target fault isolation
# --------------------------------------------------------------------------- #
def test_connection_error_records_connection_failure(caplog):
    engine = ScannerEngine(
        repository=FakeRepository(),
        credentials_for=_creds,
        matcher=FakeMatcher([]),
        collector_factory=lambda platform: FakeCollector(
            error=ConnectionError("host down")
        ),
    )
    target = TargetMachine(id="m1", hostname="host", platform=Platform.LINUX)
    result = engine.scan([target])

    scan = result.machine_scans[0]
    assert scan.status is ScanStatus.CONNECTION_FAILURE
    assert isinstance(scan.error, ConnectionError)
    assert scan.inventory is None


def test_auth_error_records_auth_failure():
    engine = ScannerEngine(
        repository=FakeRepository(),
        credentials_for=_creds,
        matcher=FakeMatcher([]),
        collector_factory=lambda platform: FakeCollector(
            error=AuthError("bad password")
        ),
    )
    target = TargetMachine(id="m1", hostname="host", platform=Platform.LINUX)
    result = engine.scan([target])

    scan = result.machine_scans[0]
    assert scan.status is ScanStatus.AUTH_FAILURE
    assert isinstance(scan.error, AuthError)


def test_failure_never_aborts_the_batch():
    repo = FakeRepository()
    ok_inv = _inventory("ok")

    # The engine selects a collector by platform, so hand out a per-target
    # collector in scan order to drive each target's outcome independently.
    collectors = {
        "conn": FakeCollector(error=ConnectionError("down")),
        "auth": FakeCollector(error=AuthError("nope")),
        "ok": FakeCollector(inventory=ok_inv),
    }
    order = ["conn", "auth", "ok"]
    idx = {"i": 0}

    def ordered_factory(platform: Platform):
        key = order[idx["i"]]
        idx["i"] += 1
        return collectors[key]

    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher([_finding("ok", "CVE-9")]),
        collector_factory=ordered_factory,
    )
    targets = [
        TargetMachine(id="conn", hostname="h1", platform=Platform.LINUX),
        TargetMachine(id="auth", hostname="h2", platform=Platform.LINUX),
        TargetMachine(id="ok", hostname="h3", platform=Platform.LINUX),
    ]
    result = engine.scan(targets)

    statuses = {s.machine_id: s.status for s in result.machine_scans}
    assert statuses == {
        "conn": ScanStatus.CONNECTION_FAILURE,
        "auth": ScanStatus.AUTH_FAILURE,
        "ok": ScanStatus.SUCCESS,
    }
    # The reachable target was still fully processed despite earlier failures.
    assert repo.saved_inventories == [ok_inv]
    assert [f.cve_id for f in repo.saved_findings["ok"]] == ["CVE-9"]
    # by_status helper reflects the aggregate outcome.
    assert len(result.by_status(ScanStatus.SUCCESS)) == 1
    assert len(result.by_status(ScanStatus.CONNECTION_FAILURE)) == 1
    assert len(result.by_status(ScanStatus.AUTH_FAILURE)) == 1


# --------------------------------------------------------------------------- #
# Threat-intel enrichment
# --------------------------------------------------------------------------- #
class FakeEnricher:
    """Stamps a KEV flag onto every finding it is given."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self._error = error
        self.calls: list[list[FindingInput]] = []

    def enrich(self, findings):
        self.calls.append(list(findings))
        if self._error is not None:
            raise self._error
        return [replace(f, kev_listed=True, epss_score=0.5) for f in findings]


def test_findings_are_enriched_before_they_are_persisted():
    """Enrichment must reach the database, not just the response.

    Findings are read back from storage by every dashboard view, so an
    enrichment that only decorated the in-memory result would be invisible
    everywhere it matters.
    """
    repo = FakeRepository()
    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher([_finding("m1", "CVE-1")]),
        collector_factory=lambda platform: FakeCollector(inventory=_inventory("m1")),
        enricher=FakeEnricher(),
    )

    engine.scan([TargetMachine(id="m1", hostname="h", platform=Platform.LINUX)])

    [saved] = repo.saved_findings["m1"]
    assert saved.kev_listed is True
    assert saved.epss_score == 0.5


def test_findings_persist_unenriched_when_no_enricher_is_configured():
    """No enricher means null enrichment fields -- never fabricated ones."""
    repo = FakeRepository()
    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher([_finding("m1", "CVE-1")]),
        collector_factory=lambda platform: FakeCollector(inventory=_inventory("m1")),
    )

    engine.scan([TargetMachine(id="m1", hostname="h", platform=Platform.LINUX)])

    [saved] = repo.saved_findings["m1"]
    assert saved.kev_listed is None
    assert saved.epss_score is None


def test_a_failing_enricher_does_not_cost_the_scan_its_findings():
    """Collected findings are the expensive part of a scan.

    Enrichment is a local cache lookup layered on top; losing an SSH round trip
    to the whole fleet because that lookup raised would be a badly skewed
    trade. The findings persist unenriched, which their null fields make plain.
    """
    repo = FakeRepository()
    engine = ScannerEngine(
        repository=repo,
        credentials_for=_creds,
        matcher=FakeMatcher([_finding("m1", "CVE-1")]),
        collector_factory=lambda platform: FakeCollector(inventory=_inventory("m1")),
        enricher=FakeEnricher(error=RuntimeError("cache exploded")),
    )

    result = engine.scan(
        [TargetMachine(id="m1", hostname="h", platform=Platform.LINUX)]
    )

    assert result.machine_scans[0].status is ScanStatus.SUCCESS
    [saved] = repo.saved_findings["m1"]
    assert saved.cve_id == "CVE-1"
    assert saved.kev_listed is None


def test_the_enricher_is_not_called_for_a_target_with_no_findings():
    """A clean host should not pay for a pointless cache round trip."""
    enricher = FakeEnricher()
    engine = ScannerEngine(
        repository=FakeRepository(),
        credentials_for=_creds,
        matcher=FakeMatcher([]),
        collector_factory=lambda platform: FakeCollector(inventory=_inventory("m1")),
        enricher=enricher,
    )

    engine.scan([TargetMachine(id="m1", hostname="h", platform=Platform.LINUX)])

    assert enricher.calls == []
