"""Scanner engine that orchestrates a batch scan with per-target fault isolation.

The :class:`ScannerEngine` scans a batch of :class:`~app.models.TargetMachine`
targets one at a time. For each target it selects the platform-specific
collector, collects inventory read-only, persists it, matches the inventory
against the vulnerability data sources, and persists the resulting findings.

Fault isolation is the defining behavior (design "Scan Flow", Req 1.4/1.5):
``_scan_one`` is wrapped so that a target raising the built-in
``ConnectionError`` is recorded as ``CONNECTION_FAILURE`` and a target raising
``AuthError`` is recorded as ``AUTH_FAILURE``. Neither aborts the batch, so the
remaining targets are still scanned. On success the target is recorded as
``SUCCESS`` and its inventory (Req 1.6) and findings (Req 2.3) are persisted.

Dependencies are injected so the engine stays testable without touching real
hosts, data sources, or a database:

- ``credentials_for`` resolves the :class:`~app.models.Credentials` for a target.
- ``repository`` persists inventory and findings; it only needs the
  ``save_inventory`` and ``save_findings`` operations of
  :class:`app.data.repository.Repository`.
- ``matcher`` produces findings from an inventory (defaults to
  :class:`app.scanner.matcher.Matcher`).
- ``nvd`` / ``osv`` are the data-source clients passed through to the matcher; a
  ``None`` client is treated as unreachable by the matcher.
- ``collector_factory`` selects a collector by platform (defaults to
  :func:`app.scanner.collectors.get_collector`).
- ``record_status`` optionally records the per-target outcome (e.g. to update
  the persisted machine row). It is called with the target and the completed
  ``MachineScan``, so it can persist the scan timestamp and data-source health
  alongside the status.
- ``enricher`` optionally attaches cached threat-intel signals (KEV/EPSS) to the
  findings before they are persisted. It runs after matching rather than inside
  it, so ``Matcher.match`` stays pure and network-free; see
  :mod:`app.services.enrichment`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence

from app.data.repository import FindingDiff, FindingInput
from app.enums import ScanStatus, SourceStatus
from app.models import Credentials, Inventory, TargetMachine
from app.scanner.collectors import InventoryCollector, get_collector
from app.scanner.exceptions import (
    AuthError,
    HostKeyMismatchError,
    HostKeyUnknownError,
    InventoryUnavailableError,
)
from app.scanner.matcher import (
    Finding,
    Matcher,
    MatchResult,
    NvdClient,
    OsvClient,
)

_LOGGER = logging.getLogger(__name__)


class _Repository(Protocol):
    """The subset of persistence operations the engine depends on."""

    def save_inventory(self, inventory: Inventory) -> object:
        ...

    def save_findings(
        self,
        machine_id: str,
        findings: list[FindingInput],
        *,
        suppress_resolved: bool = False,
    ) -> object:
        ...


class _Enricher(Protocol):
    """The subset of :class:`app.services.enrichment.FindingEnricher` used here."""

    def enrich(self, findings: Sequence[FindingInput]) -> list[FindingInput]:
        ...


@dataclass(frozen=True)
class MachineScan:
    """The outcome of scanning a single target.

    ``status`` is the recorded :class:`ScanStatus`. On ``SUCCESS`` the collected
    ``inventory`` and the ``match_result`` (with its findings) are populated; on
    ``CONNECTION_FAILURE`` / ``AUTH_FAILURE`` they are ``None`` and ``error``
    carries the originating exception.
    """

    machine_id: str
    status: ScanStatus
    inventory: Inventory | None = None
    match_result: MatchResult | None = None
    error: Exception | None = None
    #: Configured data sources that did not answer during this scan. Empty when
    #: everything that was asked responded. Set by the engine, which is the only
    #: layer that knows which sources were wired up in the first place.
    unavailable_sources: tuple[str, ...] = ()
    #: How the findings differ from the machine's previous ones (Req 18), when
    #: the repository reports it. ``None`` on a failed scan.
    diff: FindingDiff | None = None

    @property
    def findings(self) -> list[Finding]:
        """The findings produced for this target (empty unless successful)."""
        if self.match_result is None:
            return []
        return list(self.match_result.findings)

    @property
    def sources_ok(self) -> bool:
        """Whether every *configured* data source answered (Req 10.1).

        ``False`` means the findings are partial: the scan succeeded but a
        source that should have answered did not, so a low finding count does
        not mean the host is clean. A SUCCESS with an unreachable source is
        otherwise indistinguishable from a genuinely clean result -- a silent
        false negative, the worst failure mode for a vulnerability scanner.

        A source that is not configured at all (NVD, currently) is not counted
        as unavailable (Req 10.2); absent capability is not a per-scan
        anomaly.

        Only meaningful when ``status`` is ``SUCCESS``. A scan that failed to
        connect never consulted a source, so this is vacuously ``True`` there
        and ``status`` is what carries the information.
        """
        return not self.unavailable_sources

    @property
    def message(self) -> str | None:
        """A human-readable explanation of this outcome, or ``None``.

        On failure this is the originating exception's message -- without it the
        UI can only show a bare ``auth_failure`` with no hint whether the cause
        was a bad password, a bad username, or a rejected key.
        """
        if self.error is not None:
            text = str(self.error).strip()
            return text or type(self.error).__name__
        if self.unavailable_sources:
            names = " and ".join(self.unavailable_sources)
            return (
                f"Partial results: {names} unreachable. "
                f"Findings from {'that source' if len(self.unavailable_sources) == 1 else 'those sources'} are missing."
            )
        return None


@dataclass(frozen=True)
class ScanResult:
    """The aggregate outcome of scanning a batch of targets."""

    machine_scans: list[MachineScan] = field(default_factory=list)

    def by_status(self, status: ScanStatus) -> list[MachineScan]:
        """Return the per-target scans that recorded ``status``."""
        return [scan for scan in self.machine_scans if scan.status is status]


def _finding_to_input(finding: Finding) -> FindingInput:
    """Map a matcher :class:`Finding` to the repository's ``FindingInput``."""
    return FindingInput(
        cve_id=finding.cve_id,
        cvss_score=finding.cvss_score,
        severity=finding.severity,
        source=finding.source,
        package_identifier=finding.package_identifier,
    )


class ScannerEngine:
    """Orchestrates a batch scan with per-target fault isolation."""

    def __init__(
        self,
        repository: _Repository,
        credentials_for: Callable[[TargetMachine], Credentials],
        *,
        matcher: Matcher | None = None,
        nvd: NvdClient | None = None,
        osv: OsvClient | None = None,
        collector_factory: Callable[..., InventoryCollector] = get_collector,
        record_status: Callable[[TargetMachine, "MachineScan"], None] | None = None,
        enricher: _Enricher | None = None,
    ) -> None:
        self._repository = repository
        self._credentials_for = credentials_for
        self._matcher = matcher or Matcher()
        self._nvd = nvd
        self._osv = osv
        self._collector_factory = collector_factory
        self._record_status = record_status
        self._enricher = enricher

    def set_credentials(self, credentials_by_id: dict[str, Credentials]) -> None:
        """Install a per-target credential lookup from an id -> credentials map.

        Used by the API's scan endpoint: the request supplies each target's
        credentials, and the engine resolves them by target id at scan time.
        Replaces any previously configured ``credentials_for`` resolver.

        Raises:
            KeyError: At scan time, if a scanned target's id is absent from the
                supplied map.
        """
        self._credentials_for = lambda target: credentials_by_id[target.id]

    def scan(self, targets: list[TargetMachine]) -> ScanResult:
        """Scan each target independently.

        A per-target ``ConnectionError`` or ``AuthError`` is captured as a
        :class:`ScanStatus` and never aborts the remaining targets (Req 1.4,
        1.5). Returns a :class:`ScanResult` aggregating every per-target outcome.
        """
        machine_scans: list[MachineScan] = []
        for target in targets:
            machine_scans.append(self._scan_target(target))
        return ScanResult(machine_scans=machine_scans)

    def _scan_target(self, target: TargetMachine) -> MachineScan:
        """Run ``_scan_one`` for a target, isolating recoverable failures.

        Maps ``ConnectionError`` -> ``CONNECTION_FAILURE`` (Req 1.4),
        ``AuthError`` -> ``AUTH_FAILURE`` (Req 1.5, 9.4), an unreadable package
        inventory -> ``INVENTORY_UNAVAILABLE`` (Req 1.7), and a refused SSH
        host key -> ``HOST_KEY_MISMATCH`` / ``HOST_KEY_UNKNOWN`` (Req 17.3,
        17.5); records the status
        and returns the outcome rather than propagating, so one bad key or
        passphrase does not abort the batch (Req 9.4, 11.9). The originating
        exception travels on the outcome as ``error`` so the API can report it
        alongside the status (Req 10.3).
        """
        try:
            scan = self._scan_one(target)
        except AuthError as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.AUTH_FAILURE,
                error=exc,
            )
        except HostKeyMismatchError as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.HOST_KEY_MISMATCH,
                error=exc,
            )
        except HostKeyUnknownError as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.HOST_KEY_UNKNOWN,
                error=exc,
            )
        except InventoryUnavailableError as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.INVENTORY_UNAVAILABLE,
                error=exc,
            )
        except ConnectionError as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.CONNECTION_FAILURE,
                error=exc,
            )
        except Exception as exc:
            scan = MachineScan(
                machine_id=target.id,
                status=ScanStatus.CONNECTION_FAILURE,
                error=exc,
            )
        self._record(target, scan)
        return scan

    def _scan_one(self, target: TargetMachine) -> MachineScan:
        """Connect, collect, match, and persist for a single target.

        Selects the collector by platform, collects inventory read-only and
        persists it (Req 1.6), runs the Matcher, maps findings to the
        repository's input shape, and persists them (Req 2.3). May raise
        ``ConnectionError`` / ``AuthError`` from the collector; the caller
        isolates those.
        """
        collector = self._collector_factory(target.platform)
        credentials = self._credentials_for(target)

        inventory = collector.collect(target, credentials)
        self._repository.save_inventory(inventory)

        match_result = self._matcher.match(inventory, self._nvd, self._osv)
        # Known before saving, because a partial scan must not resolve anything:
        # a source that did not answer is not a patch (Req 18.3).
        unavailable = self._unavailable_sources(match_result)
        saved = self._repository.save_findings(
            target.id,
            self._enrich([_finding_to_input(f) for f in match_result.findings]),
            suppress_resolved=bool(unavailable),
        )

        return MachineScan(
            machine_id=target.id,
            status=ScanStatus.SUCCESS,
            inventory=inventory,
            match_result=match_result,
            unavailable_sources=unavailable,
            diff=saved if isinstance(saved, FindingDiff) else None,
        )

    def _enrich(self, findings: list[FindingInput]) -> list[FindingInput]:
        """Attach cached threat-intel signals, if an enricher is configured.

        Enrichment reads a local cache and cannot reach the network, so it has
        no outage mode of its own. It is still guarded: a defect in enrichment
        must not cost the caller a scan's worth of collected findings, which
        are the expensive part. On failure the findings are persisted
        unenriched, which the ``None`` fields make visible downstream.
        """
        if self._enricher is None or not findings:
            return findings
        try:
            return self._enricher.enrich(findings)
        except Exception:
            _LOGGER.exception(
                "Enrichment failed; persisting findings without intel signals"
            )
            return findings

    def _unavailable_sources(self, match_result: MatchResult) -> tuple[str, ...]:
        """Names of configured sources that failed to answer (Req 10.1).

        Only sources this engine was actually given are considered
        (Req 10.2). NVD is not wired in any current deployment, so counting
        its absence would mark every scan partial and train users to ignore
        the warning.
        """
        unavailable: list[str] = []
        if self._nvd is not None and match_result.nvd_status is not SourceStatus.OK:
            unavailable.append("NVD")
        if self._osv is not None and match_result.osv_status is not SourceStatus.OK:
            unavailable.append("OSV")
        return tuple(unavailable)

    def _record(self, target: TargetMachine, scan: MachineScan) -> None:
        """Record the per-target outcome via the optional hook, if provided.

        The hook receives the whole :class:`MachineScan`, not just a status, so
        it can persist the scan timestamp and data-source health too. Read
        ``scan.status`` for the previous behaviour.
        """
        if self._record_status is not None:
            self._record_status(target, scan)
