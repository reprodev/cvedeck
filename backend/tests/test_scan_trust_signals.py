"""Tests for the signals that let a client distinguish clean from broken.

A scan that succeeds against an unreachable advisory source returns a reduced
finding count and a SUCCESS status, which is indistinguishable from a genuinely
clean host unless the partial-ness is reported. These tests pin that reporting,
along with the failure message and the never-scanned status.
"""

from __future__ import annotations

import pytest

from app.enums import Platform, ScanStatus, SourceStatus
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.engine import MachineScan, ScannerEngine
from app.scanner.exceptions import AuthError
from app.scanner.matcher import MatchResult


class _Repo:
    def save_inventory(self, inventory):
        return inventory

    def save_findings(self, machine_id, findings, **_kwargs):
        return findings


class _Collector:
    def __init__(self, inventory=None, raises=None):
        self._inventory = inventory
        self._raises = raises

    def collect(self, target, credentials):
        if self._raises is not None:
            raise self._raises
        return self._inventory


class _Matcher:
    def __init__(self, nvd_status, osv_status):
        self._nvd_status = nvd_status
        self._osv_status = osv_status

    def match(self, inventory, nvd, osv):
        return MatchResult(
            machine_id=inventory.machine_id,
            findings=[],
            nvd_status=self._nvd_status,
            osv_status=self._osv_status,
        )


def _inventory():
    return Inventory(
        machine_id="m1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[Package(name="openssl", version="3.0.2", ecosystem="Ubuntu")],
    )


def _engine(matcher, *, osv=object(), nvd=None, collector=None):
    return ScannerEngine(
        repository=_Repo(),
        credentials_for=lambda t: Credentials(username="u", password="p"),
        matcher=matcher,
        osv=osv,
        nvd=nvd,
        collector_factory=lambda platform: collector or _Collector(_inventory()),
    )


_TARGET = TargetMachine(id="m1", hostname="h", platform=Platform.LINUX)


def test_reachable_sources_report_ok():
    engine = _engine(_Matcher(SourceStatus.DATA_SOURCE_UNAVAILABLE, SourceStatus.OK))

    scan = engine.scan([_TARGET]).machine_scans[0]

    assert scan.status is ScanStatus.SUCCESS
    assert scan.sources_ok is True
    assert scan.unavailable_sources == ()
    assert scan.message is None


def test_unconfigured_source_is_not_reported_as_unavailable():
    """NVD is not wired in any deployment; its absence is not a scan anomaly.

    Counting it would mark every scan partial and train users to ignore the
    warning entirely.
    """
    engine = _engine(
        _Matcher(SourceStatus.DATA_SOURCE_UNAVAILABLE, SourceStatus.OK), nvd=None
    )

    scan = engine.scan([_TARGET]).machine_scans[0]

    assert "NVD" not in scan.unavailable_sources
    assert scan.sources_ok is True


def test_configured_but_unreachable_source_marks_the_scan_partial():
    engine = _engine(
        _Matcher(SourceStatus.OK, SourceStatus.DATA_SOURCE_UNAVAILABLE),
        osv=object(),
        nvd=object(),
    )

    scan = engine.scan([_TARGET]).machine_scans[0]

    assert scan.status is ScanStatus.SUCCESS, "a source outage is not a scan failure"
    assert scan.sources_ok is False
    assert scan.unavailable_sources == ("OSV",)
    assert "Partial results" in scan.message
    assert "OSV" in scan.message


def test_failure_message_carries_the_originating_error():
    """A bare auth_failure gives the user nothing to act on."""
    engine = _engine(
        _Matcher(SourceStatus.OK, SourceStatus.OK),
        collector=_Collector(raises=AuthError("authentication failed for root@host")),
    )

    scan = engine.scan([_TARGET]).machine_scans[0]

    assert scan.status is ScanStatus.AUTH_FAILURE
    assert scan.message == "authentication failed for root@host"
    # The sources were never consulted, so there is nothing partial to report.
    # `status` already tells the client this scan failed; `sources_ok` only
    # carries information when the status is SUCCESS.
    assert scan.unavailable_sources == ()


def test_failed_scan_falls_back_to_the_exception_type_when_message_is_empty():
    engine = _engine(
        _Matcher(SourceStatus.OK, SourceStatus.OK),
        collector=_Collector(raises=ConnectionError()),
    )

    scan = engine.scan([_TARGET]).machine_scans[0]

    assert scan.message == "ConnectionError"


def test_record_status_hook_receives_the_whole_scan():
    """The hook needs the scan, not just the status, to persist source health."""
    recorded: list[MachineScan] = []
    engine = ScannerEngine(
        repository=_Repo(),
        credentials_for=lambda t: Credentials(username="u", password="p"),
        matcher=_Matcher(SourceStatus.OK, SourceStatus.DATA_SOURCE_UNAVAILABLE),
        osv=object(),
        collector_factory=lambda platform: _Collector(_inventory()),
        record_status=lambda target, scan: recorded.append(scan),
    )

    engine.scan([_TARGET])

    assert len(recorded) == 1
    assert recorded[0].status is ScanStatus.SUCCESS
    assert recorded[0].sources_ok is False
