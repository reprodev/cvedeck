"""Unit tests for the core enumerations.

Verifies enum member sets and that the string values match the design document
exactly, since these values are persisted and serialized to JSON.
"""

from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SourceStatus,
    SyncStatus,
)


def test_platform_values():
    assert {m.value for m in Platform} == {"linux", "windows"}
    assert Platform.LINUX == "linux"
    assert Platform.WINDOWS == "windows"


def test_severity_values():
    assert {m.value for m in Severity} == {"critical", "high", "medium", "low"}
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM == "medium"
    assert Severity.LOW == "low"


def test_scan_status_values():
    assert {m.value for m in ScanStatus} == {
        "never_scanned",
        "success",
        "connection_failure",
        "auth_failure",
        "host_key_mismatch",
        "host_key_unknown",
    }


def test_source_status_values():
    assert {m.value for m in SourceStatus} == {"ok", "data_source_unavailable"}


def test_sync_status_values():
    assert {m.value for m in SyncStatus} == {"synced", "pending_sync"}


def test_remediation_status_values():
    assert {m.value for m in RemediationStatus} == {
        "open",
        "in_progress",
        "remediated",
        "accepted_risk",
    }


def test_enums_are_str_subclasses():
    """String enums so members serialize directly and compare to raw strings."""
    for enum_cls in (
        Platform,
        Severity,
        ScanStatus,
        SourceStatus,
        SyncStatus,
        RemediationStatus,
    ):
        for member in enum_cls:
            assert isinstance(member, str)
