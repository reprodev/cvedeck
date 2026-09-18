"""Unit tests for the core enumerations.

Verifies enum member sets and that the string values match the design document
exactly, since these values are persisted and serialized to JSON.
"""

from app.enums import (
    SEVERITY_RANK,
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
    assert {m.value for m in Severity} == {
        "critical",
        "unscored",
        "high",
        "medium",
        "low",
    }
    assert Severity.CRITICAL == "critical"
    assert Severity.UNSCORED == "unscored"
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM == "medium"
    assert Severity.LOW == "low"


def test_severity_rank_orders_unscored_between_critical_and_high():
    """An unmeasured finding could be either, so it ranks high (Req 10.11)."""
    assert [s for s, _ in sorted(SEVERITY_RANK.items(), key=lambda kv: kv[1])] == [
        Severity.CRITICAL,
        Severity.UNSCORED,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    # Total over the enum: anything that ranks a severity can index this
    # without a fallback that would quietly park a new member at one end.
    assert set(SEVERITY_RANK) == set(Severity)


def test_scan_status_values():
    assert {m.value for m in ScanStatus} == {
        "never_scanned",
        "success",
        "connection_failure",
        "auth_failure",
        "inventory_unavailable",
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
