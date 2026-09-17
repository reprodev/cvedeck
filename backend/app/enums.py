"""Core enumerations shared across the CveDeck layers.

These string-valued enums are used by the scanner engine, persistence layer,
API serialization, and synchronization service. String values match the design
document exactly so they serialize to stable JSON and persist consistently in
both the Local_Database and Online_Database.
"""

from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    """Operating-system family of a Target_Machine (selects the collector)."""

    LINUX = "linux"
    WINDOWS = "windows"


class Severity(str, Enum):
    """Severity_Level derived from a CVSS_Score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, Enum):
    """Per-target outcome of a scan; failures never abort the batch.

    ``NEVER_SCANNED`` is the state of a machine that exists in the roster but
    has not been scanned yet -- typically one enrolled from network discovery
    (Req 10.4). It previously defaulted to ``CONNECTION_FAILURE``, which made
    every freshly enrolled host render as a red failure before anything had
    been attempted -- the distinction Req 10.4 exists to preserve.

    ``INVENTORY_UNAVAILABLE`` is a host that authenticated but whose package
    inventory could not be read (Req 1.7). It is not a success with nothing
    found: an empty inventory would delete every finding recorded by the last
    scan and report them resolved.

    ``HOST_KEY_MISMATCH`` and ``HOST_KEY_UNKNOWN`` are refusals, not failures
    to connect (Req 17.3, 17.5): the host answered, with a key other than the
    pinned one, or with a key when policy requires one to be pinned already.
    """

    NEVER_SCANNED = "never_scanned"
    SUCCESS = "success"
    CONNECTION_FAILURE = "connection_failure"
    AUTH_FAILURE = "auth_failure"
    INVENTORY_UNAVAILABLE = "inventory_unavailable"
    HOST_KEY_MISMATCH = "host_key_mismatch"
    HOST_KEY_UNKNOWN = "host_key_unknown"


class FindingChange(str, Enum):
    """How a finding differs between a host's consecutive scans (Req 18).

    Persisted on each scan run's change rows. There is deliberately no
    "unchanged": a run records only what moved.
    """

    NEW = "new"
    RESOLVED = "resolved"


class SourceStatus(str, Enum):
    """Reachability of a public vulnerability data source during matching."""

    OK = "ok"
    DATA_SOURCE_UNAVAILABLE = "data_source_unavailable"


class FeedStatus(str, Enum):
    """Outcome of the last refresh of a locally cached threat-intel feed.

    KEV and EPSS are cached locally and refreshed on a cadence rather than
    queried per scan, so a feed can be silently months out of date. Recording
    the outcome is what lets the dashboard say "enrichment is stale" instead of
    presenting an unenriched finding as one that is simply not exploited --
    the same reasoning behind ``last_scan_sources_ok`` on a target machine.

    ``NEVER_REFRESHED`` is the state of a deployment that has not yet pulled
    the feed at all, which is distinct from one whose pull failed.
    """

    NEVER_REFRESHED = "never_refreshed"
    OK = "ok"
    FAILED = "failed"


class SyncStatus(str, Enum):
    """Synchronization state of a syncable row between local and online stores."""

    SYNCED = "synced"
    PENDING_SYNC = "pending_sync"


class RemediationStatus(str, Enum):
    """Manually maintained remediation state for a CVE on a machine."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
