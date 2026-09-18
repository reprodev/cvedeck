"""SQLAlchemy ORM models for the CveDeck persistence layer.

These ORM tables are intentionally separate from the in-memory domain models in
``app.models`` (which are Pydantic structures produced by collectors and consumed
by the matcher). The persistence layer maps domain structures to/from these rows.

The schema defined here is identical for the Local_Database and Online_Database,
so synchronization is a direct row propagation (Req 5.5). Every syncable row
carries a ``sync_status`` column (Req 5.2, 5.3, 5.4).

The data model is deliberately extensible for a future dependency/application-path
visualization: ``CveFinding`` carries a ``package_identifier`` (Req 7.1) and a
``dependency_path_id`` FK into ``DependencyPath`` (Req 5.5, 7.2), and
``DependencyPath`` has a ``parent_path_id`` self-reference so dependency chains can
be modeled. These are stored now and remain inert until the visualization consumes
them; no restructuring is required to add that feature (Req 7).

Enum columns use SQLAlchemy's ``Enum`` type backed by the shared string enums in
``app.enums`` so values persist identically in both databases and match the JSON
serialization used by the API.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean
from sqlalchemy import Enum as SqlEnum
from sqlalchemy import Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy import false as sa_false
from sqlalchemy import text as sa_text
from sqlalchemy import true as sa_true
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)

from ..enums import (
    FeedStatus,
    FindingChange,
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models in the persistence layer."""


class TargetMachine(Base):
    """A Windows or Linux host that the system scans remotely.

    Root entity that findings, inventory, dependency paths, and remediation
    records associate with (CVE <-> machine association, Req 5.5).
    """

    __tablename__ = "target_machines"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    platform: Mapped[Platform] = mapped_column(
        SqlEnum(Platform, name="platform"), nullable=False
    )
    last_scan_status: Mapped[ScanStatus] = mapped_column(
        SqlEnum(ScanStatus, name="scan_status"), nullable=False
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # False when a data source was unreachable during the last scan, so its
    # findings are partial. A scan that reports SUCCESS with an unreachable
    # source produces a reduced finding count that is otherwise
    # indistinguishable from a genuinely clean host.
    last_scan_sources_ok: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_true()
    )
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    inventories: Mapped[list[Inventory]] = relationship(
        back_populates="machine", cascade="all, delete-orphan"
    )
    findings: Mapped[list[CveFinding]] = relationship(
        back_populates="machine", cascade="all, delete-orphan"
    )
    dependency_paths: Mapped[list[DependencyPath]] = relationship(
        back_populates="machine", cascade="all, delete-orphan"
    )
    remediation_records: Mapped[list[RemediationRecord]] = relationship(
        back_populates="machine", cascade="all, delete-orphan"
    )
    scan_runs: Mapped[list[ScanRun]] = relationship(
        back_populates="machine", cascade="all, delete-orphan"
    )


class Inventory(Base):
    """Normalized OS/package inventory collected from a single Target_Machine.

    Stored in the Local_Database and propagated to the Online_Database (Req 1.6,
    5.1). Installed packages are stored as child ``Package`` rows.
    """

    __tablename__ = "inventories"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    machine_id: Mapped[str] = mapped_column(
        ForeignKey("target_machines.id"), nullable=False
    )
    os_name: Mapped[str] = mapped_column(String, nullable=False)
    os_version: Mapped[str] = mapped_column(String, nullable=False)
    # Running kernel release. A host can have every package updated and still be
    # running the vulnerable kernel it booted from, which a package-list-only
    # scan reports as clean.
    kernel_version: Mapped[str | None] = mapped_column(String, nullable=True)
    # Whether a reboot is pending; NULL when the distribution offers no
    # read-only way to ask.
    reboot_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(nullable=False)
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    machine: Mapped[TargetMachine] = relationship(back_populates="inventories")
    packages: Mapped[list[Package]] = relationship(
        back_populates="inventory", cascade="all, delete-orphan"
    )


class Package(Base):
    """A single installed software package belonging to an Inventory.

    ``ecosystem`` (e.g. PyPI, npm, deb) is optional and refines OSV matching.
    ``dependencies`` is a comma-separated list of required package names.
    """

    __tablename__ = "packages"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    inventory_id: Mapped[str] = mapped_column(
        ForeignKey("inventories.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False)
    ecosystem: Mapped[str | None] = mapped_column(String, nullable=True)
    dependencies: Mapped[str | None] = mapped_column(String, nullable=True)

    inventory: Mapped[Inventory] = relationship(back_populates="packages")


class DependencyPath(Base):
    """Future dependency/application-path visualization anchor.

    Present in the schema now so the association survives synchronization
    (Req 7.2, 7.3). ``parent_path_id`` is a self-reference that lets dependency
    chains (e.g. app -> libA -> libB) be modeled. Inert until a future
    visualization consumes it; no restructuring is required to add that feature.
    """

    __tablename__ = "dependency_paths"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    machine_id: Mapped[str] = mapped_column(
        ForeignKey("target_machines.id"), nullable=False
    )
    package_identifier: Mapped[str | None] = mapped_column(String, nullable=True)
    path_expression: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_path_id: Mapped[str | None] = mapped_column(
        ForeignKey("dependency_paths.id"), nullable=True
    )
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    machine: Mapped[TargetMachine] = relationship(back_populates="dependency_paths")
    parent_path: Mapped[DependencyPath | None] = relationship(
        remote_side=[id], back_populates="child_paths"
    )
    child_paths: Mapped[list[DependencyPath]] = relationship(
        back_populates="parent_path"
    )
    findings: Mapped[list[CveFinding]] = relationship(
        back_populates="dependency_path"
    )


class CveFinding(Base):
    """A CVE matched against a Target_Machine's inventory.

    Associates a CVE with a Target_Machine (Req 5.5). ``package_identifier`` is
    set for OSV/package-level findings (Req 7.1) and ``dependency_path_id`` links
    the finding to a ``DependencyPath`` (Req 5.5, 7.2). Both fields are preserved
    across synchronization (Req 7.3).
    """

    __tablename__ = "cve_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    machine_id: Mapped[str] = mapped_column(
        ForeignKey("target_machines.id"), nullable=False
    )
    # Indexed because enrichment joins the whole finding set against the KEV and
    # EPSS caches by CVE id after every scan.
    cve_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # Nullable because not every advisory publishes a score, and a substituted
    # one is indistinguishable from a measured one (Req 2.7). Null is "nobody
    # published a number", never zero and never a mid-range guess; the severity
    # column still carries a band whenever the feed named one.
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        SqlEnum(Severity, name="severity"), nullable=False
    )
    source: Mapped[str] = mapped_column(String, nullable=False)  # "nvd" | "osv"
    package_identifier: Mapped[str | None] = mapped_column(String, nullable=True)
    dependency_path_id: Mapped[str | None] = mapped_column(
        ForeignKey("dependency_paths.id"), nullable=True
    )

    # --- Threat-intel enrichment ------------------------------------------
    # These three are deliberately nullable rather than defaulted, because
    # "we did not enrich this finding" and "this finding is not exploited" are
    # different claims and only one of them is safe to act on. A NULL here is
    # rendered as unknown, never as absent-from-KEV. See ``FeedStatus``.
    #
    # ``kev_listed`` is CISA's Known Exploited Vulnerabilities catalogue: the
    # vulnerability is being exploited in the wild right now. ``epss_score`` is
    # FIRST's 0.0-1.0 probability of exploitation in the next 30 days, and
    # ``epss_percentile`` is that score's rank among all scored CVEs -- the
    # percentile is what makes the number legible, since a raw EPSS of 0.08 is
    # meaningless until you know it is above 94% of everything else.
    kev_listed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    #: CISA's remediation due date for a KEV-listed CVE, when one is published.
    kev_due_date: Mapped[str | None] = mapped_column(String, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: When this finding was first seen on this machine (Req 18.5). Carried
    #: across the delete-and-rewrite of every scan by matching on CVE and
    #: package name, not version, so an upgrade that leaves a package vulnerable
    #: does not make an old finding look new.
    first_seen_at: Mapped[datetime] = mapped_column(
        nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    machine: Mapped[TargetMachine] = relationship(back_populates="findings")
    dependency_path: Mapped[DependencyPath | None] = relationship(
        back_populates="findings"
    )


class ScanRun(Base):
    """One scan attempt on one machine, successful or not (Req 18.1).

    ``new_count`` and ``resolved_count`` are NULL when the run cannot say. Both
    are NULL on a failed scan and on a baseline, a machine's first successful
    run. ``resolved_count`` alone is NULL on a partial scan, where an
    unreachable source can make a finding disappear without it being fixed.
    NULL means "not assessed", never zero.
    """

    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    machine_id: Mapped[str] = mapped_column(
        ForeignKey("target_machines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanned_at: Mapped[datetime] = mapped_column(nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        SqlEnum(ScanStatus, name="scan_status"), nullable=False
    )
    sources_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    new_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: True for a machine's first successful run, which has nothing to compare
    #: with -- including its first scan after upgrading to a version that
    #: records history (Req 18.4).
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False)
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )
    #: Why a failed run failed, as the scanner reported it (Req 18.10). ``None``
    #: for a run that succeeded. Without it the history says only "Failed",
    #: which does not tell a bad password from an unreachable port. Bounded
    #: and free of credentials, like ``FeedRefresh.error_detail``.
    error_detail: Mapped[str | None] = mapped_column(String, nullable=True)

    machine: Mapped[TargetMachine] = relationship(back_populates="scan_runs")
    changes: Mapped[list[ScanFindingChange]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class ScanFindingChange(Base):
    """A finding that appeared or cleared in one scan run (Req 18.2).

    A snapshot rather than a reference: a resolved finding no longer exists in
    ``cve_findings``, so what it was has to be kept here.
    """

    __tablename__ = "scan_finding_changes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    change: Mapped[FindingChange] = mapped_column(
        SqlEnum(FindingChange, name="finding_change"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String, nullable=False)
    package_identifier: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        SqlEnum(Severity, name="severity"), nullable=False
    )
    # Nullable for the same reason as on CveFinding: a change record quotes the
    # score the finding had, and that may be no score at all (Req 2.7).
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_listed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    scan_run: Mapped[ScanRun] = relationship(back_populates="changes")


class KevEntry(Base):
    """One CVE from CISA's Known Exploited Vulnerabilities catalogue.

    A locally cached copy of the whole catalogue rather than a per-CVE lookup:
    it is a single ~1.5 MB JSON document covering every known-exploited CVE, so
    downloading it once a day and joining locally is both faster and kinder to
    CISA than one HTTP request per finding.

    Deliberately *not* carrying a ``sync_status``: this is a public dataset
    reproducible from its source, not scan data, so propagating it through the
    Online_Database sync would be copying an upstream file between two of your
    own databases. Each instance refreshes its own copy.
    """

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    vendor_project: Mapped[str | None] = mapped_column(String, nullable=True)
    product: Mapped[str | None] = mapped_column(String, nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(String, nullable=True)
    #: ISO date strings as published by CISA; stored verbatim rather than parsed
    #: so a format change upstream degrades to a display oddity, not an import
    #: failure that loses the whole catalogue.
    date_added: Mapped[str | None] = mapped_column(String, nullable=True)
    due_date: Mapped[str | None] = mapped_column(String, nullable=True)
    #: Whether CISA has observed this CVE used in ransomware campaigns. The
    #: single strongest "drop everything" signal the catalogue carries.
    known_ransomware_use: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_false()
    )
    notes: Mapped[str | None] = mapped_column(String, nullable=True)


class EpssScore(Base):
    """One CVE's EPSS exploitation probability, cached from the FIRST feed.

    ``score`` is the modelled probability (0.0-1.0) that the CVE is exploited in
    the next 30 days; ``percentile`` is its rank against every other scored CVE.
    Like ``KevEntry`` this is an upstream dataset, so it carries no sync status.
    """

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    scored_at: Mapped[datetime] = mapped_column(nullable=False)


class FeedRefresh(Base):
    """The outcome of the most recent refresh of one cached intel feed.

    This table is the reason a stale KEV cache is visible rather than silent.
    Without it, a refresh that has been failing for a month looks identical to
    a fleet that genuinely has no known-exploited vulnerabilities -- the same
    class of false negative that ``target_machines.last_scan_sources_ok``
    exists to prevent.

    ``error_detail`` keeps the last failure's message even after a later
    success is recorded elsewhere in the row, so a flapping feed is diagnosable.
    """

    __tablename__ = "feed_refreshes"

    #: Stable feed identifier: "kev" or "epss".
    feed_name: Mapped[str] = mapped_column(String, primary_key=True)
    #: When the feed last refreshed *successfully*. NULL means it never has, so
    #: a feed that has only ever failed does not report a misleading age.
    last_refreshed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    #: When a refresh was last attempted, successful or not.
    last_attempted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_status: Mapped[FeedStatus] = mapped_column(
        SqlEnum(FeedStatus, name="feed_status"), nullable=False
    )
    record_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    error_detail: Mapped[str | None] = mapped_column(String, nullable=True)


class SshHostKey(Base):
    """The SSH host key pinned for one address (Req 17).

    Keyed by ``(hostname, port)`` rather than by machine, because a connection
    test has an address and no machine, and the two must share one pin
    (Req 17.6). ``hostname`` is stored lower-cased, since DNS names are not
    case-sensitive and a second pin for ``Host.lan`` would be a free first use.

    No ``sync_status``, like the auth tables: which key this instance trusts is
    its own decision, and a pin arriving from another database would be trust
    this instance never granted.
    """

    __tablename__ = "ssh_host_keys"
    __table_args__ = (UniqueConstraint("hostname", "port"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    #: known_hosts key type, e.g. ``ssh-ed25519``.
    key_type: Mapped[str] = mapped_column(String, nullable=False)
    key_base64: Mapped[str] = mapped_column(String, nullable=False)
    #: ``SHA256:...``, as ``ssh-keygen -lf`` prints it.
    fingerprint_sha256: Mapped[str] = mapped_column(String, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(nullable=False)


class User(Base):
    """An account that can sign in to the dashboard and API (Req 16).

    Like the intel caches, auth rows carry no ``sync_status`` and are absent
    from the sync order: credentials belong to this instance and must never be
    copied to the Online_Database.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    #: ``scrypt$n$r$p$salt$hash`` -- see ``app.auth.passwords``. Never the
    #: password itself.
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(nullable=False)


class AuthSession(Base):
    """A signed-in browser session (Req 16.5, 16.6).

    Keyed by the SHA-256 of the cookie value, so a copy of this table cannot be
    replayed as a login.
    """

    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    #: Absolute expiry. Idle expiry is computed from ``last_seen_at``.
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class ApiToken(Base):
    """A named bearer token for scripts and other applications (Req 16.7).

    Only the hash is stored; the token is shown once, when created. ``prefix``
    is the first few characters, kept so a token can be recognised in the list
    without being recoverable from it. A revoked token keeps its row, so the
    list can still show what it was and when it stopped working.
    """

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    token_hash: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    prefix: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AuthSetup(Base):
    """The outstanding first-run setup code, while no account exists (Req 16.3).

    At most one row. Holds a hash, not the code: the code itself only ever
    appears in the start-up log.
    """

    __tablename__ = "auth_setup"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)


class RemediationRecord(Base):
    """Manually maintained remediation state for a CVE on a machine.

    Only administrator-initiated; stored locally and synchronized (Req 4, 5.1).
    """

    __tablename__ = "remediation_records"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    machine_id: Mapped[str] = mapped_column(
        ForeignKey("target_machines.id"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[RemediationStatus] = mapped_column(
        SqlEnum(RemediationStatus, name="remediation_status"), nullable=False
    )
    note: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
    sync_status: Mapped[SyncStatus] = mapped_column(
        SqlEnum(SyncStatus, name="sync_status"), nullable=False
    )

    machine: Mapped[TargetMachine] = relationship(
        back_populates="remediation_records"
    )
