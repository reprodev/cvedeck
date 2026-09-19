"""Demo fleet, for screenshots and for trying CveDeck without hosts to scan.

Implements the seeding half of Req 15 (Req 15.1, 15.5, 15.6).

An empty dashboard says nothing about what this tool does. Someone evaluating
it should not have to enrol a fleet and wait for a scan before they can see
whether the prioritisation is worth anything -- and the screenshots in the
README have to come from somewhere reproducible, not from a real network with
its hostnames blurred out.

The fleet mirrors the fixture set in ``frontend/design/build.py``, which was
built to exercise the states that actually matter rather than a tidy list of
healthy hosts:

    * a host that has never been scanned          (never_scanned)
    * a host whose credentials failed             (auth_failure)
    * a host that could not be reached            (connection_failure)
    * a host scanned while a source was down      (last_scan_sources_ok=False)
    * a host scanned a month ago                  (stale)
    * hosts with findings CISA lists as exploited (kev_listed=True)
    * hosts whose findings were never enriched    (kev_listed=None)
    * a finding with a band but no CVSS score     (Req 2.6)
    * a finding with no severity published at all (unscored, Req 2.7)
    * a scan history: a baseline, a scan with new and resolved findings, a
      partial scan that resolves nothing, and failed attempts (Req 18)

That last pair is the point. Per AGENTS.md section 3, ``kev_listed`` is
three-valued and the states are never collapsed: NULL means "not checked",
False means "checked, and genuinely absent from CISA's KEV". A demo that showed
a confident "0 actively exploited" everywhere would be advertising exactly the
false negative this project exists to avoid, so the seed deliberately contains
all three states and the UI is expected to render them differently.

The same argument covers the CVSS score, which is why the seed carries a
scoreless finding: a score and a severity are independent facts, and a demo
in which every advisory has a number would hide the case the 0.8.6 release
exists to make visible.

Nothing here is called during a normal scan. Seeding happens only when
``CVEDECK_DEMO_MODE`` is set, and only into a database with no machines in it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..enums import (
    FeedStatus,
    FindingChange,
    Platform,
    ScanStatus,
    Severity,
    SyncStatus,
)
from .schema import (
    CveFinding,
    EpssScore,
    FeedRefresh,
    Inventory,
    KevEntry,
    Package,
    ScanFindingChange,
    ScanRun,
    SshHostKey,
    TargetMachine,
)


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ago(**kwargs: float) -> datetime:
    return _now() - timedelta(**kwargs)


# (hostname, platform, os_name, os_version, kernel, status, scanned_ago_hours,
#  sources_ok, reboot_required)
_HOSTS: list[tuple[str, Platform, str, str, str | None, ScanStatus, float | None, bool, bool | None]] = [
    ("db-primary.lan",  Platform.LINUX,   "Debian GNU/Linux", "12",    "6.1.0-18-amd64",  ScanStatus.SUCCESS, 24,   True,  True),
    ("web-01.lan",      Platform.LINUX,   "Ubuntu",           "22.04", "5.15.0-91-generic", ScanStatus.SUCCESS, 1,  True,  False),
    # Scanned, but one advisory source was unreachable -- reported as partial,
    # never as clean.
    ("app-alma.lan",    Platform.LINUX,   "AlmaLinux",        "9.3",   "5.14.0-362.el9",  ScanStatus.SUCCESS, 48,   False, False),
    ("cache-01.lan",    Platform.LINUX,   "Alpine Linux",     "3.19",  "6.6.7-0-lts",     ScanStatus.SUCCESS, 1,    True,  False),
    ("build-arm.lan",   Platform.LINUX,   "Raspbian",         "12",    "6.1.0-rpi7-rpi-v8", ScanStatus.SUCCESS, 1, True,  False),
    ("edge-proxy.lan",  Platform.LINUX,   "Rocky Linux",      "9.3",   "5.14.0-362.el9",  ScanStatus.SUCCESS, 1,    True,  False),
    # A month old: the fleet view flags this as stale.
    ("nas-01.lan",      Platform.LINUX,   "openSUSE Leap",    "15.5",  "5.14.21-150500",  ScanStatus.SUCCESS, 720,  True,  False),
    ("web-02.lan",      Platform.LINUX,   "Ubuntu",           "22.04", "5.15.0-91-generic", ScanStatus.SUCCESS, 1,  True,  False),
    # Enrolled but never scanned. Says so, rather than showing a failure.
    ("new-host.lan",    Platform.LINUX,   "",                 "",      None,              ScanStatus.NEVER_SCANNED, None, True, None),
    ("pi-sensor.lan",   Platform.LINUX,   "",                 "",      None,              ScanStatus.AUTH_FAILURE, 48, True, None),
    ("bastion.lan",     Platform.LINUX,   "",                 "",      None,              ScanStatus.CONNECTION_FAILURE, 24, True, None),
    # Refused before authenticating: this host presented a key other than the
    # pinned one (Req 17.3). Its pin is seeded below, so the machine page can
    # show what it is held to and offer to forget it.
    ("vault-01.lan",    Platform.LINUX,   "",                 "",      None,              ScanStatus.HOST_KEY_MISMATCH, 6, True, None),
    # A Windows host enrolled from network discovery. Windows scans are refused
    # (Req 10.8) because collected Windows inventory cannot yet be matched, so
    # the honest state for one is enrolled and never scanned -- a Windows host
    # with findings, or with a scan failure, would imply a capability that does
    # not exist.
    ("dc-01.lan",       Platform.WINDOWS, "",                 "",      None,              ScanStatus.NEVER_SCANNED, None, True, None),
]

# Pinned SSH host keys (Req 17). Without these the machine pages show no pin,
# the Settings panel is empty, and the whole pinning feature is invisible in
# the demo. The last two exist to show the states nothing else can reach: a
# second port on an enrolled host, and an address no machine matches.
#
# (hostname, port, key_type, fingerprint, first_seen_hours_ago)
_HOST_KEYS: list[tuple[str, int, str, str, float]] = [
    ("web-01.lan",   22,   "ssh-ed25519", "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", 24 * 30),
    ("db-primary.lan", 22, "ssh-ed25519", "SHA256:9lJ7Bs0aMIcQKq8eQwDfVYsDKXxQfLMk1pPRr8SD0nE", 24 * 30),
    ("vault-01.lan", 22,   "ssh-rsa",     "SHA256:0mQ3xVYYFRkGjBb3xHtYJkGRPQ8mKfVHl2kHbdUm7vA", 24 * 45),
    # The same host on a second port, as an sshd listening twice presents it.
    ("web-01.lan",   2222, "ssh-ed25519", "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", 24 * 12),
    # A connection test to an address nobody enrolled: no machine page can show
    # this one, which is why the Settings listing exists (Req 17.10).
    ("spare-nic.lan", 22,  "ssh-ed25519", "SHA256:tJ0Yb4cQwVvNn2pLx6RfKmAe1sZgHu9WqDcXoP5iM3U", 24 * 60),
]

# (cve_id, cvss, severity, package, fixed_version, kev, epss, percentile)
#
# `kev` is the three-valued field: True listed, False checked-and-absent,
# None never checked.
#
# `fixed_version` None means no vendor patch exists yet, which is what puts a
# finding in "Pending Vendor Patch" rather than "Ready to Fix". Note that the
# database has no fixed_version column: the API parses it back out of
# `package_identifier`, which the matcher formats as
# "<ecosystem>:<name>@<version> (fixed in <fixed>)". The seed therefore has to
# build that same string rather than set a field, so that demo data travels the
# identical code path real scan results do -- see _identifier() below.
_FINDINGS_LINUX: list[
    tuple[
        str,
        float | None,
        Severity,
        str,
        str | None,
        bool | None,
        float | None,
        float | None,
    ]
] = [
    # Actively exploited. The whole argument for this tool is that these
    # outrank the 9.8 below them that nobody has ever touched.
    ("CVE-2024-3094",  10.0, Severity.CRITICAL, "xz-utils",     "5.6.1+really5.4.5-1", True,  0.9421, 0.9998),
    ("CVE-2023-4863",   8.8, Severity.HIGH,     "libwebp",      "1.2.4-0.2+deb12u1",   True,  0.7215, 0.9971),
    ("CVE-2024-21762",  9.8, Severity.CRITICAL, "openssl",      "3.0.11-1~deb12u2",    True,  0.9604, 0.9999),
    ("CVE-2023-44487",  7.5, Severity.HIGH,     "nginx",        "1.22.1-9",            True,  0.8832, 0.9989),
    # High CVSS, no evidence of exploitation. Deliberately ranked below.
    ("CVE-2023-38545",  9.8, Severity.CRITICAL, "curl",         "7.88.1-10+deb12u5",   False, 0.0043, 0.7211),
    ("CVE-2024-0567",   6.5, Severity.MEDIUM,   "gnutls28",     "3.7.9-2+deb12u2",     False, 0.0009, 0.3902),
    ("CVE-2023-29491",  7.8, Severity.HIGH,     "ncurses",      "6.4-4",               False, 0.0006, 0.2755),
    ("CVE-2024-22365",  5.5, Severity.MEDIUM,   "pam",          "1.5.2-6+deb12u1",     False, 0.0004, 0.1483),
    ("CVE-2023-5678",   5.3, Severity.MEDIUM,   "openssl",      "3.0.11-1~deb12u2",    False, 0.0011, 0.4520),
    ("CVE-2023-6246",   7.8, Severity.HIGH,     "glibc",        "2.36-9+deb12u4",      False, 0.0021, 0.5904),
    ("CVE-2024-25062",  7.5, Severity.HIGH,     "libxml2",      "2.9.14+dfsg-1.3~deb12u1", False, 0.0015, 0.5111),
    ("CVE-2023-50387",  7.5, Severity.HIGH,     "bind9",        "1:9.18.24-1",         False, 0.0087, 0.8033),
    # Awaiting a vendor build: no fixed version, so no upgrade command exists.
    ("CVE-2024-26461",  6.5, Severity.MEDIUM,   "krb5",         None,                  False, 0.0007, 0.3011),
    ("CVE-2023-52425",  7.5, Severity.HIGH,     "expat",        None,                  False, 0.0032, 0.6688),
    ("CVE-2024-28085",  6.7, Severity.MEDIUM,   "util-linux",   None,                  False, 0.0005, 0.2210),
    ("CVE-2023-45853",  9.8, Severity.CRITICAL, "zlib",         None,                  False, 0.0064, 0.7743),
    # No published score. These are the two shapes a scoreless advisory takes,
    # and the fleet carries both for the same reason it carries all three
    # kev_listed states: a demo in which every finding has a tidy number would
    # advertise a confidence the data does not have.
    #
    #   - a band and no number: the feed published the word "High" and no
    #     vector, which is what an Alpine or SUSE record often looks like. The
    #     band is real; the number was never published (Req 2.6).
    #   - neither: nobody has said how bad this is at all (Req 2.7). It ranks
    #     below Critical and above High, because it could be either.
    ("CVE-2024-45490", None, Severity.HIGH,     "libexpat",     "2.5.0-1+deb12u1",     False, 0.0019, 0.5402),
    ("CVE-2024-45491", None, Severity.UNSCORED, "libxslt",      "1.1.35-1+deb12u1",    None,  None,   None),
    # Low-severity noise, so the ramp has something at the bottom.
    ("CVE-2023-4039",   4.8, Severity.LOW,      "gcc-12",       "12.2.0-14",           False, 0.0003, 0.0912),
    ("CVE-2024-2236",   5.3, Severity.LOW,      "libgcrypt20",  "1.10.1-3",            False, 0.0002, 0.0655),
]
# Hosts whose findings were never enriched. Their KEV and EPSS columns must
# render as unknown -- not as a clean bill of health.
_UNENRICHED_HOSTS = {"nas-01.lan", "build-arm.lan"}

# What each package depends on -- the direction dpkg reports, which the API
# reverses to answer "what breaks if this goes". The demo used to list it the
# other way round, so openssl was recorded as depending on nginx.
_DEPENDENCIES: dict[str, list[str]] = {
    "nginx": ["openssl", "zlib", "glibc"],
    "curl": ["openssl", "zlib", "glibc"],
    "bind9": ["openssl", "glibc"],
    "openssl": ["glibc"],
    "pam": ["glibc"],
    "util-linux": ["glibc"],
    "libxml2": ["zlib", "glibc"],
    "gnutls28": ["libgcrypt20", "glibc"],
    "krb5": ["openssl", "glibc"],
    "xz-utils": ["glibc"],
    "libwebp": ["zlib", "glibc"],
    "expat": ["glibc"],
    "ncurses": ["glibc"],
    "zlib": ["glibc"],
    "libgcrypt20": ["glibc"],
    "gcc-12": ["glibc"],
}

# Inventory packages that carry no finding of their own. A real host has
# hundreds of these, and without them nothing in the demo reaches the ten
# dependents that make a blast radius high -- so the top tier of the feature
# the tool is built around could not appear in a screenshot (Req 10.10).
_EXTRA_PACKAGES: dict[str, list[str]] = {
    "openssh-server": ["openssl", "glibc", "pam"],
    "git": ["openssl", "curl", "zlib", "glibc"],
    "python3.11": ["openssl", "zlib", "expat", "glibc"],
    "postfix": ["openssl", "glibc", "pam"],
    "rsync": ["openssl", "zlib", "glibc"],
    "wget": ["openssl", "zlib", "glibc"],
    "ldap-utils": ["openssl", "glibc"],
    "chrony": ["openssl", "glibc"],
    "apt": ["openssl", "zlib", "glibc"],
    "systemd": ["openssl", "libgcrypt20", "glibc", "pam"],
    "sudo": ["pam", "glibc"],
    "cron": ["pam", "glibc"],
}


# Scan history (Req 18). Every successfully scanned host has a baseline a week
# before its last scan, then that scan. Two hosts carry more:
#
# web-01 has three runs. Eight days ago two findings appeared and one cleared;
# its latest scan found two actively exploited ones new and cleared three. The
# cleared findings are not in the host's findings any more, which is the point:
# only the history remembers them.
#
# app-alma's latest scan was partial. It reports what it found new, and says
# nothing about what cleared, because an unreachable source is not a patch.
_WEB01_NEW_LATEST = {"CVE-2024-3094", "CVE-2023-44487"}
_WEB01_NEW_EARLIER = {"CVE-2023-6246", "CVE-2024-25062"}
# (cve_id, cvss, severity, package, kev)
_WEB01_RESOLVED_LATEST: list[
    tuple[str, float | None, Severity, str, bool | None]
] = [
    ("CVE-2024-6387",  8.1, Severity.HIGH,   "openssh-server", False),
    ("CVE-2023-48795", 5.9, Severity.MEDIUM, "openssh-client", False),
    ("CVE-2024-2961",  7.3, Severity.HIGH,   "glibc",          False),
    # A resolved finding that never had a score, so the history panel renders
    # the null case too.
    ("CVE-2024-45492", None, Severity.UNSCORED, "libtasn1-6",   None),
]
_WEB01_RESOLVED_EARLIER: list[
    tuple[str, float | None, Severity, str, bool | None]
] = [
    ("CVE-2023-4911",  7.8, Severity.HIGH,   "glibc",          True),
]
_ALMA_NEW_LATEST = {"CVE-2023-50387"}


def _run(
    machine: TargetMachine,
    at: datetime,
    *,
    finding_count: int,
    status: ScanStatus = ScanStatus.SUCCESS,
    sources_ok: bool = True,
    baseline: bool = False,
    new: list[tuple[str, float, Severity, str, bool | None]] = (),
    resolved: list[tuple[str, float, Severity, str, bool | None]] | None = (),
) -> ScanRun:
    """One seeded scan run. ``resolved=None`` is a partial run: not assessed."""
    succeeded = status is ScanStatus.SUCCESS
    compared = succeeded and not baseline
    run = ScanRun(
        id=_uid(),
        machine_id=machine.id,
        scanned_at=at,
        status=status,
        sources_ok=sources_ok,
        finding_count=finding_count if succeeded else 0,
        new_count=len(new) if compared else None,
        resolved_count=len(resolved) if compared and resolved is not None else None,
        baseline=baseline,
        sync_status=SyncStatus.PENDING_SYNC,
    )
    for kind, rows in ((FindingChange.NEW, new), (FindingChange.RESOLVED, resolved or ())):
        for cve_id, cvss, severity, package, kev in rows:
            run.changes.append(
                ScanFindingChange(
                    id=_uid(),
                    change=kind,
                    cve_id=cve_id,
                    package_identifier=_identifier("Debian", package, None),
                    severity=severity,
                    cvss_score=cvss,
                    kev_listed=kev,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
    return run


def _identifier(ecosystem: str, package: str, fixed: str | None) -> str:
    """Build a ``package_identifier`` in the format the API parses.

    Mirrors what the OSV matcher emits. If this drifts from
    ``routes._parse_fixed_version``, demo findings silently stop being
    actionable, which is exactly the sort of quiet wrongness the rest of this
    project goes out of its way to avoid -- so the shared format is asserted in
    the tests.
    """
    base = f"{ecosystem}:{package}@1.0-demo"
    return base if fixed is None else f"{base} (fixed in {fixed})"


def fleet_is_empty(session: Session) -> bool:
    """Whether the database holds no machines yet (Req 15.2).

    The guard that keeps seeding from touching a database holding real
    results.
    """
    return session.query(TargetMachine).first() is None


def seed_demo_fleet(session: Session) -> int:
    """Populate ``session`` with the demo fleet. Returns the machine count.

    Seeds a fictional fleet covering every scan status (Req 15.1, 15.5) and
    all three states of exploitation knowledge, never recording a partial
    enrichment (Req 15.6).

    Caller is responsible for the emptiness check and for committing; this
    flushes but does not commit, so it composes with a larger transaction.
    """
    machines: list[TargetMachine] = []

    for (
        hostname, platform, os_name, os_version, kernel,
        status, scanned_ago_h, sources_ok, reboot,
    ) in _HOSTS:
        machine = TargetMachine(
            id=_uid(),
            hostname=hostname,
            platform=platform,
            last_scan_status=status,
            last_scanned_at=None if scanned_ago_h is None else _ago(hours=scanned_ago_h),
            last_scan_sources_ok=sources_ok,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        session.add(machine)
        machines.append(machine)

        # Hosts that were never successfully scanned have no inventory and no
        # findings. Giving them any would contradict their own status
        # (Req 15.5). A failed attempt is still in the history.
        if status is not ScanStatus.SUCCESS:
            if scanned_ago_h is not None:
                session.add(
                    _run(machine, _ago(hours=scanned_ago_h), finding_count=0, status=status)
                )
            continue

        last_scan = _ago(hours=scanned_ago_h or 0)
        baseline_at = last_scan - timedelta(days=7)

        inventory = Inventory(
            id=_uid(),
            machine_id=machine.id,
            os_name=os_name,
            os_version=os_version,
            kernel_version=kernel,
            reboot_required=reboot,
            collected_at=_ago(hours=scanned_ago_h or 0),
            sync_status=SyncStatus.PENDING_SYNC,
        )
        session.add(inventory)

        enriched = hostname not in _UNENRICHED_HOSTS

        # Only Linux hosts are ever scanned successfully in the demo, so there is
        # one catalogue. Windows scanning is refused (Req 10.8).
        catalogue = _FINDINGS_LINUX

        # Deterministic slice per host: a different, stable subset each time, so
        # screenshots do not change between runs.
        #
        # Every host takes the whole catalogue. The README's argument is that a
        # fleet produces several hundred findings and a CVSS-sorted list gives
        # you no way to pick among them -- a demo with four findings per host
        # quietly refutes it, because four items need no ranking at all. The
        # rotation only varies which package versions and dependency shapes
        # appear, not the count.
        offset = sum(ord(c) for c in hostname) % len(catalogue)
        chosen = [catalogue[(offset + i) % len(catalogue)] for i in range(len(catalogue))]

        # The rest of the inventory, so the dependency graph has the shape a
        # real host's does. No findings hang off these.
        for extra, extra_deps in _EXTRA_PACKAGES.items():
            session.add(
                Package(
                    id=_uid(),
                    inventory_id=inventory.id,
                    name=extra,
                    version="1.0-demo",
                    ecosystem="Debian",
                    dependencies=",".join(extra_deps) or None,
                )
            )

        seen: set[str] = set()
        ecosystem = "Debian"
        if hostname == "web-01.lan":
            first_seen_by_cve = {
                **{cve: last_scan for cve in _WEB01_NEW_LATEST},
                **{cve: _ago(hours=scanned_ago_h + 24 * 8) for cve in _WEB01_NEW_EARLIER},
            }
            baseline_at = last_scan - timedelta(days=15)
        elif hostname == "app-alma.lan":
            first_seen_by_cve = {cve: last_scan for cve in _ALMA_NEW_LATEST}
        else:
            first_seen_by_cve = {}
        seeded: list[tuple[str, float, Severity, str, bool | None]] = []

        for cve_id, cvss, severity, package, fixed, kev, epss, pct in chosen:
            if cve_id in seen:
                continue
            seen.add(cve_id)

            session.add(
                Package(
                    id=_uid(),
                    inventory_id=inventory.id,
                    name=package,
                    version="1.0-demo",
                    ecosystem=ecosystem,
                    dependencies=",".join(_DEPENDENCIES.get(package, [])) or None,
                )
            )
            session.add(
                CveFinding(
                    id=_uid(),
                    machine_id=machine.id,
                    cve_id=cve_id,
                    cvss_score=cvss,
                    severity=severity,
                    source="osv" if platform is Platform.LINUX else "nvd",
                    package_identifier=_identifier(ecosystem, package, fixed),
                    # The three-valued field. An unenriched host keeps NULL
                    # across all three enrichment columns -- never False.
                    kev_listed=kev if enriched else None,
                    kev_due_date="2024-07-01" if (enriched and kev) else None,
                    epss_score=epss if enriched else None,
                    epss_percentile=pct if enriched else None,
                    first_seen_at=first_seen_by_cve.get(cve_id, baseline_at),
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
            seeded.append((cve_id, cvss, severity, package, kev if enriched else None))

        count = len(seeded)
        by_cve = {row[0]: row for row in seeded}
        session.add(_run(machine, baseline_at, finding_count=count, baseline=True))
        if hostname == "web-01.lan":
            session.add(
                _run(
                    machine,
                    _ago(hours=scanned_ago_h + 24 * 8),
                    finding_count=count + len(_WEB01_RESOLVED_LATEST) - len(_WEB01_NEW_LATEST),
                    new=[by_cve[cve] for cve in sorted(_WEB01_NEW_EARLIER)],
                    resolved=_WEB01_RESOLVED_EARLIER,
                )
            )
            session.add(
                _run(
                    machine,
                    last_scan,
                    finding_count=count,
                    new=[by_cve[cve] for cve in sorted(_WEB01_NEW_LATEST)],
                    resolved=_WEB01_RESOLVED_LATEST,
                )
            )
        elif hostname == "app-alma.lan":
            session.add(
                _run(
                    machine,
                    last_scan,
                    finding_count=count,
                    sources_ok=False,
                    new=[by_cve[cve] for cve in sorted(_ALMA_NEW_LATEST)],
                    resolved=None,
                )
            )
        elif hostname != "nas-01.lan":
            # nas-01's only run is its month-old baseline.
            session.add(_run(machine, last_scan, finding_count=count))

    # Pins are keyed by address, not by machine, so they are seeded on their own
    # rather than inside the host loop (Req 17.6).
    for hostname, port, key_type, fingerprint, first_seen_h in _HOST_KEYS:
        session.add(
            SshHostKey(
                id=_uid(),
                hostname=hostname,
                port=port,
                key_type=key_type,
                # Not a real key: the demo never connects anywhere, and the
                # dashboard only ever shows the fingerprint.
                key_base64="AAAAC3NzaC1lZDI1NTE5AAAAIDEMOkeyDEMOkeyDEMOkeyDEMOkeyDEMO",
                fingerprint_sha256=fingerprint,
                first_seen_at=_ago(hours=first_seen_h),
                last_seen_at=_ago(hours=6),
            )
        )

    _seed_intel_cache(session)

    session.flush()
    return len(machines)


def _seed_intel_cache(session: Session) -> None:
    """Give the demo a fictional KEV and EPSS cache of its own (Req 15.6).

    Derived from ``_FINDINGS_LINUX`` rather than written out again, so the cache
    and the findings cannot disagree: the catalogue lists exactly the CVEs the
    fleet carries as exploited, and the score set carries exactly the
    probabilities its findings were given.

    The demo needs this because the dashboard gates the *display* of
    exploitation on feed health, not on the findings: with no usable feed the
    "actively exploited" triage card renders an em dash rather than a count. Up
    to 0.8.9 a visitor got that dash until they pressed **Refresh intel**, which
    downloaded the real catalogue and reapplied it over this fixture --
    destroying the unchecked findings above, permanently, since nothing
    re-seeds. Shipping the cache instead means the demo is right on first paint
    and never needs the network at all.

    Deliberately not a copy of the real catalogues. These are the four CVEs this
    fictional fleet treats as exploited; what CISA lists today is a question
    about the real world, which a demo has no business answering.
    """
    kev_cves = [cve for cve, *_rest, kev, _s, _p in _FINDINGS_LINUX if kev is True]
    for cve_id in kev_cves:
        session.add(
            KevEntry(
                cve_id=cve_id,
                # A date far enough out that the demo does not drift into
                # showing every federal deadline as overdue.
                due_date=(_now() + timedelta(days=21)).date().isoformat(),
            )
        )

    scored = [
        (cve, score, percentile)
        for cve, *_rest, _kev, score, percentile in _FINDINGS_LINUX
        if score is not None and percentile is not None
    ]
    for cve_id, score, percentile in scored:
        session.add(
            EpssScore(
                cve_id=cve_id,
                score=score,
                percentile=percentile,
                scored_at=_now(),
            )
        )

    _stamp_demo_feeds(session, kev_count=len(kev_cves), epss_count=len(scored))


def _stamp_demo_feeds(session: Session, *, kev_count: int, epss_count: int) -> None:
    """Record both demo feeds as refreshed just now.

    Split out because it runs on every demo start-up, not only at seeding. A
    cache is stale after 48 hours (``FindingEnricher._is_stale``), and seeding
    happens once, so a long-lived public demo would otherwise start reporting
    degraded enrichment after two days and stop matching its own screenshots.
    Re-stamping costs one row per feed and touches no finding.
    """
    now = _now()
    for feed_name, count in (("kev", kev_count), ("epss", epss_count)):
        row = session.get(FeedRefresh, feed_name)
        if row is None:
            row = FeedRefresh(feed_name=feed_name)
            session.add(row)
        row.last_status = FeedStatus.OK
        row.last_refreshed_at = now
        row.last_attempted_at = now
        row.record_count = count
        row.error_detail = None


def refresh_demo_feed_timestamps(session: Session) -> bool:
    """Re-stamp the demo's seeded feeds, if this database has them.

    Called on every start-up in demo mode. Returns whether anything was
    stamped, so a database that predates the seeded cache -- or one seeded by
    an older release -- is left alone rather than being given feed rows with no
    catalogue behind them, which would report a usable feed holding nothing.
    """
    kev_count = session.query(KevEntry).count()
    if kev_count == 0:
        return False
    _stamp_demo_feeds(
        session, kev_count=kev_count, epss_count=session.query(EpssScore).count()
    )
    return True
