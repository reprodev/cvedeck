# Design Document

## Overview

The CveDeck is an agentless vulnerability management system. A central Python/FastAPI server remotely scans Windows and Linux hosts (SSH via `paramiko` for Linux, WinRM via `pywinrm` for Windows), collects OS and installed-software inventory, and matches that inventory against public vulnerability data (NVD for OS-level CVEs and CVSS scoring, OSV.dev for package-level advisories). Findings, inventory, and manually maintained remediation records are stored in a local database and synchronized to an online database. A React/TypeScript dashboard presents machines, severity-grouped counts, severity filters, and per-machine drill-down views. An outward-facing JSON API exposes the same data to external consumers.

All operations in this version are manually initiated. The data model is deliberately structured so a future dependency/application-path visualization can be added without restructuring stored data: every CVE finding can carry a package identifier and a dependency-path association that persists locally and survives synchronization.

### Design Goals

- Agentless, read-only collection from targets (no software installed on targets).
- Fault isolation: one target's connection/auth failure never aborts the batch.
- Graceful degradation when a public data source is unreachable.
- Durable synchronization: local is the source of truth; online converges eventually.
- Forward-compatible schema: package identifiers and dependency-path associations are first-class from day one.

### Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Backend API | Python 3.11+, FastAPI, Pydantic | Async I/O for concurrent scans; Pydantic gives structured JSON responses (Req 6.5). |
| Linux collection | `paramiko` (SSH) | Agentless remote command execution. |
| Windows collection | `pywinrm` (WinRM/PowerShell remoting) | Agentless remote command execution. |
| Persistence | SQLAlchemy ORM over a relational DB (local + online) | Identical schema on both sides simplifies sync (Req 5.5). |
| Vulnerability data | NVD REST API, OSV.dev API | OS-level CVE/CVSS and package-level advisories. |
| Frontend | React + TypeScript | Dashboard, filters, drill-down. |

## Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │              Central Server                  │
                         │                                              │
 External Consumers ───► │  Backend_API (FastAPI)                       │
                         │     │                                        │
                         │     ▼                                        │
 Web_Dashboard  ───────► │  Service Layer                               │
 (React/TS)              │     ├── ScanService ── Scanner_Engine        │
                         │     │        ├── LinuxCollector (paramiko) ──┼──► Linux Target_Machine (SSH)
                         │     │        └── WindowsCollector (pywinrm) ─┼──► Windows Target_Machine (WinRM)
                         │     │        └── Matcher ── NvdClient ────────┼──► NVD
                         │     │                    └─ OsvClient ────────┼──► OSV.dev
                         │     ├── RemediationService                    │
                         │     └── SyncService ─────────────────────────┼──► Online_Database
                         │              │                               │
                         │              ▼                               │
                         │        Local_Database (SQLAlchemy)           │
                         └─────────────────────────────────────────────┘
```

### Component Responsibilities

- **Scanner_Engine** orchestrates a scan across a batch of targets. It delegates collection to the platform-specific collector, delegates matching to the Matcher, records per-target status, and persists results. It isolates faults per target so the batch continues (Req 1.4, 1.5).
- **Collectors** (`LinuxCollector`, `WindowsCollector`) issue read-only inventory commands over SSH/WinRM and normalize the results into an `Inventory` structure. They install nothing on the target (Req 1.3).
- **Matcher** takes an `Inventory` plus data-source clients and produces `Finding` records. OS inventory → NVD; software inventory → OSV. It derives severity from CVSS and records data-source-unavailable status when a source is unreachable (Req 2).
- **Persistence layer** stores inventory, findings, and remediation records in the Local_Database and exposes read queries for the dashboard and API (Req 5.1).
- **RemediationService** creates and updates manually maintained remediation records (Req 4).
- **SyncService** propagates local writes to the Online_Database, marks unsynced items pending on failure, and reconciles pending items when connectivity returns (Req 5.2–5.4, 7.3).
- **Backend_API** exposes machines, per-machine CVEs, severity filtering, and structured JSON responses (Req 6).
- **Web_Dashboard** renders the machine list with severity-grouped counts, severity filters, and drill-down with remediation status (Req 3, 4.4).

### Scan Flow

1. Administrator initiates a scan for a set of targets (manual trigger).
2. For each target, the engine selects a collector by platform and attempts to connect.
   - Connection failure → record `CONNECTION_FAILURE`, continue to next target (Req 1.4).
   - Auth failure → record `AUTH_FAILURE`, continue (Req 1.5).
3. On success, collect inventory (read-only) and persist it (Req 1.6).
4. Match inventory against NVD (OS) and OSV (software). Unreachable source → record `DATA_SOURCE_UNAVAILABLE` and continue with the reachable source (Req 2.5).
5. Persist findings; enqueue writes for synchronization.
6. SyncService propagates to the Online_Database; on failure, items stay `PENDING_SYNC` (Req 5.3).

## Components and Interfaces

Interfaces below use Python type hints (backend) and TypeScript (frontend).

### Enumerations

```python
class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ScanStatus(str, Enum):
    SUCCESS = "success"
    CONNECTION_FAILURE = "connection_failure"
    AUTH_FAILURE = "auth_failure"

class SourceStatus(str, Enum):
    OK = "ok"
    DATA_SOURCE_UNAVAILABLE = "data_source_unavailable"

class SyncStatus(str, Enum):
    SYNCED = "synced"
    PENDING_SYNC = "pending_sync"

class RemediationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
```

### Collector Interface

```python
class InventoryCollector(Protocol):
    def collect(self, target: TargetMachine, credentials: Credentials) -> Inventory:
        """Connect read-only and return normalized inventory.
        Raises ConnectionError on unreachable host, AuthError on auth failure."""
```

`LinuxCollector` runs read-only commands (e.g. OS release files, package manager query) over `paramiko`. `WindowsCollector` runs read-only PowerShell (e.g. OS build, installed products) over `pywinrm`. Neither writes to the target.

### Scanner Engine

```python
class ScannerEngine:
    def scan(self, targets: list[TargetMachine]) -> ScanResult:
        """Scan each target independently. A per-target failure is recorded
        as a ScanStatus and never aborts the remaining targets."""

    def _scan_one(self, target: TargetMachine) -> MachineScan:
        """Connect, collect, match, persist. Returns the per-target outcome
        including status and findings."""
```

### Matcher and Data-Source Clients

```python
class NvdClient(Protocol):
    def match_os(self, os_info: OsInfo) -> list[RawCve]: ...

class OsvClient(Protocol):
    def match_packages(self, packages: list[Package]) -> list[RawAdvisory]: ...

class Matcher:
    def match(self, inventory: Inventory,
              nvd: NvdClient | None, osv: OsvClient | None
              ) -> MatchResult:
        """Produce findings from reachable sources. A None (unreachable)
        client yields DATA_SOURCE_UNAVAILABLE and is skipped."""

def derive_severity(cvss_score: float) -> Severity:
    """Total function mapping a CVSS base score to a Severity band."""
```

Severity bands (CVSS v3.x):

| CVSS score | Severity |
|------------|----------|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9  | High     |
| 4.0 – 6.9  | Medium   |
| 0.0 – 3.9  | Low      |

### Remediation Service

```python
class RemediationService:
    def add(self, machine_id: str, cve_id: str,
            status: RemediationStatus, note: str) -> RemediationRecord: ...
    def update(self, record_id: str,
               status: RemediationStatus, note: str) -> RemediationRecord: ...
```

Remediation is only ever invoked through these explicit administrator-initiated calls; there is no scheduler or automated trigger (Req 4.5).

### Sync Service

```python
class SyncService:
    def enqueue(self, entity: SyncableEntity) -> None:
        """Mark an entity PENDING_SYNC in the local store."""

    def sync(self) -> SyncReport:
        """Propagate all PENDING_SYNC entities to the online database.
        On online-unreachable, entities remain PENDING_SYNC.
        On success, entities become SYNCED and online converges to local."""
```

### Backend API

| Method | Path | Description | Requirement |
|--------|------|-------------|-------------|
| GET | `/api/machines` | List scanned machines with severity-grouped CVE counts | 6.1, 3.2 |
| GET | `/api/machines/{machine_id}` | Machine detail; 404 if unknown | 6.4 |
| GET | `/api/machines/{machine_id}/cves?severity=` | CVEs for a machine, optional severity filter | 6.2, 6.3 |
| GET | `/api/cves?severity=` | All CVEs, optional severity filter | 3.3, 6.3 |
| POST | `/api/machines/{machine_id}/cves/{cve_id}/remediation` | Add remediation record | 4.1 |
| PUT | `/api/remediation/{record_id}` | Update remediation record | 4.3 |
| POST | `/api/scans` | Manually initiate a scan | 1.1, 1.2 |
| POST | `/api/scans/test-connection` | Pre-flight connectivity & credential validation | 1.1, 9.1 |
| POST | `/api/discovery/sweep` | Zero-touch ICMP/TCP/banner network asset sweep | 8.1, 8.2 |
| POST | `/api/discovery/enroll` | Enroll discovered network hosts into fleet roster | 8.4 |
| POST | `/api/sync` | Manually trigger synchronization | 5.2 |
| GET | `/api/health` | Liveness probe for container orchestrators and reverse proxies | operational |

All responses are Pydantic models serialized to JSON (Req 6.5). Unknown machine ids return HTTP 404 (Req 6.4).

`/api/health` is operational rather than requirement-derived: it exists so a
deployment can be health-checked, and carries no domain data. `POST /api/sync`
returns HTTP 503 when the deployment has configured no Online_Database, so an
unconfigured optional feature reports itself as unavailable rather than as a
server error.

Example response models:

```python
class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class MachineSummary(BaseModel):
    machine_id: str
    hostname: str
    platform: Platform
    last_scan_status: ScanStatus
    cve_counts: SeverityCounts

class CveFindingOut(BaseModel):
    cve_id: str
    severity: Severity
    cvss_score: float
    package_identifier: str | None      # present for OSV-sourced findings
    remediation_status: RemediationStatus | None
    remediation_record_id: str | None   # lets a client PUT an update (Req 4.3)
    remediation_note: str | None        # free-text detail (Req 4.2)
```

The three `remediation_*` fields are all `None` until a remediation record
exists for that CVE on that machine. `remediation_record_id` is what makes
`PUT /api/remediation/{record_id}` reachable from a read: without it a client
could only ever add records, never update the one it just created.

### Frontend Interfaces

```typescript
interface MachineSummary {
  machineId: string;
  hostname: string;
  platform: "linux" | "windows";
  lastScanStatus: string;
  cveCounts: { critical: number; high: number; medium: number; low: number };
}

interface CveFinding {
  cveId: string;
  severity: "critical" | "high" | "medium" | "low";
  cvssScore: number;
  packageIdentifier: string | null;
  remediationStatus: string | null;
  remediationRecordId: string | null;
  remediationNote: string | null;
}

interface ScanTargetInput {
  id: string;                 // the hostname, so a re-scan updates one machine
  hostname: string;
  platform: "linux" | "windows";
  username: string;
  password: string;           // held for the request only, never stored
}

interface ScanOutcome {
  machineId: string;
  status: string;             // success | connection_failure | auth_failure
  findingCount: number;
}

// Pure client-side helpers (unit/property tested)
function filterBySeverity(findings: CveFinding[], severity: Severity): CveFinding[];
function groupCountsBySeverity(findings: CveFinding[]): SeverityCounts;
```

Views: `ScanFormView` (target + credentials, initiating a scan and reporting its per-target outcome), `MachineListView` (list + severity-grouped counts + severity filter), `MachineDrillDownView` (per-CVE id, severity, CVSS score, current remediation status, and the controls to add or update a remediation record).

A scan is the only way a machine enters the system: `POST /api/scans` registers each target before scanning it, and there is no separate create-machine endpoint. The scan form therefore doubles as the machine-registration surface, and uses the hostname as the machine id so re-scanning a host updates its existing row.

## Data Models

The schema is identical on the Local_Database and Online_Database so synchronization is a direct row propagation (Req 5.5). Every syncable row carries a `sync_status`.

```python
class TargetMachine(Base):
    id: str                     # primary key
    hostname: str
    platform: Platform
    last_scan_status: ScanStatus
    last_scanned_at: datetime | None
    sync_status: SyncStatus

class Inventory(Base):
    id: str
    machine_id: str             # FK -> TargetMachine
    os_name: str
    os_version: str
    collected_at: datetime
    sync_status: SyncStatus

class Package(Base):
    id: str
    inventory_id: str           # FK -> Inventory
    name: str
    version: str
    ecosystem: str | None       # e.g. PyPI, npm, deb (for OSV matching)

class CveFinding(Base):
    id: str
    machine_id: str             # FK -> TargetMachine  (CVE ↔ machine association)
    cve_id: str
    cvss_score: float
    severity: Severity
    source: str                 # "nvd" | "osv"
    package_identifier: str | None   # set for OSV/package-level findings (Req 7.1)
    dependency_path_id: str | None   # FK -> DependencyPath (Req 5.5, 7.2)
    sync_status: SyncStatus

class DependencyPath(Base):
    """Future dependency/application-path visualization anchor.
    Present in the schema now so the association survives sync (Req 7.2, 7.3)."""
    id: str
    machine_id: str
    package_identifier: str | None
    path_expression: str | None      # e.g. app -> libA -> libB
    parent_path_id: str | None       # self-reference for dependency chains
    sync_status: SyncStatus

class RemediationRecord(Base):
    id: str
    machine_id: str             # FK -> TargetMachine
    cve_id: str
    status: RemediationStatus
    note: str
    updated_at: datetime
    sync_status: SyncStatus
```

The `CveFinding.dependency_path_id` → `DependencyPath` relationship, plus `DependencyPath.parent_path_id` self-reference, lets a CVE be linked to a chain of dependencies and application paths. This is stored now and is inert until the future visualization consumes it; no restructuring is required to add that feature (Req 7).

## Error Handling

| Condition | Handling | Requirement |
|-----------|----------|-------------|
| Target unreachable | Record `CONNECTION_FAILURE` for that target, continue batch | 1.4 |
| Target auth fails | Record `AUTH_FAILURE` for that target, continue batch | 1.5 |
| NVD or OSV unreachable | Record `DATA_SOURCE_UNAVAILABLE`, complete matching against the reachable source | 2.5 |
| Online DB unreachable during sync | Retain data locally, mark `PENDING_SYNC` | 5.3 |
| Online DB reachable after outage | Propagate all pending items on next sync; online converges | 5.4 |
| API request for unknown machine | HTTP 404 not-found | 6.4 |
| Malformed API request | HTTP 422 (Pydantic validation) | 6.5 |

Per-target scanning runs in isolation (try/except around `_scan_one`) so a raised `ConnectionError`/`AuthError` is captured as a status rather than propagating and aborting the batch.

## Testing Strategy

A dual approach is used. Property-based tests (minimum 100 iterations each, tagged with the feature name and property number) verify universal behavior of the pure/logic layers using mocked collectors, data-source clients, and an in-memory online store. Example-based and integration tests cover UI rendering, API contracts, error cases, and the SSH/WinRM I/O layers (which are not amenable to property testing).

- **Integration**: Linux SSH collection (1.1), Windows WinRM collection (1.2), read-only command review (1.3), API machine-list read (6.1), 404 for unknown machine (6.4), JSON schema validation (6.5).
- **Example**: dashboard list rendering (3.1), drill-down rendering and remediation status display (3.4, 4.4), remediation field capture (4.2).
- **Smoke**: absence of automated remediation triggers (4.5).
- **Property**: the properties below.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Per-target fault isolation

*For any* batch of target machines where each target is assigned a random outcome (reachable, unreachable, or auth-failure), scanning the batch SHALL record `CONNECTION_FAILURE` for every unreachable target, `AUTH_FAILURE` for every auth-failing target, and SHALL still produce a completed scan result for every reachable target.

**Validates: Requirements 1.4, 1.5**

### Property 2: Inventory persistence round-trip

*For any* collected inventory for a machine, persisting it to the Local_Database and then reading it back SHALL yield an inventory equivalent to the one persisted.

**Validates: Requirements 1.6, 5.1**

### Property 3: Matching correctness and finding completeness

*For any* inventory and in-memory NVD/OSV fixtures, the Matcher SHALL produce exactly the findings whose applicability criteria the inventory satisfies, and every produced finding SHALL carry a CVE identifier, a CVSS score, and the affected machine reference; additionally every OSV-sourced (package-level) finding SHALL carry a package identifier.

**Validates: Requirements 2.1, 2.2, 2.3, 7.1**

### Property 4: Severity derivation is total and correct

*For any* CVSS score in the range 0.0 to 10.0, `derive_severity` SHALL return exactly one Severity level matching the documented CVSS band boundaries (0.0–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical).

**Validates: Requirements 2.4**

### Property 5: Graceful degradation on unavailable data sources

*For any* combination of NVD and OSV availability, matching SHALL record `DATA_SOURCE_UNAVAILABLE` for each unreachable source while still producing findings from every reachable source.

**Validates: Requirements 2.5**

### Property 6: Severity-grouped counts are accurate

*For any* set of findings for a machine, the severity-grouped counts SHALL equal the actual tally of findings per severity level, and the sum of the four counts SHALL equal the total number of findings.

**Validates: Requirements 3.2**

### Property 7: Severity filtering is sound and complete

*For any* set of findings and any selected Severity_Level, filtering (whether applied in the dashboard or via the API) SHALL return every finding with that severity and no finding with any other severity.

**Validates: Requirements 3.3, 6.3**

### Property 8: Finding rendering and serialization completeness

*For any* finding presented in the drill-down view or serialized in an API response, the output SHALL include the CVE identifier, the Severity_Level, and the CVSS_Score.

**Validates: Requirements 3.5, 6.2**

### Property 9: Remediation persistence reflects last write

*For any* remediation record and any subsequent update to it, reading the record back from the Local_Database SHALL reflect the most recently written status and note.

**Validates: Requirements 4.1, 4.3**

### Property 10: Durable synchronization convergence with field preservation

*For any* set of local writes, if the Online_Database is unreachable then those items SHALL remain in the Local_Database marked `PENDING_SYNC`; and once the Online_Database becomes reachable and synchronization runs, the Online_Database SHALL converge to the Local_Database with no items left pending, preserving each finding's package identifier and dependency-path association.

**Validates: Requirements 5.2, 5.3, 5.4, 7.3**

### Property 11: Dependency-path association round-trip

*For any* CVE finding that carries a dependency-path association, persisting and reading it back SHALL preserve the association linking the CVE to its software dependencies and application path on the target machine.

**Validates: Requirements 5.5, 7.2**

### Property 12: Every API route outside the public allowlist refuses an anonymous caller

*For any* route the application serves under `/api`, other than the health check and the auth state, setup, sign-in and sign-out routes, a request carrying neither a current session nor a current API token SHALL be refused with HTTP 401 while login is required. The route set is discovered from the application itself, so a route added later is covered without being listed.

**Validates: Requirements 16.1**


---

## Addendum: design changes after the initial implementation

Covers Requirements 10-16 (see requirements.md addendum).

### Scan result reporting

`MatchResult` already carried `nvd_status` / `osv_status`; that status now
propagates to `MachineScan.unavailable_sources`, is persisted as
`target_machines.last_scan_sources_ok`, and is serialized on both
`MachineScanOut` and `MachineSummary`.

Only **configured** sources count as unavailable. NVD ships disabled by default
(`CVEDECK_NVD_ENABLED`), so counting its absence would mark every scan on a
deployment that never opted in as partial, and train operators to ignore the
warning -- which would destroy the value of the signal. Absent capability is a
documented limitation; an outage is a per-scan anomaly.

`ScannerEngine`'s `record_status` hook takes the whole `MachineScan` rather than
a bare `ScanStatus`, so it can persist the timestamp and source health together.

`ScanStatus.NEVER_SCANNED` is the state of an enrolled-but-unscanned machine.
Enrollment previously stamped `CONNECTION_FAILURE`, which rendered as a failure
for a connection nobody had attempted.

### Credential resolution

`app/api/credentials.py:resolve_credentials` is the single place a scan's
credentials are decided, used by both `POST /api/scans` and
`POST /api/scans/test-connection` so pre-flight and the real scan can never
disagree. Precedence: supplied password, supplied private key, then the
server-managed key (Linux only).

`Credentials` enforces exactly one secret. Accepting both would delegate the
choice to paramiko's argument precedence rather than to an explicit decision.

Keys are parsed by `parse_private_key` from an in-memory buffer, before an SSH
client is allocated, so a malformed key or wrong passphrase is reported as such
rather than surfacing later as a connection failure.

### Collector

The Linux collector issues two commands rather than three: `/etc/os-release`,
the running kernel, and the reboot-required probe share one round trip, split on
a marker. Each SSH round trip pays full network latency.

The read-only invariant is enforced by a test treating any `>` other than
`2>/dev/null` as a write, so the probe captures output into a shell variable
instead of redirecting it. The guard is deliberately not loosened.

### Ecosystem resolution

OSV's `/querybatch` rejects an entire batch on one unrecognized ecosystem name,
and the client's error path falls back to per-item queries -- so an invalid name
silently disables batching rather than failing visibly. `_ALL_LINUX_ECOSYSTEMS`
therefore contains only names verified against the live API, and distributions
without their own tracker (Oracle Linux, Amazon Linux, Fedora, Arch) map onto
the upstream they derive from. `Red Hat` is queried unversioned: OSV accepts
`Red Hat:9` and returns nothing for it.

### Migrations

Alembic replaces `Base.metadata.create_all` as the schema story.
`migrations_runtime.upgrade_to_head` runs on first engine use and handles three
cases: an empty database is created from metadata and stamped `head`; a
pre-Alembic database (tables, no `alembic_version`) is stamped at the baseline
and migrated forward; a managed database is upgraded. SQLAlchemy persists enum
*names*, which data migrations touching enum columns must account for.

### Frontend structure

Logic that had been duplicated across views now lives in shared modules:
`lib/labels.ts`, `lib/remediation.ts`, `lib/useClipboard.ts`, `lib/platform.ts`,
`lib/useSort.ts`, `lib/a11y.ts`, `components/Toast.tsx`, `components/Modal.tsx`,
`components/EmptyState.tsx`.

Two of these merged implementations that had **disagreed**: `inferPlatform`
classified the same host differently depending on which view asked, and
remediation tooling was chosen by unanchored substring matching against a
package identifier rather than from the machine.

`src/api/client.ts` remains the sole owner of snake_case/camelCase mapping.
Credential fields on scan and test-connection requests are mapped explicitly
rather than spread, because a spread would send camelCase keys the backend
ignores silently.

### Demonstration mode

`CVEDECK_DEMO_MODE` (read through `app/config.py`, like every other setting)
turns an instance into a showcase. It has two halves, and the second is the
important one.

**Seeding.** `app/data/demo_seed.py` holds a fixture fleet and a Linux and a
Windows finding catalogue. It is invoked once from `get_engine()` in
`app/api/dependencies.py`, after migrations, guarded on the fleet being empty —
so a restarting container does not accumulate duplicates and pointing the flag
at a database with real results in it is a no-op. A seeding failure is logged
and swallowed: an empty dashboard is a better outcome than an API that will not
start.

The fixture mirrors `frontend/design/build.py`, which was assembled to exercise
the states that matter rather than a tidy list of healthy hosts. Two constraints
on its content are load-bearing rather than cosmetic:

- Findings must cover all three values of `kev_listed`, and an unenriched
  finding must be NULL across *every* enrichment column. A demo that showed a
  confident "0 actively exploited" would be advertising precisely the silent
  false negative the enrichment invariant exists to prevent.
- Package identifiers are constructed in the format the API parses back
  (`<ecosystem>:<name>@<version> (fixed in <fixed>)`), rather than by setting a
  field — there is no `fixed_version` column; `routes._parse_fixed_version`
  derives it. If the seed's format drifts from that parser, every demo finding
  silently reclassifies as "Pending Vendor Patch" with nothing failing, so the
  coupling is asserted directly in `tests/test_demo_seed.py`.

**Refusal.** Every route that opens a connection to a user-supplied address —
`POST /api/scans`, `POST /api/discovery/sweep`, `POST /api/scans/test-connection`
— is disabled with HTTP 403. Without this a public instance is an SSH/WinRM
client and port scanner that any visitor can aim at any address, sourced from
the operator's IP rather than the visitor's.

The guard is attached as a route-level dependency
(`dependencies=[Depends(_demo_guard(...))]`), not as a check inside the handler.
FastAPI resolves a handler's own parameter dependencies before its body runs, so
a body check allowed `get_scanner_engine` to be constructed first and surfaced
its `NotImplementedError` instead of the 403. Decorator-level dependencies are
inserted ahead of the handler's own and therefore run first.

The state is reported at `GET /api/health` as `capabilities.demo_mode`, which
the dashboard uses to show a banner.

### Frontend design system

`src/index.css` is still the only stylesheet, and now carries full token scales
for type, spacing, radius, shadow and scrim alongside the existing colour
tokens. The scales exist because the stylesheet had drifted to 25 distinct font
sizes across 87 declarations and 20 radii that bypassed the 2/3/4px tokens; the
values were individually defensible and collectively incoherent.

Colour is expressed as `light-dark()` pairs defined once in `:root`, with three
small `color-scheme` rules — bare `:root`, a guarded `prefers-color-scheme`
query, and `:root[data-theme]` — deciding which half resolves. This replaced two
byte-identical 55-line palette blocks that every light-theme change had to touch
twice. Declaring `color-scheme` also fixed native scrollbars and form controls,
which rendered light while the application rendered dark.

`components/Icon.tsx` inlines its SVG rather than depending on an icon package
or a CDN, for the two reasons that vendored the fonts: a scanner runs on
isolated networks where a CDN request never resolves, and a dashboard load
should not report the IP of a machine running a vulnerability scanner to a third
party. Icons are `aria-hidden` and sized in `em`, coloured by `currentColor`, so
they inherit type scale, theme, and hover state from their context. They
replaced emoji, which rendered as three different drawings across operating
systems, could not respond to the theme, and were announced by screen readers
alongside the labels they sat beside.

One palette rule is enforced in the markup as well as the stylesheet: red is
reserved for exploitation. The "Actively exploited" triage card carries
`data-tone="exploit"`, distinct from the amber severity ramp used by the cards
beside it — and drops to a neutral tone when the KEV feed has never loaded,
because a zero there is an absence of an answer rather than an all-clear.

### Access control

Login is built in and on by default (Req 16). The shape follows from who runs
CveDeck: one person, one container, often on a home network, frequently without
a reverse proxy.

- **Protected by default.** `require_principal` (`app/auth/dependencies.py`) is
  attached to whole routers when `create_app` includes them, never to single
  routes. The public allowlist is five routes and lives in
  `tests/test_auth_enforcement.py`, which discovers every route from the
  application and asserts each one outside the list returns 401 (Property 12).
- **Two credentials.** A browser gets an `HttpOnly`, `SameSite=Strict` session
  cookie; a script sends `Authorization: Bearer cvd_...`. Both are 32 random
  bytes stored as SHA-256. Because a browser attaches cookies automatically, a
  cookie-authenticated request that changes state must also carry an `Origin`
  (or `Referer`) matching the request host. Tokens are exempt, and cannot manage
  the account.
- **Passwords** are hashed with the standard library's scrypt (n=2^15, r=8, p=1),
  in a self-describing `scrypt$n$r$p$salt$hash` form so the cost can rise later.
  An unknown username still spends one verification.
- **First run** needs no default password. With no account, start-up issues a
  setup code, stores its hash in `auth_setup`, and prints it to the log; the
  dashboard's setup page asks for it. Whoever can read the container logs can
  already read the database, so the log is the right trust boundary.
  `CVEDECK_ADMIN_USERNAME` / `CVEDECK_ADMIN_PASSWORD` pre-create the account
  instead, and `cvedeck-admin` recovers a lost password from a shell.
- **State.** Accounts, sessions, tokens and the setup code are four tables
  outside `_SYNC_ORDER`: credentials never leave the instance. Failed-attempt
  throttling is in memory, which fits the single-worker process.
- **Opting out.** `CVEDECK_AUTH=disabled` serves everything without login, for
  deployments behind an authenticating proxy, and logs a warning on every
  start. Anything else, including a typo, leaves login on. Demo mode is open.
- **Frontend.** `AuthGate` asks `GET /api/auth/state` before rendering and
  shows the setup page, the sign-in page, or the dashboard. The API client
  reports any 401 so an expired session returns to sign-in. Account settings
  (password, tokens) live at `#/settings`.
