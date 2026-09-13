# Requirements Document

## Introduction

The CveDeck is a vulnerability management tool that scans Windows and Linux machines for known Common Vulnerabilities and Exposures (CVEs) and presents the results on a web dashboard. Scanning is agentless, performed remotely from a central server using SSH for Linux hosts and WinRM/PowerShell remoting for Windows hosts. Collected inventory is matched against public vulnerability data sources (NVD for OS-level CVEs and CVSS severity scoring, and OSV.dev for software and package-level matching). Results are stored in both a local database and an online database kept in sync, enabling manual remediation tracking. The system exposes its own outward-facing API so external applications can consume scan and vulnerability data. All operations in the first version are initiated manually. The data model is structured to accommodate a future capability for visualizing software dependencies and the application paths where vulnerabilities are found.

## Glossary

- **CVE_Scanner_System**: The complete tool, comprising the scanner engine, backend API, databases, and web dashboard.
- **Scanner_Engine**: The backend component that connects to target machines, collects inventory, and matches it against vulnerability data.
- **Backend_API**: The outward-facing FastAPI service that exposes scan results and vulnerability data to external consumers.
- **Web_Dashboard**: The React/TypeScript frontend that displays machines, vulnerabilities, severity filters, and drill-down views.
- **Target_Machine**: A Windows or Linux host that the CVE_Scanner_System scans remotely.
- **CVE**: A Common Vulnerabilities and Exposures entry identifying a specific known vulnerability.
- **CVSS_Score**: The Common Vulnerability Scoring System numeric score used to derive a severity level.
- **Severity_Level**: One of the categories Critical, High, Medium, or Low, derived from the CVSS_Score.
- **NVD**: The National Vulnerability Database, a public source for OS-level CVEs and CVSS severity scoring.
- **OSV_Source**: The OSV.dev public database, used for software and package-level vulnerability matching.
- **Local_Database**: The database instance residing on the central server.
- **Online_Database**: The remote database instance kept in sync with the Local_Database.
- **Sync_Process**: The logic that reconciles data between the Local_Database and the Online_Database.
- **Remediation_Record**: A manually maintained note tracking the remediation status of a vulnerability on a machine.
- **Inventory**: The collected set of operating system details and installed software/packages for a Target_Machine.
- **Scan**: A single execution of the Scanner_Engine against one or more Target_Machines.
- **Dependency_Path**: A future data relationship describing how software dependencies and application paths link to a vulnerability.

## Requirements

### Requirement 1: Agentless Machine Scanning

**User Story:** As a security administrator, I want to scan Windows and Linux machines remotely without installing agents, so that I can assess vulnerabilities without modifying the target endpoints.

#### Acceptance Criteria

1. WHEN an administrator initiates a Scan against a Linux Target_Machine, THE Scanner_Engine SHALL connect to the Target_Machine over SSH and collect the Inventory.
2. WHEN an administrator initiates a Scan against a Windows Target_Machine, THE Scanner_Engine SHALL connect to the Target_Machine over WinRM and collect the Inventory.
   *Deferred as of 0.6.0.* WinRM collection is implemented, but collected Windows
   inventory cannot yet be matched against vulnerability data, so a Windows scan
   would report zero findings for an unassessed host. Until Windows matching
   exists, Windows scans are refused under Requirement 10.8.
3. THE Scanner_Engine SHALL collect the Inventory without installing software on the Target_Machine.
4. IF the Scanner_Engine cannot establish a connection to a Target_Machine, THEN THE Scanner_Engine SHALL record a connection failure status for that Target_Machine and continue scanning remaining Target_Machines.
5. IF authentication to a Target_Machine fails, THEN THE Scanner_Engine SHALL record an authentication failure status for that Target_Machine.
6. WHEN a Scan completes for a Target_Machine, THE Scanner_Engine SHALL persist the collected Inventory to the Local_Database.

### Requirement 2: CVE Matching from Public Data Sources

**User Story:** As a security administrator, I want collected inventory matched against public vulnerability databases, so that I can identify which CVEs affect each machine.

#### Acceptance Criteria

1. WHEN the Scanner_Engine processes the operating system Inventory of a Target_Machine, THE Scanner_Engine SHALL match the Inventory against NVD to identify applicable CVEs.
2. WHEN the Scanner_Engine processes the installed software Inventory of a Target_Machine, THE Scanner_Engine SHALL match the Inventory against OSV_Source to identify applicable CVEs.
3. WHEN a CVE is identified for a Target_Machine, THE Scanner_Engine SHALL record the CVE identifier, the associated CVSS_Score, and the affected Target_Machine.
4. WHEN a CVE has an associated CVSS_Score, THE Scanner_Engine SHALL derive the Severity_Level as Critical, High, Medium, or Low from the CVSS_Score.
5. IF a public data source is unreachable during a Scan, THEN THE Scanner_Engine SHALL record a data-source-unavailable status and complete matching against any reachable data source.

### Requirement 3: Machine List and Severity Filtering

**User Story:** As a security administrator, I want to view a list of scanned machines and filter vulnerabilities by severity, so that I can prioritize the most critical issues.

#### Acceptance Criteria

1. WHEN an administrator opens the Web_Dashboard, THE Web_Dashboard SHALL display a list of scanned Target_Machines.
2. WHERE a Target_Machine is displayed in the list, THE Web_Dashboard SHALL display the count of identified CVEs for that Target_Machine grouped by Severity_Level.
3. WHEN an administrator selects a Severity_Level filter of Critical, High, Medium, or Low, THE Web_Dashboard SHALL display only the CVEs matching the selected Severity_Level.
4. WHEN an administrator selects a Target_Machine from the list, THE Web_Dashboard SHALL display the drill-down view listing the CVEs identified for that Target_Machine.
5. WHERE a drill-down view is displayed, THE Web_Dashboard SHALL display each CVE identifier, its Severity_Level, and its CVSS_Score.

### Requirement 4: Manual Remediation Tracking

**User Story:** As a security administrator, I want to record remediation notes and status for each vulnerability, so that I can track manual remediation progress.

#### Acceptance Criteria

1. WHEN an administrator adds a Remediation_Record for a CVE on a Target_Machine, THE CVE_Scanner_System SHALL persist the Remediation_Record to the Local_Database.
2. THE CVE_Scanner_System SHALL allow an administrator to record a remediation status and a free-text note for each Remediation_Record.
3. WHEN an administrator updates a Remediation_Record, THE CVE_Scanner_System SHALL persist the updated Remediation_Record to the Local_Database.
4. WHEN the Web_Dashboard displays a CVE in the drill-down view, THE Web_Dashboard SHALL display the current remediation status of that CVE.
5. THE CVE_Scanner_System SHALL perform remediation actions only when initiated manually by an administrator.

### Requirement 5: Local and Online Database Synchronization

**User Story:** As a security administrator, I want scan data and remediation records synchronized between a local and an online database, so that data is available both locally and remotely.

#### Acceptance Criteria

1. THE CVE_Scanner_System SHALL store Inventory, CVE, and Remediation_Record data in the Local_Database.
2. WHEN data is persisted to the Local_Database, THE Sync_Process SHALL propagate the data to the Online_Database.
3. IF the Sync_Process cannot reach the Online_Database, THEN THE Sync_Process SHALL retain the unsynchronized data in the Local_Database and record a pending-sync status.
4. WHEN the Online_Database becomes reachable after a pending-sync status, THE Sync_Process SHALL propagate the retained data to the Online_Database.
5. THE Local_Database and Online_Database schemas SHALL store a data structure that associates a CVE with a Target_Machine and with a Dependency_Path.

### Requirement 6: Outward-Facing API

**User Story:** As a developer of an external application, I want to pull scan and vulnerability data through an API, so that I can integrate the data into other systems.

#### Acceptance Criteria

1. WHEN an external consumer sends a request for the machine list, THE Backend_API SHALL return the list of scanned Target_Machines.
2. WHEN an external consumer sends a request for the CVEs of a specified Target_Machine, THE Backend_API SHALL return the CVE identifiers, Severity_Levels, and CVSS_Scores for that Target_Machine.
3. WHEN an external consumer sends a request filtered by Severity_Level, THE Backend_API SHALL return only the CVEs matching the specified Severity_Level.
4. IF an external consumer sends a request for a Target_Machine that does not exist, THEN THE Backend_API SHALL return a not-found response.
5. THE Backend_API SHALL return responses in a structured JSON format.

### Requirement 7: Extensible Data Model for Dependency Visualization

**User Story:** As a product owner, I want the data model to accommodate future dependency and application-path visualization, so that this capability can be added without restructuring stored data.

#### Acceptance Criteria

1. WHERE a CVE is matched at the software or package level via OSV_Source, THE CVE_Scanner_System SHALL store the associated software or package identifier with the CVE record.
2. THE CVE_Scanner_System SHALL store a Dependency_Path association capable of linking a CVE to software dependencies and application paths on a Target_Machine.
3. THE CVE_Scanner_System SHALL preserve the software or package identifier and Dependency_Path association across the Sync_Process to the Online_Database.

### Requirement 8: Zero-Touch Network Discovery and Fleet Enrollment

**User Story:** As a security administrator, I want to sweep network subnets to discover active endpoints without credentials, and enroll them into the fleet roster, so that I can discover and manage all network assets before credentialed scanning.

#### Acceptance Criteria

1. WHEN an administrator initiates a discovery sweep for an IPv4 CIDR range, THE CVE_Scanner_System SHALL probe each host address using ICMP ping, TCP connect scans, and unauthenticated service banner grabbing without requiring credentials.
2. THE CVE_Scanner_System SHALL enforce a maximum subnet size of /20 (4096 addresses) for a single discovery sweep to prevent network and system resource exhaustion.
3. FOR EACH active host discovered during a sweep, THE CVE_Scanner_System SHALL report its IP address, reverse-DNS hostname (when resolvable), ping reachability, open enterprise ports, service banners (SSH identification, HTTP Server, SMB negotiate), and an inferred OS platform guess.
4. WHEN an administrator enrolls one or more discovered hosts into the fleet, THE CVE_Scanner_System SHALL persist the target machine records to the Local_Database with pending synchronization status.
5. WHEN an administrator triggers a Quick Scan from the discovery view or fleet view, THE Web_Dashboard SHALL switch to the scan view with the target hostname/IP and inferred platform pre-populated in the scan form.
6. WHEN navigating between dashboard views or refreshing the browser session, THE Web_Dashboard SHALL maintain cached network discovery sweep results in browser session storage without requiring redundant network re-sweeps.
7. WHEN an administrator enters or selects a target host for credentialed scanning, THE Web_Dashboard SHALL automatically infer and default the platform selector to Linux or Windows based on enrolled fleet records and network discovery banner signatures.
8. WHEN an administrator requests a data export from the Fleet Overview, Machine CVE Drill-Down, or Network Discovery view, THE Web_Dashboard SHALL generate and download an RFC 4180 compliant CSV file.

### Requirement 9: SSH Key-Based and Secretless Remote Authentication

**User Story:** As a security engineer in a hardened enterprise environment, I want to authenticate to target Linux machines using cryptographic SSH private keys and passphrases instead of passwords, so that I can scan systems where password authentication is disabled.

#### Acceptance Criteria

1. WHEN an administrator initiates a scan using SSH key authentication, THE Backend_API SHALL accept an Ed25519, RSA, or ECDSA private key and an optional decryption passphrase.
2. THE CVE_Scanner_System SHALL wrap private keys and passphrases in `SecretStr` models to prevent exposure through logs, API serialization, and in-memory dumps.
3. WHEN authenticating over SSH, THE Linux_Collector SHALL parse the private key in memory without persisting key files to the disk.
4. IF an invalid private key, malformed PEM header, or incorrect passphrase is provided, THEN THE Linux_Collector SHALL record an `AUTH_FAILURE` status for that target without aborting the overall scan batch.
5. THE Web_Dashboard SHALL provide an authentication mode selector in the scan form allowing operators to choose between password and private key authentication.



---

## Addendum: requirements added after the initial spec

These were implemented after `tasks.md` was completed. Recorded here so the spec
stays the source of truth for intended behavior (AGENTS.md section 6).

These were originally numbered 12 to 17, which left an unexplained gap at 10 and
11 and made the numbering look like a mistake. They were renumbered to run
contiguously from 10. Nothing outside this document referenced them, so no
citation changed.

Requirements 9 and 11 both concern SSH key authentication and should be read
together: 9 is the original, narrower statement covering key formats,
`SecretStr` handling, and in-memory parsing, while 11 covers the operational
surface that followed it. The overlap is real, not an error.

### Requirement 10: Trustworthy scan reporting

**User story:** As an operator, I want to know when a scan's results are
incomplete, so that I do not mistake a partial scan for a clean host.

#### Acceptance criteria

1. WHEN a scan completes AND a configured vulnerability data source was
   unreachable THEN the system SHALL report the scan as partial, naming the
   unavailable source, and SHALL NOT present it as a clean result.
2. WHEN a data source is not configured at all THEN the system SHALL NOT report
   it as unavailable, so that the partial-results signal stays meaningful.
3. WHEN a scan fails for a target THEN the system SHALL surface the originating
   error message alongside the status.
4. WHEN a machine has been enrolled but never scanned THEN the system SHALL
   report its status as `never_scanned`, distinct from a connection failure.
5. WHEN a machine has been scanned THEN the system SHALL record and expose the
   time of that scan, and SHALL indicate when it is stale.
6. WHEN an API request fails THEN the client SHALL surface the server's own
   explanation rather than only an HTTP status code.
7. WHEN a request exceeds its deadline THEN the system SHALL abort it and report
   a timeout rather than waiting indefinitely.
8. IF a scan targets a platform whose inventory the system cannot match against
   vulnerability data THEN the system SHALL refuse the scan and say why, rather
   than complete it and report a result, so that an unassessed host can never be
   presented as clean.

### Requirement 11: SSH key-based authentication

**User story:** As an operator of a passwordless Linux fleet, I want to scan
using SSH keys, so that I do not have to enable password authentication.

#### Acceptance criteria

1. WHERE a scan target supplies a private key THEN the system SHALL authenticate
   with it, supporting Ed25519, ECDSA, and RSA in PEM or OpenSSH format.
2. THE system SHALL hold key material in memory only and SHALL NOT write it to
   disk.
3. IF a key is malformed THEN the system SHALL report a key error before
   attempting a network connection, distinct from a connection failure.
4. IF a key's passphrase is missing or incorrect THEN the system SHALL report
   that distinctly from a malformed key.
5. THE system SHALL require exactly one of password or private key per target.
6. WHERE a server-managed key is configured AND a Linux target supplies no
   credentials THEN the system SHALL authenticate with that key.
7. THE system SHALL re-read the server-managed key per scan, so that rotation
   does not require a restart.
8. WHEN a Windows target supplies no credentials THEN the system SHALL reject
   the scan, since WinRM has no SSH-key equivalent.
9. IF credentials cannot be resolved for a target THEN that target SHALL fail
   alone and SHALL NOT abort the batch.

### Requirement 12: Host runtime context

**User story:** As an operator, I want to know whether a host is running the
kernel it has installed, so that a patched-but-not-rebooted host is not reported
as clean.

#### Acceptance criteria

1. THE system SHALL collect the running kernel release from each Linux target.
2. THE system SHALL detect whether a reboot is pending, and SHALL record an
   indeterminate result where the distribution offers no read-only way to ask.
3. THE system SHALL collect this in the same SSH round trip as the OS release
   read.
4. THE collection commands SHALL remain read-only, containing no filesystem
   write redirect.

### Requirement 13: Fleet-scale operation

**User story:** As an operator of a fleet, I want to re-scan many hosts at once,
so that keeping the fleet current does not require re-entering credentials per
host.

#### Acceptance criteria

1. THE system SHALL accept and scan a batch of targets in a single request.
2. WHERE a server-managed key is configured THEN the dashboard SHALL allow
   re-scanning selected machines, or all machines matching current filters,
   without per-host credentials.
3. WHERE no server-managed key is configured THEN the dashboard SHALL NOT offer
   those controls.
4. THE dashboard SHALL allow every fleet and finding table to be sorted.
5. WHEN a list is empty because of active filters THEN the system SHALL name
   those filters and offer to clear them.

### Requirement 14: Accurate and reachable remediation guidance

**User story:** As an operator, I want the suggested fix command to match the
host it is for, so that copying it produces a command that works.

#### Acceptance criteria

1. THE system SHALL select remediation tooling from the target machine's
   platform and operating system, not from a package name.
2. WHEN the distribution cannot be determined THEN the system SHALL NOT suggest
   a command for a guessed package manager.
3. WHERE guidance is specific to a distribution THEN the system SHALL show it
   only for that distribution.
4. WHEN a command is copied THEN the system SHALL confirm success or report
   failure, including in browser contexts where the asynchronous clipboard API
   is unavailable.
5. THE system SHALL indicate fix availability through a structured field, not
   through the wording of a display string.
6. THE system SHALL generate remediation commands only, and SHALL NOT execute
   any command on a target (extends Req 4.5).

### Requirement 15: Public demonstration mode

**User story:** As someone evaluating CveDeck, I want to see a populated
dashboard without enrolling a fleet first, so that I can judge whether the
prioritisation is worth adopting. As the operator hosting that demonstration, I
want it to be safe to expose.

#### Acceptance criteria

1. WHERE demonstration mode is enabled AND the database holds no machines THEN
   the system SHALL populate a fictional fleet.
2. WHERE demonstration mode is enabled AND the database already holds machines
   THEN the system SHALL make no change to them.
3. WHERE demonstration mode is enabled THEN the system SHALL refuse every
   request that opens a network connection to a user-supplied address —
   scanning, network discovery, and connection testing — and SHALL report the
   refusal with its reason.
4. WHERE demonstration mode is enabled THEN the system SHALL report that fact
   through its health endpoint, and the dashboard SHALL state it.
5. THE seeded fleet SHALL include machines in every scan status, including one
   never scanned and one whose credentials failed, and SHALL NOT attach findings
   or inventory to a machine that has not been scanned successfully.
6. THE seeded findings SHALL exercise all three states of exploitation
   knowledge — listed, checked and absent, and never checked — and SHALL NOT
   record a partial enrichment in which some enrichment fields are answered and
   others are not (extends Req 10 and the enrichment invariant).
7. THE system SHALL default to demonstration mode being disabled, and SHALL
   treat an unrecognised setting as disabled.
