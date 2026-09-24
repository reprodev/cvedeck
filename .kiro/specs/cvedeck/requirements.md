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
- **Severity_Level**: One of the categories Critical, Unscored, High, Medium, or Low. Derived from the CVSS_Score where one is published, taken from the advisory where it publishes a qualitative severity instead, and Unscored where it publishes neither. A Severity_Level and a CVSS_Score are independent: a finding may carry a band with no score.
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
7. IF a Target_Machine authenticates but no package inventory can be read from it — every supported package manager failing, or returning nothing that parses as a package — THEN THE Scanner_Engine SHALL record the Scan as an inventory failure carrying the reason, and SHALL NOT persist an empty Inventory, report the Scan as successful, or treat findings from the previous Scan as resolved, since a host that could not be inventoried is not a host with nothing installed.
8. WHEN the Scanner_Engine collects a Linux Inventory, THE Scanner_Engine SHALL select the package manager by testing for each one's presence, and SHALL NOT select it from the exit status of a shell pipeline, so that a probe for an absent manager cannot report success and mask the managers after it.
9. WHEN the Scanner_Engine collects a Linux Inventory from any supported package manager, THE Scanner_Engine SHALL collect each package's declared dependencies alongside its name and version, so that impact assessment has the same evidence on every supported distribution.
10. IF a Target_Machine authenticates but has none of the supported package managers, THEN THE Scanner_Engine SHALL record that as the reason, distinctly from a package manager whose command failed.
11. THE Scanner_Engine SHALL bound the output it reads from a Target_Machine in size and in total time, and IF either bound is exceeded THEN THE Scanner_Engine SHALL record the scan as unable to read an inventory, with the reason, and SHALL NOT record a truncated inventory, since a truncated inventory would report every finding past the cut as resolved (extends Req 1.7).

### Requirement 2: CVE Matching from Public Data Sources

**User Story:** As a security administrator, I want collected inventory matched against public vulnerability databases, so that I can identify which CVEs affect each machine.

#### Acceptance Criteria

1. WHEN the Scanner_Engine processes the operating system Inventory of a Target_Machine, THE Scanner_Engine SHALL match the Inventory against NVD to identify applicable CVEs.
2. WHEN the Scanner_Engine processes the installed software Inventory of a Target_Machine, THE Scanner_Engine SHALL match the Inventory against OSV_Source to identify applicable CVEs.
3. WHEN a CVE is identified for a Target_Machine, THE Scanner_Engine SHALL record the CVE identifier, the associated CVSS_Score, and the affected Target_Machine.
4. WHEN a CVE has an associated CVSS_Score, THE Scanner_Engine SHALL derive the Severity_Level as Critical, High, Medium, or Low from the CVSS_Score.
5. IF a public data source is unreachable during a Scan, THEN THE Scanner_Engine SHALL record a data-source-unavailable status and complete matching against any reachable data source.
6. WHERE an advisory names a qualitative severity but publishes no CVSS_Score that can be parsed under its own version of the CVSS specification, THE Scanner_Engine SHALL record that Severity_Level and SHALL record no CVSS_Score, rather than substituting a number from within the band.
7. IF a CVE has neither a CVSS_Score that can be parsed nor a qualitative severity, THEN THE Scanner_Engine SHALL record its Severity_Level as Unscored and its CVSS_Score as absent, and SHALL NOT substitute a default score, so that an unmeasured finding is never presentable as a measured one.

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
9. WHEN an exported cell would be evaluated as a formula by a spreadsheet application, THE Web_Dashboard SHALL neutralise it so that it opens as text, while preserving the value it carries, so that a remediation note, a package identifier or a discovered hostname cannot execute in the recipient's spreadsheet.
10. WHERE an export carries findings or fleet counts, THE Web_Dashboard SHALL include the exploitation signals and the completeness signals shown in the view it came from — whether a CVE is known to be exploited, when each host was scanned, and whether its counts are complete — and SHALL write a value the system did not assess as unassessed rather than as a number or a negative, since an exported file carries none of the dashboard's own treatment of an unknown.
11. WHERE this deployment cannot send an ICMP echo request — no ping binary, or no permission to use one — THE CVE_Scanner_System SHALL report each swept host's ping reachability as unchecked rather than as no response, and SHALL say that hosts answering only ICMP were not visible to the sweep, since neither is a fact about the hosts.
12. IF probing an address during a discovery sweep fails outright, THEN THE CVE_Scanner_System SHALL continue the sweep, SHALL count that address as unprobed, and SHALL report the count with the results, so that a sweep which could not cover part of its range is not presented as a complete answer.
13. WHEN a discovery sweep looks up a responding address's name by reverse DNS, THE CVE_Scanner_System SHALL bound the lookup in time and SHALL report a lookup that does not answer in time as no name, so that an unresponsive resolver cannot hold the sweep.

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
9. WHEN the system tests a connection to a target THEN it SHALL use the transport,
   port and scheme that a scan of that platform would use, and SHALL name the
   endpoint it reached, so that a successful test is evidence about the path the
   scan takes and no credential is sent over a channel the deployment has
   configured away.
10. WHERE the system does not compute an impact assessment for a finding — a
   blast radius with no dependency graph behind it — THEN it SHALL report that
   assessment as unassessed rather than as its lowest value, and the dashboard
   and its exports SHALL present it as unassessed, so that a question nobody
   asked is never answered reassuringly (extends the enrichment invariant).
11. WHERE a CVE_Finding has no CVSS_Score, THE Web_Dashboard, THE Backend_API and
   their exports SHALL present it as unscored rather than as any numeric value,
   and SHALL rank it below Critical and above High, since an unmeasured finding
   could be either (extends the enrichment invariant).
12. WHERE CVE_Findings are ordered by CVSS_Score, THE CVE_Scanner_System SHALL
   place a finding that has no score explicitly and identically on every
   supported database, rather than inheriting the store's default ordering for
   absent values.
13. WHERE THE CVE_Scanner_System records a package's dependencies, it SHALL
   record only names the package manager named as packages, excluding file
   paths, shared-object names, capability namespaces and version constraints,
   since those names are both shown to the reader and counted to derive an
   impact assessment, and a name that resolves to no package inflates the
   dependents of everything that requires it.
14. THE CVE_Scanner_System SHALL refresh its cached threat-intel feeds on a
   schedule of its own, without requiring an external trigger, and SHALL report
   that schedule; since a cache nobody refreshes ages silently and renders a
   confident "none actively exploited" from a catalogue that was never fetched,
   leaving the freshness of the exploitation signal to an operator's own cron
   makes the absence of that cron indistinguishable from good news.
15. WHEN THE CVE_Scanner_System refreshes its cached threat-intel feeds THEN it
   SHALL reapply those feeds to the CVE_Findings it has already stored, and
   WHERE a feed is unusable it SHALL leave that feed's fields as they stand
   rather than clearing them; since a finding is enriched once, at the scan that
   produced it, and that scan may be weeks old, a refresh that updates only the
   cache leaves the dashboard stating an exploitation status from a catalogue
   the system no longer holds (extends the enrichment invariant).
16. WHERE THE Web_Dashboard summarises exploitation across a set of
   CVE_Findings — a host, a group, a fleet — it SHALL present that summary as
   clear only WHERE every finding in the set was checked against the
   catalogue, and otherwise SHALL present it as incomplete and SHALL state how
   many were checked; since a summary that asks only whether *any* finding was
   checked reports a confident "none actively exploited" over a set that is
   mostly unchecked, and a reader reads the headline rather than auditing the
   rows beneath it (extends the enrichment invariant).
17. WHERE THE CVE_Scanner_System declines to rewrite a cached threat-intel feed
   because the downloaded records match the digest it recorded, it SHALL first
   confirm that the cached catalogue holds records, counting them rather than
   reading a count recorded alongside the digest; since that count is written
   by the same operation that writes the digest and therefore agrees with it
   whatever the catalogue contains, an emptied catalogue would report itself
   usable and every finding would be recorded as not exploited on the authority
   of no catalogue at all (extends the enrichment invariant).
18. THE CVE_Scanner_System SHALL bound the size of every response it reads
   from a data source -- as transferred and, where it decompresses one, as
   decompressed -- SHALL follow a redirect only to the host it asked and not
   from HTTPS to HTTP, and IF a response exceeds its bound or redirects
   elsewhere THEN SHALL treat it as a failed fetch, keeping a cached feed and
   reporting an advisory lookup as unanswered, never as an empty answer
   (extends Req 10.1).

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
7. WHEN matching a package on a host whose distribution release is known THEN
   the system SHALL judge the vulnerability against that release, and SHALL NOT
   report an advisory that describes the host's release without affecting the
   installed version, or that describes the host's distribution but none of its
   releases -- except WHERE the advisory source does not track that release, or
   its answer is unavailable or incomplete, in which case the system SHALL NOT
   drop the advisory on that basis.
8. THE system SHALL offer a fix as installable, in a copied command or a host's
   remediation plan, only WHERE the host's own release publishes it. WHERE only a
   newer release or a subscription stream publishes a fix, the system SHALL name
   that release and state that upgrading packages cannot clear the finding; WHERE
   the host's release cannot be matched to the advisory, the system SHALL report
   the fix as upstream and unconfirmed for the host.
9. WHERE a finding names no package — a kernel or operating-system advisory —
   THE system SHALL report its fix status as unknown rather than as no fix
   published, since no vendor was asked about a package that was never named.
10. WHEN the system places a package name, a release name or any other text
    reported by a Target_Machine into a command or script offered for copying
    THEN it SHALL quote the name so that a shell reads it as exactly one literal
    argument, SHALL keep text placed in a comment line free of line breaks, and
    SHALL NOT place a control character into a command, since a scanned host
    is not trusted and these commands are run with root privileges.

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
8. WHERE demonstration mode is enabled THEN the system SHALL NOT download a
   threat-intel feed or replace a cached one, on any trigger — the HTTP route,
   the command-line tool, or its own schedule — and SHALL refuse **before**
   performing either, reporting the refusal rather than an ordinary success;
   since the seeded intel is a fixture whose authored values include the
   deliberately unchecked findings of Req 15.6, re-seeding is guarded on an
   empty fleet and so cannot restore it, and a guard placed after the download
   skips only what follows it while the catalogue has already been replaced.
9. WHERE demonstration mode is enabled THEN the system SHALL refuse every
   request that would change stored state -- every API method other than GET,
   HEAD and OPTIONS outside the sign-in routes -- whether or not it reaches the
   network, and SHALL apply that refusal to the routers as a whole rather than
   route by route, so that a route added later is refused without being named
   (extends Req 15.3 and 15.8).

### Requirement 16: Access control

**User story:** As the operator of a CveDeck instance, I want it to require a
login by default, so that someone who can reach the port cannot read my fleet's
vulnerabilities or use the instance to connect to other hosts. As someone
scripting against the API, I want a token that does not depend on a browser.

#### Acceptance criteria

1. WHERE login is required THEN the system SHALL refuse every API request that
   carries neither a current session nor a current API token, except the health
   check and the routes that report the auth state, complete setup, sign in and
   sign out; SHALL NOT serve its API documentation without one; and SHALL report
   through the health check only its status, version, demonstration mode and
   whether login is required to a caller who is not signed in.
2. WHEN a user signs in THEN the system SHALL verify the password against a
   salted, memory-hard hash; SHALL give the same response for an unknown username
   as for a wrong password, taking comparable time; and SHALL refuse to set a
   password shorter than 12 characters, stating why.
3. WHERE login is required AND no account exists THEN the system SHALL issue a
   single-use setup code, record only its hash, write the code to its log, and
   SHALL create the first account only for a request presenting that code before
   it expires; a restart SHALL replace the code.
4. WHERE an administrator username and password are configured AND no account
   exists THEN the system SHALL create that account at start-up, and SHALL NOT
   change an account that already exists.
5. WHEN a user signs in THEN the system SHALL issue a new random session token,
   store only its hash, send it in a cookie that scripts cannot read and other
   sites do not send, and SHALL end the session 30 days after sign-in or 7 days
   after its last use, whichever is sooner.
6. WHEN a user changes their password THEN the system SHALL require the current
   password and SHALL end every other session of that account.
7. THE system SHALL let a signed-in user create, list and revoke named API
   tokens; SHALL show a token only in the response that creates it and store only
   its hash; SHALL accept a current token as a bearer credential; and SHALL NOT
   let a token manage the account.
8. WHEN sign-in or setup attempts from one client address for one username
   repeatedly fail THEN the system SHALL refuse further attempts for an interval
   that grows with each failure, and SHALL report how long to wait.
9. THE system SHALL require login unless it is explicitly disabled, SHALL treat
   any unrecognised setting as enabled, and SHALL log a warning at start-up
   whenever login is disabled.
10. WHEN a request authenticated by session cookie would change state AND it does
    not come from the dashboard's own origin or a configured CORS origin THEN the
    system SHALL refuse it and say that scripts should use an API token.
11. WHERE demonstration mode is enabled THEN the system SHALL NOT require login
    (extends Req 15).
12. THE system SHALL provide a command, run on the host, that resets the account
    password, ending every session and revoking every API token, or creates the
    account when none exists.
13. THE system SHALL refuse, before acting on it, a request whose lists or
    strings exceed fixed upper bounds -- the targets in a scan, the hosts in an
    enrolment, the ports in a sweep, each credential field and each note --
    and SHALL refuse a port outside 1 to 65535.
14. WHEN the system refuses a request as malformed THEN it SHALL name the field
    and the reason, and SHALL NOT echo the rejected value, which may be a
    password or a private key.
15. THE system SHALL send with every response the headers that forbid another
    site from framing it, forbid content-type sniffing, send no referrer, and
    restrict the dashboard to running and styling itself only from its own
    origin, with no inline script.
16. WHERE login is disabled, WHEN a state-changing request states that it came
    from another site -- by its Origin, its Referer or its fetch metadata --
    THEN the system SHALL refuse it, while still accepting a request that
    states no origin at all; AND THE system SHALL refuse to start with a
    wildcard CORS origin, since credentials would then be granted to any site.
17. WHERE a list of host names is configured THEN the system SHALL refuse any
    request whose Host is not on it or loopback, as the defence against DNS
    rebinding; AND WHERE login is disabled and no list is configured, THE
    system SHALL warn at start-up that it is exposed to DNS rebinding.
18. THE system SHALL let a signed-in person revoke every API token at once,
    and SHALL NOT let an API token do so.
19. THE system SHALL record in its log, with who asked and from where and
    without any credential: each scan, discovery sweep and connection test,
    including whether the server-managed key was used; each forgotten host
    key; each refused cross-origin or cross-site request; each unknown or
    revoked API token presented; and each attempt refused by throttling.
20. THE system SHALL throttle failed sign-ins per client address across all
    usernames as well as per account, with a looser limit, AND SHALL bound how
    many password verifications run at once, so that sign-in attempts with
    made-up usernames cannot consume memory and processor time without limit.
21. THE system SHALL serve nothing that makes a browser fetch code, styles or
    other resources from a third party, since each such fetch tells that party
    the address of an instance and that it runs CveDeck; its API schema SHALL
    remain available, behind sign-in, for tools a user runs themselves.

### Requirement 17: Pinned SSH host keys

**User story:** As an administrator scanning hosts over a network I do not fully
trust, I want CveDeck to remember each host's SSH key and refuse a host that
presents a different one, so that a machine in the middle cannot collect the
credentials I scan with or feed the scanner a false inventory.

#### Acceptance criteria

1. WHEN the system connects to a host and port for which no SSH host key is
   pinned AND the policy is trust on first use THEN the system SHALL pin the key
   the host presents, and SHALL pin it only after the connection has succeeded,
   so that an unreachable host or a rejected login pins nothing.
2. WHEN the system connects to a host and port for which a key is pinned AND the
   host presents that key THEN the system SHALL proceed and record when the key
   was last seen.
3. WHEN a host presents a key other than the one pinned for it THEN the system
   SHALL refuse the connection before offering any credential, SHALL record the
   outcome as `HOST_KEY_MISMATCH` rather than as a connection failure, SHALL
   report the SHA-256 fingerprints of both keys, and SHALL NOT replace the pin.
4. WHEN a host offers several key types AND one of them is pinned THEN the system
   SHALL negotiate the pinned key type, so that a host is not refused for
   presenting a different type of key it also holds.
5. WHERE the host key policy is `strict` THEN the system SHALL refuse a host with
   no pinned key before offering any credential and record the outcome as
   `HOST_KEY_UNKNOWN`; THE system SHALL default to trust on first use and SHALL
   reject an unrecognised policy setting.
6. THE system SHALL hold scans and connection tests to one store of pinned keys,
   so that a key accepted by either is the key the other requires.
7. THE system SHALL change a pinned key only when a signed-in user explicitly
   forgets it, and SHALL refuse to forget a key in demonstration mode (extends
   Req 15).
8. THE system SHALL show the type and fingerprint of the key pinned for a
   machine, so that it can be compared with the key file on the host.
9. WHEN two connections to the same unpinned address try to pin at the same time
   THEN the system SHALL keep one pin, SHALL let the connection that did not
   write it proceed when the key it saw is the key that was pinned, SHALL refuse
   that connection as a mismatch when it is not, and SHALL NOT report the race as
   a server error.
10. THE system SHALL list every pinned key with its address, port, key type,
    fingerprint and when it was first and last seen -- including a key pinned for
    an address no enrolled machine matches, or on a port the deployment no longer
    uses -- and SHALL let a signed-in user forget any of them (extends Req 17.7).
11. THE system SHALL show, on a machine's page, every key pinned for that
    machine's address on a port other than the one whose key it shows, with its
    port, type and fingerprint, and SHALL let a signed-in user forget any of them
    there (extends Req 17.8, 17.10).
12. WHERE a connection is made with nowhere to record a pinned key THEN the
    system SHALL refuse any host whose key is not already known, before
    sending a credential, whatever the host key policy -- no code path SHALL
    accept an unknown key without recording it (extends Req 17.5).

### Requirement 18: Scan history and what changed

**User story:** As an administrator re-scanning my fleet, I want to see what is
new since the last scan, what a patch cleared, and how long each finding has
been open, so that I can tell whether my patching worked without comparing
lists by hand.

#### Acceptance criteria

1. WHEN a scan of a machine is attempted THEN the system SHALL record a run for
   it, successful or not, with its outcome, its time, whether every configured
   data source answered, and the number of findings it left recorded.
2. WHEN a scan of a machine succeeds THEN the system SHALL compare its findings
   with the machine's previous findings, treating two findings as the same when
   they share a CVE and package name whatever the package version; SHALL record
   the findings that are new and the findings that are resolved, with each one's
   severity, CVSS score and exploitation status at the time; and SHALL report the
   new and resolved counts with the scan result.
3. WHEN a scan succeeds AND a configured data source did not answer THEN the
   system SHALL record the findings that are new, SHALL NOT mark any finding
   resolved, SHALL keep the findings the scan did not report, and SHALL report
   the resolved count as not assessed rather than as zero (extends Req 10).
4. WHEN a machine's first successful scan is recorded, including its first scan
   after upgrading to a version that records history, THEN the system SHALL
   record it as a baseline with no new or resolved findings; AND WHEN a scan fails
   THEN the system SHALL leave the machine's findings unchanged and record no
   comparison.
5. THE system SHALL record when each finding was first seen on its machine and
   SHALL keep that time across scans for as long as the finding is found.
6. THE system SHALL show, for each machine, the new and resolved counts of its
   latest successful scan, which of its findings that scan found new, and the
   history of its runs with each run's new and resolved findings; and SHALL show
   a count that was not assessed differently from zero.
7. THE system SHALL keep a configurable number of runs per machine, 50 by
   default, and SHALL NOT discard a machine's latest successful run.
8. THE system SHALL synchronize scan runs and their changes to the
   Online_Database like other scan data (extends Req 5).
9. THE system SHALL NOT change a remediation record because a scan resolved its
   finding (extends Req 4).
10. WHEN a Scan of a Target_Machine does not succeed, THE system SHALL keep the
    reason with that run and show it in the machine's scan history, bounded in
    length and carrying no credential, so that a failed run says whether the
    host was unreachable, rejected the credentials, presented a different host
    key, or could not be inventoried, rather than only that it failed.
