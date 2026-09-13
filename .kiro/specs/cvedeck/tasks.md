# Implementation Plan: CveDeck

## Overview

This plan builds the CveDeck incrementally: first the foundational domain model, enums, and severity logic; then the persistence layer; then the pure matching and presentation logic; then the agentless collectors and data-source clients; then remediation and synchronization; and finally the FastAPI surface and the React/TypeScript dashboard, wiring every component together. Property-based tests (minimum 100 iterations, tagged with the feature name and property number) cover the pure/logic layers; example and integration tests cover UI rendering, API contracts, error cases, and the SSH/WinRM I/O layers.

Backend: Python 3.11+, FastAPI, Pydantic, SQLAlchemy, `paramiko`, `pywinrm`, Hypothesis. Frontend: React + TypeScript, with fast-check for property tests.

## Tasks

- [x] 1. Set up project structure and core domain types
  - [x] 1.1 Scaffold backend project and tooling
    - Create the backend package layout (`app/`, `app/scanner/`, `app/data/`, `app/api/`, `tests/`)
    - Add `pyproject.toml`/requirements with FastAPI, Pydantic, SQLAlchemy, paramiko, pywinrm, pytest, Hypothesis
    - Configure pytest and Hypothesis (min 100 iterations) settings
    - _Requirements: 6.5_

  - [x] 1.2 Define enumerations and core dataclasses/Pydantic models
    - Implement `Platform`, `Severity`, `ScanStatus`, `SourceStatus`, `SyncStatus`, `RemediationStatus` enums
    - Define `TargetMachine`, `Inventory`, `Package`, `OsInfo`, `Credentials` domain structures used across layers
    - _Requirements: 1.1, 1.2, 2.4, 5.1_

- [x] 2. Implement severity derivation and matching logic
  - [x] 2.1 Implement `derive_severity`
    - Total function mapping a CVSS base score (0.0–10.0) to a `Severity` band (0.0–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical)
    - _Requirements: 2.4_

  - [x] 2.2 Write property test for severity derivation
    - **Property 4: Severity derivation is total and correct**
    - **Validates: Requirements 2.4**

  - [x] 2.3 Implement the Matcher and data-source client protocols
    - Define `NvdClient`/`OsvClient` protocols and implement `Matcher.match` producing `Finding` records
    - OS inventory → NVD, software inventory → OSV; attach CVE id, CVSS score, machine ref, and package identifier for OSV findings
    - Record `DATA_SOURCE_UNAVAILABLE` for a `None`/unreachable client and continue with the reachable source
    - _Requirements: 2.1, 2.2, 2.3, 2.5, 7.1_

  - [x] 2.4 Write property test for matching correctness and finding completeness
    - **Property 3: Matching correctness and finding completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 7.1**

  - [x] 2.5 Write property test for graceful degradation on unavailable data sources
    - **Property 5: Graceful degradation on unavailable data sources**
    - **Validates: Requirements 2.5**

- [x] 3. Implement persistence layer and data model
  - [x] 3.1 Define SQLAlchemy models and identical local/online schema
    - Implement `TargetMachine`, `Inventory`, `Package`, `CveFinding`, `DependencyPath`, `RemediationRecord` tables
    - Include `sync_status` on syncable rows, `package_identifier` and `dependency_path_id` on `CveFinding`, and `DependencyPath.parent_path_id` self-reference
    - _Requirements: 5.1, 5.5, 7.1, 7.2_

  - [x] 3.2 Implement repository read/write operations
    - Persist and read back inventory, findings, and remediation records against the Local_Database
    - Provide read queries for the dashboard/API (machine list, per-machine CVEs)
    - _Requirements: 1.6, 5.1_

  - [x] 3.3 Write property test for inventory persistence round-trip
    - **Property 2: Inventory persistence round-trip**
    - **Validates: Requirements 1.6, 5.1**

  - [x] 3.4 Write property test for dependency-path association round-trip
    - **Property 11: Dependency-path association round-trip**
    - **Validates: Requirements 5.5, 7.2**

- [x] 4. Checkpoint - core logic and persistence
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement agentless collectors and scanner engine
  - [x] 5.1 Implement `LinuxCollector` and `WindowsCollector`
    - `LinuxCollector` runs read-only inventory commands over `paramiko` (SSH); `WindowsCollector` runs read-only PowerShell over `pywinrm` (WinRM)
    - Normalize results into `Inventory`; raise `ConnectionError` on unreachable host and `AuthError` on auth failure; install nothing on the target
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 5.2 Write integration tests for collectors
    - Test SSH collection, WinRM collection, and verify commands are read-only (no writes to target)
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 5.3 Implement `ScannerEngine` with per-target fault isolation
    - Select collector by platform; wrap `_scan_one` so a `ConnectionError` records `CONNECTION_FAILURE` and an `AuthError` records `AUTH_FAILURE`, never aborting the batch
    - On success, collect inventory, persist it, run the Matcher, and persist findings
    - _Requirements: 1.4, 1.5, 1.6_

  - [x] 5.4 Write property test for per-target fault isolation
    - **Property 1: Per-target fault isolation**
    - **Validates: Requirements 1.4, 1.5**

- [x] 6. Implement remediation and synchronization services
  - [x] 6.1 Implement `RemediationService`
    - `add` and `update` remediation records (status + free-text note) persisted to the Local_Database; only administrator-initiated, no scheduler/automated trigger
    - _Requirements: 4.1, 4.2, 4.3, 4.5_

  - [x] 6.2 Write property test for remediation persistence
    - **Property 9: Remediation persistence reflects last write**
    - **Validates: Requirements 4.1, 4.3**

  - [x] 6.3 Write smoke test for absence of automated remediation triggers
    - Verify remediation only occurs via explicit service calls (no scheduler)
    - _Requirements: 4.5_

  - [x] 6.4 Implement `SyncService`
    - `enqueue` marks entities `PENDING_SYNC`; `sync` propagates pending entities to the Online_Database, keeps them `PENDING_SYNC` on failure, and converges online to local on success, preserving package identifier and dependency-path association
    - _Requirements: 5.2, 5.3, 5.4, 7.3_

  - [x] 6.5 Write property test for durable synchronization convergence
    - **Property 10: Durable synchronization convergence with field preservation**
    - **Validates: Requirements 5.2, 5.3, 5.4, 7.3**

- [x] 7. Checkpoint - scanning, remediation, and sync
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement the Backend API
  - [x] 8.1 Implement machine and CVE read endpoints
    - `GET /api/machines` (severity-grouped counts), `GET /api/machines/{id}` (404 if unknown), `GET /api/machines/{id}/cves?severity=`, `GET /api/cves?severity=`
    - Serialize `MachineSummary`, `SeverityCounts`, `CveFindingOut` as structured JSON; include CVE id, severity, and CVSS score
    - _Requirements: 3.2, 3.3, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 8.2 Implement remediation and action endpoints
    - `POST /api/machines/{id}/cves/{cve_id}/remediation`, `PUT /api/remediation/{record_id}`, `POST /api/scans`, `POST /api/sync`
    - Wire to `RemediationService`, `ScannerEngine`, and `SyncService`
    - _Requirements: 1.1, 1.2, 4.1, 4.3, 5.2_

  - [x] 8.3 Write property test for severity filtering (API)
    - **Property 7: Severity filtering is sound and complete**
    - **Validates: Requirements 3.3, 6.3**

  - [x] 8.4 Write property test for API serialization completeness
    - **Property 8: Finding rendering and serialization completeness**
    - **Validates: Requirements 3.5, 6.2**

  - [x] 8.5 Write integration tests for API contracts
    - Machine-list read, 404 for unknown machine, and JSON schema/validation (422 on malformed request)
    - _Requirements: 6.1, 6.4, 6.5_

- [x] 9. Implement the Web Dashboard
  - [x] 9.1 Scaffold React/TypeScript frontend and API client
    - Set up the frontend project, define `MachineSummary`/`CveFinding` interfaces, and an API client for the backend endpoints
    - _Requirements: 3.1_

  - [x] 9.2 Implement pure client-side helpers
    - `filterBySeverity` and `groupCountsBySeverity`
    - _Requirements: 3.2, 3.3_

  - [x] 9.3 Write property test for severity-grouped counts
    - **Property 6: Severity-grouped counts are accurate**
    - **Validates: Requirements 3.2**

  - [x] 9.4 Write property test for severity filtering (dashboard)
    - **Property 7: Severity filtering is sound and complete**
    - **Validates: Requirements 3.3, 6.3**

  - [x] 9.5 Implement `MachineListView` and `MachineDrillDownView`
    - List view: scanned machines with severity-grouped counts and a severity filter
    - Drill-down: per-CVE id, severity, CVSS score, and current remediation status
    - _Requirements: 3.1, 3.4, 3.5, 4.4_

  - [x] 9.6 Write example tests for dashboard rendering
    - List rendering, drill-down rendering, remediation status display, and remediation field capture
    - _Requirements: 3.1, 3.4, 4.2, 4.4_

- [x] 10. Final checkpoint - full integration
  - [x] 10.1 Wire frontend to backend and verify end-to-end data flow via automated tests
    - Connect dashboard views to the API client and confirm machine list, filtering, drill-down, and remediation display resolve against the backend
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 4.4, 6.1, 6.2_

  - [x] 10.2 Checkpoint
    - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional test sub-tasks and can be skipped for a faster MVP.
- Each task references specific requirements for traceability.
- Checkpoints ensure incremental validation.
- Property tests validate the 11 universal correctness properties from the design (pure/logic layers), and run a minimum of 100 iterations each, tagged with the feature name and property number.
- Example and integration tests cover UI rendering, API contracts, error cases, and the SSH/WinRM I/O layers, which are not amenable to property testing.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "3.1", "9.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.2", "5.1", "9.2"] },
    { "id": 3, "tasks": ["2.4", "2.5", "3.3", "3.4", "5.2", "5.3", "6.1", "6.4", "9.3", "9.4", "9.5"] },
    { "id": 4, "tasks": ["5.4", "6.2", "6.3", "6.5", "8.1", "8.2", "9.6"] },
    { "id": 5, "tasks": ["8.3", "8.4", "8.5", "10.1"] }
  ]
}
```
