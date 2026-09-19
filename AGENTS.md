# Notes for future contributors (humans and LLMs)

This project was built spec-first. Read this before changing anything.

## 0. Read the spec first

The source of truth for intended behavior is:

    .kiro/specs/cvedeck/
      requirements.md   # EARS-style acceptance criteria, glossary
      design.md         # architecture, interfaces, data model, 11 properties
      tasks.md          # the implementation plan (all tasks complete)

Requirements are referenced throughout the code and tests as "Req X.Y". When you
change behavior, update requirements.md and design.md in the same change so the
spec stays accurate. Do not let code and spec drift apart.

Every acceptance criterion is cited at least once, at the place that implements
it, and that is meant to stay true: a new criterion without a citation is an
unfinished change, and so is a renamed or deleted one that leaves a citation
pointing at nothing. This held for Requirements 1-7 for a long time while the
eight added later had no citations at all, which is a worse state than having
none -- the covered ones make the convention look complete. Both halves are
mechanically checkable, so check them rather than trusting the convention.

## 1. Project shape

- backend/  Python 3.11+ (FastAPI, Pydantic, SQLAlchemy, paramiko, pywinrm, Hypothesis)
- frontend/ React + TypeScript (Vite, Vitest, @testing-library/react, fast-check)

Backend package layout:
- app/enums.py            shared string enums (values are persisted + serialized; do not rename lightly)
- app/models.py           in-memory domain models (Pydantic) produced by collectors
- app/scanner/            collectors (SSH/WinRM), matcher (NVD/OSV + derive_severity), engine,
                          osv_client.py (live OSV.dev), nvd_client.py (live NVD 2.0, opt-in),
                          kev_client.py + epss_client.py (whole-feed threat-intel downloads),
                          discovery.py (Phase 1 zero-touch network sweep: ICMP ping, TCP connect,
                          unauthenticated SSH/HTTP/SMB banner grabbing, OS guessing)
- app/data/               schema.py (SQLAlchemy ORM) + repository.py (read/write),
                          demo_seed.py (the CVEDECK_DEMO_MODE fixture fleet)
- app/services/           remediation.py, sync.py, enrichment.py (FeedRefreshService pulls the
                          KEV/EPSS caches; FindingEnricher joins them onto findings)
- app/config.py           deployment settings read from the environment (nothing else reads os.environ)
- app/api/                app.py (create_app factory), routes.py (reads, including
                          GET /api/feeds for intel cache health), actions.py (writes,
                          including POST /api/discovery/sweep for network discovery,
                          POST /api/discovery/enroll for fleet enrollment,
                          POST /api/feeds/refresh for the KEV/EPSS caches),
                          schemas.py (response/request models), dependencies.py (get_session etc.),
                          wiring.py (concrete engine/sync service for deployments)

Deployment (Dockerfile, docker-compose.yml, deploy/) is documented in
DEPLOYMENT.md. The image serves the API and the built frontend from one origin.

Frontend layout:
- src/types.ts            camelCase domain types (do not switch to snake_case)
- src/api/client.ts       maps backend snake_case JSON -> frontend camelCase (see invariant below)
- src/lib/severity.ts     pure helpers (filterBySeverity, groupCountsBySeverity)
- src/lib/intel.ts        pure KEV/EPSS presentation helpers (exploitStatus, sortByRisk,
                          enrichmentWarning). isKnownExploited uses `=== true` on purpose --
                          see the enrichment invariant below
- src/lib/csvExport.ts    RFC 4180 CSV export utilities for fleet, drill-down findings, and discovery
- src/lib/labels.ts       shared display labels (severityLabel, statusLabel,
                          remediationStatusLabel, relativeTime, isStale). One implementation
                          each -- the drill-down used to keep private copies that drifted
- src/lib/useUrlState.ts  hash-based routing (parseHash/formatHash/useUrlState). Hash, not
                          History API, on purpose -- see the invariant below
- src/lib/useTheme.ts     theme preference: light / dark / system, persisted to localStorage,
                          applied by stamping data-theme on <html>
- src/views/              ScanFormView, MachineListView, MachineDrillDownView, DiscoveryView
- src/components/         Modal, Toast, EmptyState, CveDetailModal, RemediationCell,
                          Icon (inline SVG set), Skeleton (loading placeholders)
- src/App.tsx             wires views to the API client; navigation comes from the URL via
                          useUrlState, not component state, so screens are linkable
- src/index.css           the only stylesheet; plain CSS with custom properties. Every colour
                          is a light-dark() pair defined once in :root; three small
                          color-scheme rules (bare :root, a guarded prefers-color-scheme
                          query, and :root[data-theme]) decide which half applies. Type,
                          spacing, radius, shadow and scrim are all tokenised -- add a step
                          rather than a literal. No framework; react and react-dom are the
                          only runtime deps.
- src/fonts/, public/     vendored woff2 faces (with OFL.txt) and the favicon. Nothing the
                          dashboard renders is fetched from a third party at runtime

The dashboard drives scans, remediation, and network asset discovery. A machine
enters the system either via credentialed scan (POST /api/scans upserts the target)
or via network discovery enrollment (POST /api/discovery/enroll registers discovered
hosts into the fleet roster). Both paths use the hostname or IP as the machine id.

## 2. How to run and verify

Backend (from backend/, in the virtualenv):
    pytest
Property-based tests use the Hypothesis profile "cvedeck" (min 100
iterations), registered in tests/conftest.py. Note Hypothesis is installed only
in backend/.venv, so run pytest via that interpreter.

Frontend (from frontend/):
    npm test        # vitest run
    npm run typecheck
    npm run build   # runs tsc --noEmit && vite build

Always run both suites before committing; both must be fully green. The counts are
deliberately not written here -- a count in a document goes stale, and two already
have. `scripts/Verify-Release.ps1` runs everything and reports the numbers.

Never make a live network call in a test. The OSV, NVD, KEV, and EPSS clients are
all tested against recorded fixture payloads through `httpx.MockTransport`; a
suite that depends on CISA or NIST being reachable fails offline and on a plane.

Database migrations run automatically on first engine use. To drive them by hand
from `backend/`: `alembic current`, `alembic upgrade head`,
`alembic revision --autogenerate -m "..."`. The URL comes from the same
environment the app reads, so no alembic.ini edit is needed.

## 3. Invariants you must not break

- CVSS -> severity bands (derive_severity in app/scanner/matcher.py): 0.0-3.9 Low,
  4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical. Total over 0.0-10.0; raises
  outside that range. Property 4 depends on this.
- A severity and a score are INDEPENDENT facts, and neither may be invented from
  the other (resolve_severity in app/scanner/matcher.py; Req 2.6, 2.7, Property
  15). An advisory publishing a qualitative word and no vector keeps that band
  and records NO score -- do not reconstruct a number inside the band. One
  publishing neither is Severity.UNSCORED with a null score -- do not substitute
  a default. `cvss_score` is nullable everywhere, and null means "nobody
  published one", never 0.0.
  UNSCORED ranks below CRITICAL and above HIGH (SEVERITY_RANK in app/enums.py,
  mirrored in frontend/src/lib/severity.ts): an unmeasured finding could be
  either, so ranking it last is the same silent all-clear that the old
  substituted 5.0 was. Anything that orders findings ranks by severity first and
  states its null ordering explicitly -- SQLite and PostgreSQL disagree about
  where NULLs land in a DESC sort (Req 10.12).
  The severity list is mirrored by hand across app/enums.py, frontend types.ts
  and frontend lib/severity.ts; backend/tests/test_severity_parity.py fails if
  they drift. Add a band in one place and that test tells you the other two.
  **The NVD path deliberately differs**: it DROPS a CVE it cannot score rather
  than reporting it UNSCORED, because CPE matching returns everything for an OS
  CPE under a 250-finding cap and unscored entries sort first. Read the
  docstring on parse_nvd_response before "fixing" the inconsistency.
- A dependency list contains only names the package manager named as packages
  (_parse_dependencies in app/scanner/collectors.py; Req 10.13, Property 16). No
  file path, soname, apk so:/cmd:/pc: capability, rpm rpmlib()/config()/rtld()
  internal or version constraint. The filters run on the RAW token, BEFORE the
  "(" and ":" splits -- reversing that order is what made the rpmlib filter
  dead code for five releases, and applied to apk it turns
  so:libc.musl-x86_64.so.1 into a package named "so" that everything depends on.
  An arch-qualified or versioned rpm provide -- rpm-libs(x86-64),
  rocky-repos(9) -- IS a real package: do not drop every token with parentheses.
  Fixtures live in backend/tests/test_dependency_parsing.py and are real
  container output. Add a distro by capturing its output, not by writing it.
- Per-target fault isolation & timeout architecture (ScannerEngine): a ConnectionError /
  socket timeout / unhandled runtime exception -> CONNECTION_FAILURE, an AuthError ->
  AUTH_FAILURE, and a refused SSH host key -> HOST_KEY_MISMATCH / HOST_KEY_UNKNOWN for
  that target; a failing target NEVER aborts the batch or causes an HTTP 500.
  LinuxCollector separates TCP connect timeout (_CONNECT_TIMEOUT = 5.0s) from package
  database query timeout (_COMMAND_TIMEOUT = 45.0s). Property 1 depends on this.
- Collectors are read-only. They may only issue inventory-read commands (os-release,
  package queries, kernel/reboot probes, Get-CimInstance / registry reads). Never add
  install/remove/write commands. Req 1.3 and the collector integration tests enforce
  this, and `test_linux_ssh_issued_commands_are_read_only` treats ANY `>` other than
  `2>/dev/null` as a write -- capture output into a shell variable instead of
  redirecting to /dev/null. Do not loosen that guard to make a command pass.
- SSH auth: `Credentials` carries exactly one of `password` / `private_key` (both
  `SecretStr`). Keys are parsed in memory via `parse_private_key` and NEVER written to
  disk. Parse before allocating a client so a bad key is reported as a key problem, not
  a connection failure. `CVEDECK_DEFAULT_SSH_KEY_PATH` provides the Phase B server
  key, re-read per scan so rotation needs no restart; it applies to Linux only, since
  WinRM has no SSH-key equivalent. A credential failure isolates to its own target.
- Graceful degradation: a None/unreachable data-source client is recorded as
  DATA_SOURCE_UNAVAILABLE and skipped; matching still completes against the reachable
  source. Property 5. This covers *outages only*: `Matcher.match` re-raises
  NameError/TypeError/AttributeError/ImportError rather than reporting them as an
  unavailable source. Never widen those handlers back to a bare `except Exception` --
  a defect reported as an outage yields a silent zero-finding scan behind a green
  success badge (see CHANGELOG 0.3.1).
- The matcher can only degrade if the client *raises*. A data-source client must raise
  when any query goes unanswered -- transport error, non-2xx (including OSV's 400 for
  an ecosystem it does not have), unparseable body -- and must never return an empty
  result in its place, or cache a failure as a negative result. `OsvHttpClient` did
  exactly that until 0.6.0: an OSV outage produced a complete, zero-finding scan, and
  the matcher's degradation test stayed green because it used a fake client that
  raised. So: **tests for degradation drive the real client** through a mocked
  transport (`tests/test_osv_client_failures.py`), and a new one is run against the
  broken behaviour once to prove it can fail. A seam tested in isolation is a claim
  about one side of it.
- A platform whose inventory cannot be matched is refused, not scanned (Req 10.8).
  Windows is refused at `POST /api/scans` with a 422 and a reason, and the dashboard
  does not offer what the API refuses (`isScannable` in `src/lib/platform.ts`). A
  mixed batch is refused whole -- dropping the unscannable targets would report the
  batch as complete when part of it was never attempted. Lift this only together with
  real Windows matching and tests that prove a Windows host can produce findings.
- Threat-intel enrichment is three-valued, and the three values are never collapsed.
  `kev_listed = NULL` means "not checked"; `kev_listed = False` means "checked, and
  genuinely absent from CISA's catalogue"; `True` means listed. This holds in the ORM
  column, the API schema, `src/types.ts`, and the rendered table -- which is why
  `isKnownExploited` in `src/lib/intel.ts` uses `=== true` rather than a truthiness
  check, and why the API client maps with `?? null` rather than `?? false`. Rendering
  NULL as "not exploited" would tell an operator their fleet is clear on the basis of
  a feed that was never downloaded: the same class of silent false negative as a
  partial scan reported clean. `FindingEnricher.enrich` only writes a `False` when the
  feed is *usable* (successfully refreshed AND non-empty); an unusable feed leaves
  every enrichment field NULL. Same reasoning as `last_scan_sources_ok`.
  `FindingEnricher.reapply_to_stored` applies the identical rule to findings already
  in the database (Req 10.15). It is the riskier of the two: it runs after every
  refresh, over the whole fleet at once, so an unusable feed there would rewrite
  every finding rather than one scan's worth. It must never clear a signal -- only
  a *usable* catalogue may set `False`, and EPSS only ever writes scores it has.
- A failed feed refresh never overwrites a good cache. `FeedRefreshService` records the
  failure and leaves the previous catalogue in place, because yesterday's KEV answer
  beats no answer. An empty catalogue returned with HTTP 200 is treated as a *failure*
  rather than written -- writing it would erase every exploitation flag in the fleet.
  `last_refreshed_at` advances only on success, so the dashboard reports the age of the
  data rather than the age of the last attempt.
- Enrichment must never cost a scan its findings. `ScannerEngine._enrich` catches and
  logs; the findings persist unenriched (visibly, as NULLs). Collected inventory is the
  expensive part of a scan -- an SSH round trip to every host -- and a local cache
  lookup layered on top must not be able to discard it.
- Routing is hash-based, and must stay that way. `src/lib/useUrlState.ts` puts
  navigation in the fragment (`#/machines/web-01`), never in the path. The dashboard is
  served by FastAPI's StaticFiles mount and typically sits behind whatever reverse proxy
  the operator already runs; a path route would 404 on refresh unless every deployment
  grows an SPA fallback, which is a support burden paid by users to buy a prettier URL.
  A fragment never reaches the server. `parseHash` must also stay total: it falls back to
  the fleet view for anything unrecognised, and guards `decodeURIComponent`, which throws
  on a malformed escape -- a shared link is exactly the thing that arrives truncated.
- **Vulnerabilities and fixes are judged against the host's own distribution release
  (Req 14.7, 14.8).** OSV lists one entry per release, each with its own fix. Never take
  a fix from another release's entry and call it installable -- that put Debian 14 fixes
  into a Debian 13 host's apt plan, where they could never clear. And never *drop* an
  advisory unless the release-specific answer is complete and the release is known to
  OSV (it appears in the scan's advisories): an untracked release answers with silence,
  and silence must not turn a host clean. `app/scanner/releases.py` holds the release
  names, verified against the live API; `tests/test_release_matching.py` pins the drop
  and no-drop cases. Only the "(fixed in V)" note contains the words "fixed in".
- **Every route is protected unless it is on the public allowlist (Req 16.1).**
  `require_principal` is attached to whole routers in `create_app`, never per route, so
  a new route is protected by default. The allowlist is five routes -- health, and auth
  state/setup/login/logout -- pinned in `tests/test_auth_enforcement.py`, which
  discovers routes from the app and fails if anything else answers an anonymous caller
  (Property 12). Adding to the allowlist is a security decision: update the spec, the
  test and DEPLOYMENT.md in the same change.
- **Passwords, session tokens and API tokens are stored only as hashes and never
  logged.** Passwords use scrypt (`app/auth/passwords.py`); tokens use SHA-256
  (`app/auth/tokens.py`), which is right only because they carry 256 random bits. The
  first-run setup code is the one secret deliberately written to the log: whoever can
  read the log can already read the database. Auth tables are outside `_SYNC_ORDER`
  and must stay there.
- **Login fails closed.** `config.auth_enabled()` is true for every value of
  `CVEDECK_AUTH` except the explicit "off" spellings, so a typo leaves login on; this
  is the opposite default to demo mode, for the same reason. A cookie-authenticated
  request that changes state must carry a same-origin `Origin`/`Referer`; bearer
  tokens are exempt because browsers never send them on their own.
- **Tests that are not about auth sign in with `override_auth(create_app())`**
  (`tests/auth_helpers.py`). Never make the gate optional in `create_app` or disable it
  globally in `conftest.py` -- that is exactly the injected-seam coverage hole CHANGELOG
  0.3.1 records.
- **Never write a colour literal outside the palette blocks.** Not in CSS rules,
  not in a JSX `style` prop. A hardcoded colour cannot be reached by the token
  layer and therefore cannot be reached by the theme toggle, which is how light
  mode was silently half-broken for five releases. v0.5.2 removed 138 of them
  (102 in `index.css`, 36 in TSX inline styles), all Tailwind defaults. Black
  box-shadows are the one exception. If a colour is needed, add a token.
- **Colour is scarce in the DATA, not in the interface.** Three data tiers:
  the amber `--critical`/`--high`/`--medium`/`--low` ramp for severity, and
  `--exploit` red for confirmed exploitation only. The interface gets exactly
  one accent (`--accent`, verdigris) which must never appear in the data and
  must stay chromatically clear of both amber and red. Making the accent neutral
  to "keep colour scarce" was an over-correction that left the primary action
  grey on grey -- the rule governs meaning, not energy. `--exploit` must never be aliased to `--critical`: when
  they shared red, nine red criticals and three red exploitation marks competed
  and the eye found neither, which defeats the ranking the product is built on.
- Hostnames render as stamped asset tags (`.hostname-link`), and the tag's left
  edge repeats the exploitation state so it survives without colour vision. Keep
  the label motif on hostnames; the moment it spreads to buttons and chips it
  stops being a signature and becomes a theme.
- Fonts are vendored under `src/fonts/`, never fetched. A request to
  fonts.googleapis.com silently never resolves on the isolated networks this
  scanner runs on, and it reports the IP of a machine running a vulnerability
  scanner to a third party. Both families are SIL OFL.
- **Responsive rules are verified by measurement, not by screenshot.** Windows
  headless Chrome enforces a minimum window width, so `--window-size=390` renders
  at roughly 600px and crops the image to 390 — which looks exactly like
  horizontal overflow and once produced a confident, wrong bug report. Render
  inside a 390px iframe, which gets a real layout viewport, and assert
  `documentElement.scrollWidth === clientWidth`.
- **Watch flex-basis when a container switches to `flex-direction: column`.**
  The basis applies to the main axis, so `flex: 1 1 280px` silently becomes a
  280px *height* that then grows. That cost about 360px of dead space on the
  fleet view before anyone noticed.
- Below 700px the fleet table re-flows into cards using `data-label` on each
  `<td>`; column priority below that uses `data-col` names, never `nth-child`,
  because the optional select column shifts every index.
- The theme is three-valued: light, dark, or system. `useTheme` stamps `data-theme` on
  `<html>` for an explicit choice and *removes* it for "system", which is what hands
  control back to the media query. A two-state boolean would pin the theme on first click
  and make "follow the OS" unreachable forever. Colours must be reachable from tokens for
  this to work at all: a rule hardcoding a colour and a `prefers-color-scheme` block
  patching it cannot be overridden by an attribute, which is how light mode was quietly
  broken before v0.5.1.
- Display labels live in `src/lib/labels.ts`, once. The drill-down used to carry private
  copies of `severityLabel` and `remediationStatusLabel`, and the two remediation
  implementations disagreed ("In progress" vs "In Progress") with nothing importing the
  shared one. Nobody saw the bug because the duplicate was dead -- which is the point: a
  second implementation is a trap, not redundancy.
- Sync durability: local is the source of truth. If the online DB is unreachable,
  rows stay PENDING_SYNC and nothing is written online; on reconnect the online DB
  converges to local and package_identifier + dependency_path_id are preserved.
  Properties 10 and 11.
- Matcher Precision, Concurrency & 3-Tier Classification:
  - `_extract_fixed_version` in `osv_client.py` strictly validates `aff["package"]["name"] == package.name` and release-specific range events so companion packages (e.g. `xorg-server`) never leak fixes into target packages (`xwayland`).
  - Ubuntu targets query Ubuntu release trackers exclusively to eliminate Debian version suffix contamination (`+deb12u3`).
  - Multi-distribution ecosystems (Alpine `apk`, RHEL/CentOS/AlmaLinux/Rocky/Oracle/Amazon/Fedora `rpm`, Arch `pacman`, openSUSE/SLES `zypper`) use a 5-tier resolution pipeline with a universal fallback querying every ecosystem in `_ALL_LINUX_ECOSYSTEMS` in parallel.
  - Cross-distribution family normalization in `_extract_fixed_version` ensures Enterprise Linux derivatives (AlmaLinux, Rocky Linux, Oracle Linux) seamlessly inherit upstream Red Hat fixed versions.
  - Findings are deduplicated per `(cve_id, package_name)`, prioritizing records with actionable `fixed in ...` versions.
  - **OSV ecosystem names must be ones OSV actually accepts.** `/querybatch` rejects the
    ENTIRE batch with HTTP 400 on a single invalid ecosystem, so one bad name in
    `_ALL_LINUX_ECOSYSTEMS` defeats batching for every package reaching the universal
    fallback and degrades the scan to one request per package per ecosystem. `Arch Linux`
    and `Fedora` are NOT valid ecosystems; neither are `Oracle Linux` or `Amazon Linux`.
    Distributions without their own tracker map onto the upstream they derive from.
    `Red Hat` is queried UNVERSIONED -- OSV accepts `Red Hat:9` but returns nothing for it,
    so a suffix silently loses every finding. `tests/test_ecosystem_resolution.py` guards this.
  - The unknown-distribution fallback is `unknown` (routing to the universal fallback),
    never `deb`. Assuming Debian on an unrecognized distro produces confident wrong answers.
  - Advisory querying uses a thread pool of 25 workers (`_DEFAULT_MAX_WORKERS = 25`), HTTP connection pooling (`_DEFAULT_POOL_SIZE = 50` keepalive / 100 max connections), and thread-safe in-memory caching (`self._advisory_cache`) across scans to keep scan times fast even for systems with 1,000+ packages.
  - Any test for `OsvHttpClient` that injects an `http_client` skips the branch that
    builds the client itself -- the only branch deployments take. Keep
    `tests/test_osv_client_live_path.py`, which covers that branch with no injected
    client; it exists because a missing constant there went undetected by 215 passing tests.
- Remediation is manual only. No scheduler, thread, timer, or background trigger may
  be added to RemediationService. Req 4.5 and tests/test_remediation_smoke.py guard this.
  The frontend generates commands for the user to run; it never executes one.
- Remediation tooling lives in `src/lib/remediation.ts` and is selected from the
  MACHINE (platform + OS name), never by substring-matching a package identifier.
  Unanchored matching caused real bugs: `includes("ol")` matches `tool`/`console`/
  `golang`, `includes("arch")` matches `libarchive`/`noarch`. Ecosystem matching is
  anchored to the prefix. An unknown distro emits a comment, never a guessed command.
  Ubuntu-only advice (Ubuntu Pro / ESM / do-release-upgrade) is gated on `isUbuntu`.
- Clipboard access goes through `src/lib/useClipboard.ts`, never `navigator.clipboard`
  directly. That API is undefined on plain-http origins -- how a LAN deployment is
  reached -- so a bare call silently no-ops. The hook falls back to `execCommand`,
  reports failure through a toast, and announces success via `aria-live`.
- Fix availability comes from the backend's `has_fix` / `fixed_version` fields, not
  from searching `package_identifier` for the substring "fixed in". Prose is not an
  API contract.
- API/frontend key mapping: the backend serializes snake_case (machine_id, cve_counts,
  cvss_score, remediation_status, ...); the frontend uses camelCase. src/api/client.ts
  owns the mapping. If you add a field, update the wire interface AND the mapping
  function there. Do not push snake_case into src/types.ts. Build test fixtures with
  `src/test-utils/factories.ts` so a new field does not break every fixture.
- Trust signals: a scan is not trustworthy just because it returned. A SUCCESS whose
  advisory source was unreachable is a silent false negative, so `MachineScan` carries
  `unavailable_sources` / `sources_ok`, it is persisted as
  `target_machines.last_scan_sources_ok`, and the UI must render it. Never report a
  partial scan as clean. A source that is not *configured* is not "unavailable" --
  counting it would mark every scan partial and train users to ignore the warning.
  `ScanStatus.NEVER_SCANNED`, not `CONNECTION_FAILURE`, is the state of an enrolled
  but unscanned host, and it renders neutral rather than red.
- Error surfacing: `src/api/client.ts` must read the response body and report
  FastAPI's `detail`; a bare status code tells the user nothing. Every request carries
  a deadline. User-facing errors go through `ToastProvider`, not `alert()` or a
  view-local banner. Display labels live in `src/lib/labels.ts` -- never render a raw
  enum value like `connection_failure` in the UI.
- Frontend shared modules: display labels in `src/lib/labels.ts`, remediation tooling
  in `src/lib/remediation.ts`, clipboard in `src/lib/useClipboard.ts`, platform
  inference in `src/lib/platform.ts`, sorting in `src/lib/useSort.ts`, control
  a11y props in `src/lib/a11y.ts`, dialog a11y in `src/components/Modal.tsx`,
  notifications in `src/components/Toast.tsx`, empty states in
  `src/components/EmptyState.tsx`. Each replaced logic duplicated across views;
  do not reintroduce a view-local copy. `inferPlatform` in particular had two
  disagreeing implementations that classified the same host differently.
- Interactive non-button elements (clickable rows, sortable headers) must use
  `toggleButtonProps` / `clickableProps` from `src/lib/a11y.ts`: role, tabIndex,
  AND both Enter and Space. An `onClick` on a bare `<div>` is unreachable by
  keyboard and invisible to assistive technology. Prefer a real `<button>` where
  the element is genuinely a control -- the triage cards and severity chips are
  buttons with `aria-pressed`, which needs no helper and cannot drift from it.
- Empty states must name the filter actually excluding rows and offer to clear it.
  Guessing ("No machines match ''" when the platform filter was responsible) sends
  users to the wrong control.
- Bulk scans go through `POST /api/scans` with a multi-target array and no
  credentials, relying on the server key. `GET /api/health` reports
  `capabilities.server_ssh_key`; hide the controls when it is false rather than
  offering a button that must fail.
- Frontend Build, Master-Detail & Accessibility Invariants:
  - In `frontend/package.json`, keep `"build": "tsc --noEmit && vite build"`. Do NOT use `tsc -b` as the project does not use TypeScript composite project references.
  - In `MachineDrillDownView.tsx`, preserve accessibility labels & headings:
    - `<h2 className="view-title">CVE Findings for {hostname ?? machineId}</h2>`
    - `<label htmlFor="drilldown-severity-filter">Filter by severity</label>`
    - `<input aria-label="Search CVE findings" />`
    - `aria-label="Back to machines"`
    - `remediation-status-${cveId}`, `remediation-note-${cveId}`, `Save remediation for ${cveId}`
  - Keep client-side pagination (15 / 25 / 50 / 100 items per page) in Master list and Package views to avoid DOM rendering lags.
- Network Discovery Invariants:
  - `NetworkDiscoveryEngine` in `app/scanner/discovery.py` is strictly read-only and
    credential-free. It uses only ICMP ping (subprocess), TCP `connect_ex`, and
    unauthenticated banner reads. Never add credential-based probes to this module.
  - Discovery sweep is limited to /20 (4096 addresses) to prevent resource exhaustion.
    The API endpoint (`POST /api/discovery/sweep`) enforces this server-side.
  - Banner parsers (`_parse_ssh_banner`, `_parse_http_banner`, `_parse_smb_banner`)
    extract product/version from protocol-standard fields only. SSH uses RFC 4253
    identification strings; HTTP uses the `Server` response header; SMB uses protocol
    negotiation responses.
  - Discovery types follow the same snake_case (backend) / camelCase (frontend) mapping
    convention as all other API types. Wire shapes live in `client.ts`; domain types in
    `types.ts`. See the API/frontend key mapping invariant above.
- Schema changes ship with an Alembic revision. `app/data/schema.py` and
  `app/data/migrations/versions/` must agree; a column added to one without the other
  breaks every existing deployment on upgrade. Enum value changes need a data
  migration, not just a revision (enum values are persisted). The container image
  packages `backend/alembic.ini` to `/app/alembic.ini` and `migrations/env.py` checks
  file existence defensively.
- Scan Form field alignment: `.scan-form-grid` uses `align-items: start` and labels
  must maintain uniform single-line height across all columns. Dynamic badges (such as
  the platform auto-detection indicator) render underneath the form control as a helper
  hint rather than inline with the `<label>` so input fields remain aligned across rows.
- Top-Level Workspaces & Navigation Structure:
  - Top navigation bar provides 3 dedicated workspaces (`📊 Fleet Overview`, `🚀 New Scan`, `🔍 Network Discovery`).
  - Scanning is isolated into its own dedicated view rather than pinned permanently on top of the fleet list.
  - Fleet Overview leads with 4 triage cards (`Actively exploited`, `Critical findings`, `High findings`, `Needs attention`), each a real `<button>` with `aria-pressed`. Every card counts HOSTS and states its unit; findings totals live in a separate strip below that doubles as the severity filter. Keeping those two units visually distinct is the point -- an earlier layout stacked two five-card rows of identical weight where one counted hosts and the other findings.
  - `Needs attention` groups stale, never-scanned and failed hosts. Separately they were separately ignorable; together they answer "whose data can I not trust right now".
  - Navigation is URL-backed (`#/fleet`, `#/scan`, `#/machines/<id>`), so screens are linkable and browser back works. See the routing invariant in section 3.
  - Quick-scan triggers (`⚡ Scan`) from Fleet or Discovery pre-fill `ScanFormView` and seamlessly switch to the `"scan"` workspace.
  - Drill-down sub-tabs (`🚀 Ready to Fix`, `⏳ Pending Vendor Patch`, `📋 All Findings`, `📦 By Package`, `🌳 Dependency Map`) maintain keyboard navigable tab semantics and preserve all accessibility contracts.
  - The drill-down header is a single `host-summary` strip -- exploitation state, severity chips, remediation progress -- sharing `.sev-chip` with the fleet view so the two screens read as one product. It replaced five KPI cards and a full-width progress card that cost ~250px and duplicated counts the sub-tabs already carry.

- Demo mode must refuse every route that reaches the network. `CVEDECK_DEMO_MODE`
  exists so strangers can click around a populated dashboard; the seeded fleet is
  the harmless half. `POST /api/scans`, `POST /api/discovery/sweep`, and
  `POST /api/scans/test-connection` each take a hostname or a CIDR plus
  credentials and connect to it, so an unguarded public instance is an SSH/WinRM
  client and port scanner anyone can aim at any address, sourced from the
  operator's IP. If you add a fourth route that dials out, add the guard --
  `tests/test_demo_mode.py` asserts each one individually for exactly this
  reason.

  The guard is a route-level dependency (`dependencies=[Depends(_demo_guard(...))]`),
  not a check in the handler body. FastAPI resolves a handler's parameter
  dependencies before its body runs, so a body check let the `ScannerEngine` be
  constructed first and surfaced its failure instead of the 403.

- The demo seed must not misrepresent anything. It is what strangers and
  screenshots see, which makes it the easiest place to introduce a
  comfortable-looking lie. `kev_listed` keeps all three states, an unenriched
  finding is NULL across every enrichment column rather than half-answered, and
  a host that never scanned successfully carries no findings. Package
  identifiers are built in the format `routes._parse_fixed_version` and
  `_parse_pkg_name` actually parse -- if that drifts, every demo finding
  silently becomes "Pending Vendor Patch" with nothing failing.

## 4. Conventions

- Add/extend tests with any behavior change. Pure/logic layers get property-based
  tests (Hypothesis / fast-check, min 100 iterations, tagged with the feature name
  and the property number). I/O layers (SSH/WinRM, API contracts, UI) get
  example/integration tests. This split is described in design.md "Testing Strategy".
- Keep the ORM models (app/data/schema.py) separate from the Pydantic domain models
  (app/models.py) and the API schemas (app/api/schemas.py). Map between layers; do
  not collapse them.
- Enum string values are persisted and serialized. Changing a value is a
  data-migration concern, not a rename.
- FastAPI dependencies (get_session, get_scanner_engine, get_sync_service) are
  overridable so tests inject in-memory sessions / stubbed engines and never touch
  real hosts or an online DB. Preserve that seam. Production implementations live
  in `app/api/wiring.py` (which wires `OsvHttpClient`).
- Read configuration through app/config.py, not os.environ directly, so every knob a
  deployment can turn is discoverable in one place (and documented in DEPLOYMENT.md).
- The frontend has no runtime dependencies beyond react and react-dom, and nothing
  it renders is fetched from a third party at load time. Fonts are vendored and
  icons are inlined SVG (`components/Icon.tsx`) for the same two reasons: this is
  a scanner run on isolated networks, where a CDN request never resolves and the
  design that ships is not the design anyone sees; and a dashboard load should
  not report the IP of a machine running a vulnerability scanner to a third
  party. Do not add an icon font, a CDN stylesheet, or a UI framework.
- Use the tokens in `index.css`. Type, spacing, radius, shadow and scrim all have
  scales; a literal in a rule is how the stylesheet drifted to 25 font sizes and
  20 bypassed radii the first time. If a value does not exist, add a step and say
  why rather than writing the number inline.
- Colours are `light-dark()` pairs defined once in `:root`. Do not reintroduce a
  parallel palette block per theme -- there were two identical ones, and every
  light-theme change had to be made twice.
- Icons are decorative and `aria-hidden`; the adjacent text is the accessible
  name. Do not put an icon in a label that tests or screen readers depend on.
- Pin dependency versions and prefer well-known packages. Runtime pins live in
  backend/requirements.txt and test-only pins in backend/requirements-dev.txt; keep
  them in step with pyproject.toml. Do not commit secrets; credentials are passed at
  request time and Credentials uses SecretStr so it is not logged or serialized.

## 5. Shipped behaviour, follow-ups & research tracks

This section used to be one list titled "known follow-ups", which by 0.8.0 held
as much shipped behaviour as roadmap -- an entry marked **Implemented** reads as
a plan until you notice the word. What has shipped is a constraint on your
change; what has not is context.

### 5.1 Shipped, and how it must keep behaving

- **Linux-First Execution Focus**: The active production scanner, advisory matching engine (OSV.dev + Ubuntu Tracker), blast-radius reverse dependency graph, and per-distribution remediation commands (`apt`, `dnf`, `apk`, `pacman`, `zypper`) are optimized for Linux, where non-invasive SSH inventory extraction is fully proven. Covered distributions: Debian, Ubuntu, Raspbian, RHEL, CentOS, AlmaLinux, Rocky, Oracle Linux, Amazon Linux, Fedora, Alpine, Arch, openSUSE, SLES, Wolfi, Chainguard.
- **SSH key authentication, Phases A and B**: Ed25519/ECDSA/RSA in PEM or OpenSSH
  format via `Credentials.private_key` + `passphrase`, parsed in memory by
  `parse_private_key`; and the server-managed keyring
  (`CVEDECK_DEFAULT_SSH_KEY_PATH` / `CVEDECK_DEFAULT_SSH_USER`), which lets a
  target omit credentials entirely.
- **Pinned SSH host keys** (Req 17). Both SSH paths connect through
  `app/scanner/host_keys.py:connect_pinned`, keyed by `(hostname, port)` in
  `ssh_host_keys`. Trust on first use by default, `CVEDECK_SSH_HOST_KEY_POLICY=strict`
  to refuse unpinned hosts. A changed key is `HOST_KEY_MISMATCH`, never a
  connection failure, and only forgetting a pin removes one.
  Do not add a second SSH connect path that bypasses the helper.
- **A connection test dials what a scan would dial** (Req 10.9): the configured
  SSH port, or the configured WinRM scheme and port. Both hardcoded their
  defaults once, and a pre-flight that succeeds over a transport the scan does
  not use is evidence about the wrong path.
- **Real NVD 2.0 HTTP client** (`NvdHttpClient`, v0.5.0). Opt-in via
  `CVEDECK_NVD_ENABLED` because NVD allows only 5 requests / 30s without a key
  (50 with one, via `CVEDECK_NVD_API_KEY`). Left off, `wiring.build_nvd_client`
  returns `None`, which the matcher reads as "not configured" rather than "down", so
  scans are not marked partial. Matches by CPE product+version -- never a free-text
  keyword search, which would attach loosely related CVEs to every host -- and caps
  results at 250, highest CVSS first, since an OS query can legitimately match
  thousands of CVEs spanning a decade.
- **Threat-intel enrichment (KEV + EPSS)** (v0.5.0). Unlike OSV, these are
  small complete files published daily, so they are downloaded whole into
  `kev_entries` / `epss_scores` and joined locally rather than queried per finding.
  Refresh is still manual (`POST /api/feeds/refresh`) -- it becomes the first consumer
  of the scheduler when that lands.
- **Scan history and finding diffs** (Req 18). `Repository.save_findings`
  returns a `FindingDiff` keyed on CVE + package name (never version), and
  `DeploymentScannerEngine._record_scan_status` writes a `scan_runs` row for every
  attempt. Trust rules: a partial scan resolves nothing and keeps unreported findings,
  a failed scan records no counts, a machine's first successful run is a baseline.
  NULL counts mean "not assessed" and must never be rendered as 0.
- **Fleet-wide reads are batched.** `GET /api/cves` and `GET /api/machines` cost
  a fixed number of statements whatever the fleet size, through
  `latest_successful_runs`, `new_finding_keys_for_runs`,
  `latest_remediation_records` and `host_key_pins`. A per-machine query inside a
  fleet-wide loop is invisible on a fixture and grows in production; there is a
  statement-count test guarding it.
- **An unassessed value is never presented as a benign one** (Req 10.10, and
  the enrichment invariant it extends). `blast_radius` is `None` where the
  dependency graph was not built -- the fleet-wide list does not load inventory
  -- and the dashboard shows "Not assessed" while the export writes
  `not assessed`. Do not reintroduce a `?? "low"`: it reads as a default and
  lands as a claim. The same applies to the scan-change counts and every
  enrichment field.
- **Exports are neutralised and complete** (Req 8.9, 8.10). `escapeCsvCell`
  prefixes a cell a spreadsheet would evaluate, and the exports carry the
  exploitation signals plus, for the fleet, when each host was scanned and
  whether its counts are complete. A new export column that can be unknown must
  say so in words; a spreadsheet has no tooltip.
- **Sync propagates rows, never deletions.** A replaced finding, a pruned scan
  run and a forgotten host key all stay in the Online_Database. See the
  methodology document §14 for why, and do not describe the online store as
  converging on the local one.
- Schema migrations use Alembic (`backend/alembic.ini`, `backend/app/data/migrations/`).
  `app/data/migrations_runtime.py:upgrade_to_head` runs on first engine use and handles
  three cases: an empty database is created from ORM metadata and stamped `head`; a
  pre-Alembic database (tables but no `alembic_version`) is stamped at
  `BASELINE_REVISION` then migrated forward; an already-managed database is upgraded.
  Generate revisions with `alembic revision --autogenerate -m "..."` from `backend/`.
  The env resolves the URL through `app/config.py`, never alembic.ini, so migrations
  always target the database the app uses. `render_as_batch` is on because SQLite
  cannot ALTER COLUMN. Never add a column to `app/data/schema.py` without a revision.
- Deployment runs a single uvicorn worker because the engine is a process-wide
  singleton over SQLite (one writer). Multiple workers require PostgreSQL via
  CVEDECK_DB_URL.
- Single account, no roles (Req 16). Any signed-in session or API token can do
  everything except manage the account. Multiple users and scoped or read-only tokens
  are follow-ups; the `users` table already allows more than one row.
- POST /api/scans accepts target credentials in the request body, so an instance
  beyond a trusted network needs TLS in front of it, login or not.
- A feed refresh reapplies the feeds to findings already stored (Req 10.15), on all
  three trigger paths -- the route, the CLI and the periodic task -- because they
  all go through `enrichment.refresh_feeds_and_reapply`. Add a fourth trigger by
  calling that, not by writing the sequence out again. Findings it changes go back
  to PENDING_SYNC, or an already-synced finding would keep the old exploitation
  status in the Online_Database for ever. Demo mode switches the periodic refresh
  off (`config.feed_refresh_hours_in_effect`), so the seeded never-checked findings
  stay never-checked.

### 5.2 Not built yet

- **Scheduled scanning.** Scans run **inline inside the HTTP request** (hence
  `proxy_read_timeout 900s` in DEPLOYMENT.md). Background execution
  (`scan_jobs` + a worker thread, no Celery/Redis -- one uvicorn worker, one SQLite
  writer) is the prerequisite for cron scans and progress reporting. No *scan* is
  scheduled and no remediation is automatic; both are deliberate for v1. The feed
  refresh got its own task in 0.8.7 (`services/feed_scheduler.py`) precisely
  because it needs none of that machinery -- it is idempotent, owns no
  transaction and keeps the previous cache on failure. Do not grow it into the
  general scheduler; a scan needs a job model, a queue and progress reporting.
- **Windows Research & Engineering Roadmap**:
  - *Track 1 (WinRM Inbound & Remote Auth)*: WinRM over HTTPS (port 5986), Kerberos SPN auth, and non-domain UAC token filter research (`LocalAccountTokenFilterPolicy`) without altering client host configurations.
  - *Track 2 (Push-Based Outbound Collector)*: Lightweight standalone PowerShell/Go collector running locally with zero inbound open ports required, pushing WMI/CIM/Registry inventory outbound to `POST /api/scans/ingest`.
  - *Track 3 (Advisory & CPE Correlation)*: Correlating Windows KB Quality Updates (`Win32_QuickFixEngineering`) and registry packages against Microsoft MSRC APIs and NIST NVD 2.0 CPEs.
- **SSH Phase C (Ephemeral Signed SSH Certificates)**: Enterprise CA integration
  (HashiCorp Vault / Teleport) for zero-trust infrastructure. Still open.
- **Phase 2 Unauthenticated Fingerprinting**: Extending `NetworkDiscoveryEngine` with deeper
  banner correlation against NVD CPEs and OSV advisories to flag network-exposed
  vulnerabilities from service versions discovered during Phase 1 sweeps.

### 5.3 Deferred, decided rather than missed

- **Whether a Windows connection test should be refused** the way Windows scans
  are (Req 10.8). It connects today, which is what makes the WinRM transport
  settings meaningful before Track 1 lands; revisit when it does.

## 6. Workflow expectations

- Make the smallest change that satisfies the requirement; do not refactor unrelated
  code opportunistically.
- Keep the spec (requirements/design) and the code in sync in the same change.
- Never commit secrets, credentials, or real hostnames from your own network --
  including in test fixtures. Placeholders belong in `.env.example`; see the RFC
  5737 addresses used in DEPLOYMENT.md for the house style.

  This rule is enforced rather than requested: `.githooks/pre-commit` refuses a
  staged credential-shaped file or a private key block, and
  `.githooks/pre-push` repeats the check over everything a push would publish,
  history included. Enable them once per clone with
  `git config core.hooksPath .githooks` -- that setting is local, so a fresh
  clone has them off.

  It is worth knowing why the rule names test fixtures specifically. A real host
  address from a developer's own network sat in a test fixture and a form
  placeholder here for several releases, read past by everyone, and was caught
  by the hook on its first run rather than by review. Addresses in this
  repository are loopback, RFC 1918 examples, or RFC 5737 documentation
  addresses, and nothing else -- see the methodology document's provenance
  section.
- Work on a branch and open a pull request; `main` is the release branch.
