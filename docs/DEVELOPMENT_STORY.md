# Development Story

A narrative record of how CveDeck was built, what went wrong, and why the code
looks the way it does. `CHANGELOG.md` records *what* changed; this document
records *why*, and what the change taught us.

New entries go at the bottom, newest last, so the document reads chronologically.

---

## Chapter 0 — Spec-first origins (v0.1.0 – v0.3.0)

CveDeck began in Kiro as a spec-first project. Requirements were written in
EARS form, the design named 11 correctness properties, and `tasks.md` was worked
top to bottom. Behaviour is anchored to the spec by "Req X.Y" references in code
and test names, and `AGENTS.md` §6 requires the spec and the code to move in the
same commit.

Three architectural bets shaped everything after:

1. **Agentless and read-only.** Nothing is ever installed on a target. Collectors
   may issue inventory-read commands only. This is an invariant, not a
   preference — it is what makes the tool safe to point at production.
2. **Layer separation.** Pydantic domain models (`app/models.py`), SQLAlchemy ORM
   rows (`app/data/schema.py`), and API schemas (`app/api/schemas.py`) are three
   distinct things that get mapped between, never collapsed.
3. **A property-based test core.** Pure logic (severity derivation, filtering,
   sync convergence) is tested with Hypothesis and fast-check at 100+ iterations;
   I/O layers get example and integration tests.

By v0.3.0 the product had a working OSV.dev matching engine, a blast-radius
reverse-dependency graph, credential-free network discovery, and a React
dashboard with no UI framework — `react` and `react-dom` are the only runtime
dependencies, and `src/index.css` is the single stylesheet.

---

## Chapter 1 — The scan that always found nothing (v0.3.1)

### What happened

A planning review of the Linux path turned up a reference to `_DEFAULT_POOL_SIZE`
in `app/scanner/osv_client.py` that had no definition anywhere in the module.

It sat inside `OsvHttpClient.match_packages`, in the branch that constructs its
own `httpx.Client`:

```python
client = httpx.Client(
    timeout=self._timeout,
    limits=httpx.Limits(
        max_keepalive_connections=_DEFAULT_POOL_SIZE,   # NameError
        max_connections=_DEFAULT_POOL_SIZE * 2,
    ),
)
```

That branch runs when no `http_client` is injected — which is precisely the
production path, since `wiring.build_osv_client()` passes none.

The resulting `NameError` was then caught by a bare `except Exception` in
`Matcher.match` and recorded as `SourceStatus.DATA_SOURCE_UNAVAILABLE`. So every
live scan completed "successfully" with **zero findings**, and the dashboard
painted a green `success` badge over it. A thoroughly vulnerable host and a
perfectly patched one were indistinguishable.

### Why 215 passing tests did not catch it

Every single existing OSV test injected an `http_client`, because that is the
clean way to test an HTTP client without network access. Injecting a client
takes the *other* branch. The suite had excellent coverage of the code paths
tests take and zero coverage of the one path deployments take.

This is the lesson worth keeping: **a dependency-injection seam is also a
coverage hole.** The parameter that makes a class testable defines a branch that
tests, by construction, never execute. Anywhere the production wiring passes
`None` to get default behaviour, something has to exercise that default.

### Why the bug was invisible rather than loud

Two design choices combined badly:

- `except Exception` around a data-source call cannot distinguish "OSV is down"
  from "this code is broken". Both became `DATA_SOURCE_UNAVAILABLE`.
- Graceful degradation was working exactly as designed — Property 5 says an
  unreachable source is skipped and matching completes against what remains.
  Applied to a defect instead of an outage, that same behaviour converts a crash
  into a silent false negative, which for a security tool is the worst possible
  failure mode.

Graceful degradation needs a blast radius. Degrading around someone else's
outage is resilience; degrading around your own bug is data loss.

### The fix

- Defined `_DEFAULT_POOL_SIZE = 50`, matching the "50 keepalive / 100 max
  connections" figures the AGENTS.md matcher invariant already documented — the
  constant had simply been lost, not mis-designed.
- `Matcher.match` now re-raises `NameError`, `TypeError`, `AttributeError`, and
  `ImportError` instead of reporting them as outages. Per-target fault isolation
  in `ScannerEngine` still prevents one bad target from aborting a batch, so this
  costs no resilience. Genuine network failures still degrade; Property 5 holds.
- Both handlers now log via `logging.exception`. Previously the failure produced
  no log line at all.
- `tests/test_osv_client_live_path.py` exercises `OsvHttpClient` and
  `wiring.build_osv_client()` with **no** injected client, asserting the pool
  limits, that the self-constructed client gets closed, that the matcher reports
  `OK`, that programming errors propagate, and that real outages still degrade.

### Verification

The fix was proved by re-introducing the bug and confirming four targeted test
failures, then by running the production path against the live OSV.dev API: an
Ubuntu 22.04 package set that returned 0 findings before the fix returned **160**
after, with correct `fixed in ...` versions.

### What changed in how we work

`AGENTS.md` gained two invariants: never widen the matcher's handlers back to a
bare `except Exception`, and keep a test that covers `OsvHttpClient` with no
injected client. Both encode a failure we cannot afford to repeat rather than a
style preference.

---

## Chapter 2 — Making failure visible (v0.4.0)

Chapter 1 fixed a bug that had hidden in plain sight for a release. The obvious
follow-up question was: what else can fail without anyone noticing? The answer
turned out to be most things.

### Four states that all rendered as "0 CVEs"

The fleet table showed a hostname, a platform, a status badge, and four severity
counts. A row reading `web-01 - linux - success - 0 0 0 0` could mean any of:

1. The host is genuinely clean.
2. The host was scanned while OSV was unreachable, so the findings are partial.
3. The host was scanned three months ago and nothing has looked since.
4. The host was enrolled from a discovery sweep and never scanned at all.

Only the first is good news. Case 4 was worse than invisible: enrollment stamped
`CONNECTION_FAILURE` on brand-new rows -- the code even had a comment calling it
"an accurate description of a scan that has not yet reached the host" -- so every
host added from discovery immediately showed a red failure badge for a
connection nobody had attempted. Users learned that red badges were noise, which
is precisely the wrong lesson for a security tool to teach.

### The data was already there

The striking thing was how little needed inventing. `MatchResult` had carried
`nvd_status` and `osv_status` since the beginning and simply dead-ended in the
matcher. `target_machines.last_scanned_at` had existed since v0.1.0 and was never
serialized into any API response. `ScannerEngine` captured the originating
exception on every failed scan and discarded it at the API boundary. Three
signals, all collected, none delivered.

The lesson generalizes: capturing a signal and surfacing it are separate pieces
of work, and finishing the first feels like finishing both. Each of these had a
plausible-looking implementation with a missing last mile.

### One judgement call worth recording

Reporting every unreachable source would have marked every scan partial, because
NVD was not wired up in any deployment at the time and its status was therefore
always `DATA_SOURCE_UNAVAILABLE`. Technically accurate; practically useless,
since a warning that always fires is a warning nobody reads.

> NVD was finally implemented in v0.5.0 (Chapter 8), but ships disabled by
> default, so this distinction still matters for exactly the same reason.

So `unavailable_sources` counts only sources that were actually configured.
Absent capability is a known limitation, documented once; an outage is a per-scan
anomaly worth interrupting someone about. Conflating the two would have destroyed
the value of the signal we had just built.

### Small things that turned out to matter

- **`client.ts` never read error response bodies.** Every failure surfaced as
  `Request POST /api/discovery/sweep failed with status 422`. The backend was
  sending `Invalid CIDR: '10.0.0'` the whole time; the client threw it away.
- **No request had a deadline.** A hung backend left the scan button disabled
  permanently, with a page reload the only way out.
- **`statusLabel` existed but was unreachable.** It was defined inside
  `ScanFormView`, so `MachineListView` -- 200 lines away in another file --
  rendered the raw enum `connection_failure` instead. Four error UIs had grown up
  the same way, including a native blocking `alert()` for form validation. All of
  it collapsed into `lib/labels.ts` and one `ToastProvider`.

### A test-fixture detour

Adding two fields to `MachineSummary` broke six test fixtures that had built the
type inline. The tempting fix -- make the new fields optional -- would have
weakened the type to keep tests compiling, which is exactly backwards. Instead
`src/test-utils/factories.ts` gives tests a builder that fills in whatever they
do not assert on. Future fields cost nothing.

### Migrations, finally

This chapter added a column and an enum value, which forced the issue AGENTS.md
had been deferring since v0.1.0: `Base.metadata.create_all` is not a migration
story. Alembic now runs on startup and handles the case that actually matters --
a v0.3.0 database with tables but no `alembic_version` -- by stamping the
baseline and migrating forward.

The backfill needed one piece of local knowledge: SQLAlchemy's `Enum` type
persists member names, not values, so the migration compares against
`CONNECTION_FAILURE` rather than `connection_failure`. Worth checking rather than
assuming; the wrong guess would have silently matched nothing and left every
enrolled host red.

The test for that backfill was itself wrong at first. It built the "legacy"
database with `Base.metadata.create_all` -- from the current metadata, which
already had the new column -- so the migration ran against a database that did
not need it, and the test proved nothing while passing. It now migrates to the
baseline revision and drops `alembic_version`, reproducing a genuine v0.3.0
schema that stays honest as more revisions land.

---

## Chapter 3 — Linux depth, and a second silent scanner (v0.4.0)

This chapter set out to do three ordinary things: add SSH key authentication,
collect more than two facts about a host, and support a few more
distributions. The third one turned up a bug as serious as Chapter 1's.

### The ecosystem names nobody validated

Extending distribution coverage meant adding Oracle Linux and Amazon Linux to
the OSV ecosystem resolver. Before writing the mapping, it seemed worth checking
what OSV actually accepts. It rejects both, with HTTP 400 and "invalid
ecosystem".

That prompted checking the names already in the code. Two of the ten entries in
`_ALL_LINUX_ECOSYSTEMS` -- the "universal fallback" every unrecognized package
routes through -- were also invalid: `Arch Linux` and `Fedora`.

The consequence is not what you would guess. OSV's `/querybatch` does not skip a
bad query and answer the rest; it fails the whole batch with
`error in query at index 1: invalid ecosystem`.

The client catches that failure and falls back to querying every item in the
chunk individually. So results were still correct -- and the entire batching
design, the thing AGENTS.md documents as keeping scans fast for hosts with
1,000+ packages, had never once worked for a fallback package. Roughly 10,000
individual HTTP requests where 20 batches were intended.

Chapter 1's bug returned zero findings. This one returned correct findings, just
a hundred times slower, which is even harder to notice. Both share a shape: an
error path that is too accommodating turns a defect into a degradation, and
degradations do not get reported.

A third finding came out of the same check. OSV accepts `Red Hat:9` and returns
zero results for it, while unversioned `Red Hat` returns 23 for the same
package. Versioning that ecosystem -- which is what I had just written, by
analogy with `AlmaLinux:9` and `Rocky Linux:9`, both of which do work -- would
have silently lost every Red Hat finding while looking entirely reasonable in
code review.

The lesson: for an external API, the set of valid values is not derivable from
the pattern of the values you already know. It has to be checked. The valid and
invalid sets are now pinned in `tests/test_ecosystem_resolution.py` so an edit
cannot reintroduce one, and no input is allowed to resolve to a name OSV would
reject.

### A read-only guard worth keeping strict

Batching the new kernel and reboot-required probes into the existing os-release
round trip failed `test_linux_ssh_issued_commands_are_read_only`. The offender
was `>/dev/null` in `command -v needs-restarting >/dev/null 2>&1` -- the guard
allows `2>/dev/null` and treats every other `>` as a filesystem write.

Writing to `/dev/null` is obviously harmless, and the fastest fix was to widen
the guard's allowlist. That would have been the wrong trade. The guard protects
the invariant that makes this tool safe to point at production, and a guard with
exceptions is a guard that accumulates exceptions. The command was rewritten to
capture output into a shell variable instead, so it contains no write redirect
at all and the guard stays absolute.

### Why the kernel probe exists

A host can have every package updated and still be running the vulnerable kernel
it booted from. A scanner that reads only the package database calls that host
clean. Collecting `uname -r` alongside the installed kernel package, plus a
reboot-required probe, closes a gap that is invisible by construction to
package-list-only scanning -- the same category of blind spot as the rest of
this chapter, just one layer further out.

### Keys never touch disk

`parse_private_key` loads Ed25519, ECDSA, and RSA keys from memory. The obvious
alternative -- write to a temp file, hand paramiko the path -- would take a
secret scoped to a single HTTP request and give it a lifetime bounded by the
filesystem and whatever cleanup code happens to run. Two smaller decisions
followed:

- Parsing happens before the SSH client is allocated, so a malformed key or a
  wrong passphrase is reported as a key problem instead of surfacing later as a
  generic connection failure. A test asserts the network is never touched.
- A wrong passphrase and a malformed key produce different messages, because
  they call for different actions from the user. Getting this right required
  checking what paramiko actually raises: a wrong passphrase on an RSA key comes
  back as `SSHException("Bad password or corrupt private key file")`, while the
  Ed25519 and ECDSA loaders report a type mismatch for the same input. Only the
  first means the passphrase is wrong.

### One ordering bug, caught by a table

`opensuse-leap` contains the substring `suse`, so the new SLES branch swallowed
openSUSE before its own branch could match. A parametrized table of eleven
distributions caught it immediately. The same substring hazard is why the
frontend's `getDistroTooling` -- where `includes("ol")` matches `tool`,
`console`, and `golang` -- is on the list for the next chapter.

---

## Chapter 4 — The fix commands that did not fit the host (v0.4.0)

The dashboard's headline feature is the copy-a-fix-command button. Two things
were wrong with it: the command was frequently for the wrong package manager,
and on most real deployments the button did nothing at all.

### Tooling chosen from the wrong thing

`getDistroTooling` inferred the distribution by substring-matching the *package
identifier*. Not the machine -- the package. That is the wrong input, and the
matching was unanchored, which made it wrong twice over:

```ts
low.includes("ol")    // matches tool, tools, console, symbol, protocol, golang
low.includes("arch")  // matches libarchive, noarch, search, architecture
```

So a Debian host with `python3-tools` installed was routed to `dnf`, and one
with `libarchive13` to `pacman`. Both produce commands that simply fail.

Worse, a Windows host has no Linux ecosystem prefix at all, so every one of its
findings fell through to the default branch and the UI confidently offered
`sudo apt install --only-upgrade` for a Windows package.

And there was a split personality: `copyFixCommand` -- a *second* copy helper
that hardcoded apt outright -- was wired to the By-CVE list, the By-Package
table, and the inspector pane, which are the three most-used surfaces. The modal
used the distro-aware path. So for the same CVE on the same AlmaLinux host, the
list said `sudo apt install --only-upgrade openssl` and the modal said
`sudo dnf upgrade -y openssl`. One of them was right.

The fix was to change the input, not to patch the matching: tooling now comes
from the machine's platform and OS name, with the ecosystem prefix consulted
only as an anchored fallback. `copyFixCommand` is gone.

Two smaller things fell out of doing this properly:

- **Arch gets `pacman -Syu`, not a single-package upgrade.** Partial upgrades
  are explicitly unsupported on Arch and routinely break the system, so the
  previous `pacman -S <pkg>` was actively harmful advice.
- **An unknown distribution now emits a `#` comment instead of a command.**
  Handing someone a confidently wrong command is worse than saying we do not
  know which package manager applies.

### The button that never worked on a LAN

Both copy helpers were guarded like this:

```ts
if (navigator.clipboard) {
  navigator.clipboard.writeText(cmd).then(() => setCopied(...));
}
```

No `else`. No `.catch()`. `navigator.clipboard` is undefined in any non-secure
context -- every origin except HTTPS and `localhost`. This tool is an internal
scanner reached at `http://192.168.1.50:8000`. So on the deployment this product
is designed for, the headline "1-click fix" silently did nothing: no error, no
fallback, no message. And when the API did exist but rejected on a permissions
failure, the missing `.catch()` turned it into an unhandled rejection.

`useClipboard` now tries the async API, falls back to `document.execCommand`,
reports failure through a toast, and announces success in an `aria-live` region
-- the confirmation was previously a checkmark swap that a screen reader would
never report.

This is the same failure mode as Chapters 1 and 3, one layer up: **a guard with
no else branch is an error path that reports nothing.** Three times now, in
three unrelated parts of the codebase, "handle the failure case by doing nothing"
has produced a bug that looked like working software.

### Prose as an API contract

`hasFix` was determined by searching the package identifier for the substring
`"fixed in"`, in nine separate places. That made the exact wording of a display
string -- assembled in `osv_client.py` for humans to read -- an unversioned
contract between backend and frontend. Rewording the identifier would have
silently emptied the "Ready to Fix" tab.

The backend now parses that structure once and sends `package_name`,
`fixed_version`, and `has_fix` as fields. The frontend prefers them and keeps the
prose check only as a fallback for findings served by an older backend.

### Persisting what we collect

Chapter 3 added kernel and reboot-required collection. This chapter noticed they
were being collected and thrown away -- the ORM had no column for either. That is
exactly the missing-last-mile mistake Chapter 2 was written about, committed
again one chapter later by the same author. They are now persisted.

The general shape is worth stating plainly: this codebase has repeatedly gotten
the hard part right and dropped the trivial part immediately after. The
interesting work -- probing the host, matching advisories, computing blast radius
-- is done well. Adding a column, reading a response body, writing an `else`
branch: that is where every bug in this release has been.

### An aside on tooling

Midway through rewiring the 1,791-line drill-down view, a scripted edit failed
partway through writing and truncated the file to zero bytes. The content was
recoverable from git, but the near-miss argued for the change that followed:
subsequent edits build the new content in full, assert it is plausible (length,
key markers present, encodes cleanly), write to a temp file, and only then
atomically replace the original. Worth doing for any programmatic edit to a file
that is not yet committed.

---

## Chapter 5 — The workflow the UI would not let you have (v0.4.0)

The last chapter of this pass was meant to be polish. It turned out to be mostly
about capability that already existed on the backend and had simply never been
exposed.

### An array that only ever held one element

`startScan` took `ScanTargetInput[]`. The backend mapped it to a batch, and
`ScannerEngine` had per-target fault isolation specifically so one bad host could
not abort the others. All of that was built, tested, and documented as an
invariant.

`App.tsx` called it as `api.startScan([target])`. Always exactly one.

So re-scanning a twenty-host fleet meant twenty passes through the form, retyping
a username and password each time, with a "⚡ Scan" button on each row that was
not a re-scan at all -- it just pre-filled the form and made you type the
credentials again. Phase 2's server-managed SSH key removed the credential
problem; this chapter removed the rest, and the backend needed no changes.

That is the third time in this release that the fix was to expose something
already built. It is worth naming the pattern directly: **the interesting half
of a feature gets finished, and the half that makes it reachable does not.** The
batching, the fault isolation, the source-status tracking, the `last_scanned_at`
column -- all correct, all invisible.

### Hiding a button is a feature

Fleet re-scan only works when a server key is configured. The options were to
show the button always and let it fail with a credential error, or to ask the
backend what it supports.

`GET /api/health` now reports `capabilities.server_ssh_key`, and the controls are
hidden when it is false. A button that is guaranteed to fail is worse than no
button: it teaches the user that the tool is unreliable, when in fact it is
correctly configured for a deployment that did not opt into unattended scanning.

### Two functions that disagreed about the same host

`inferPlatform` existed in `App.tsx` and in `DiscoveryView.tsx`. Reading them
side by side:

- DiscoveryView treated port 445 as a Windows signal. Samba is ubiquitous on
  Linux file servers, so every one of them was classified Windows.
- App.tsx did not consider 445 at all, and let an open port 22 force `linux`
  *regardless of an explicit Windows banner* -- so a Windows Server running
  OpenSSH was classified Linux and offered apt commands.

The same host, from the same discovery data, got one answer from the Discovery
tab's Scan button and the opposite answer from typing its IP into the scan form.
Neither copy was right, and the disagreement had been invisible because nobody
had read them together.

The merged version puts the precedence in writing: an explicit banner beats a
port number, because a banner is a claim about what is running while a port is an
inference from it. When both families are named, Windows wins -- misclassifying a
Linux host costs one failed SSH attempt, while misclassifying a Windows host
means confidently handing someone `sudo apt`.

### Empty states that blamed the wrong control

`No machines match ""` was rendered whenever the *platform* filter was what
excluded the rows, because the message assumed the search box was responsible and
interpolated an empty query. The drill-down said "No CVEs match the selected
severity" when the search box or the patch filter had done it.

Both sent the user to adjust a control that was not the problem. Empty states now
enumerate the filters actually in effect and offer to clear them, which took less
code than the guessing did.

### The dialog nobody could leave

The CVE modal had `role="dialog"` and `aria-modal="true"` on the **backdrop** --
the element whose entire job is to be clicked to dismiss. There was no Escape
handler, no focus trap, no initial focus, no accessible name, and no focus
restoration on close. A keyboard user who opened it could Tab straight out into
the page behind it and had no way to close it.

Nearby, the fleet view's five metric cards were plain `<div>`s with `onClick`.
Not styled as buttons with a missing handler -- genuinely unreachable, with no
`role`, no `tabIndex`, and no key handling. The drill-down's equivalent cards had
`role="button"` and `tabIndex={0}` and handled `Enter` only, which is the tell of
a11y added from a checklist rather than from trying it: whoever added the role
never pressed Space.

Both now go through `src/lib/a11y.ts`, which is four lines of shared props and
removes the possibility of getting it partly right in one place and differently
partly right in another.

---

## Chapter 6 — The container that couldn't find its migration config and the badge that broke the form grid (v0.4.1)

### What happened

Immediately following the 0.4.0 release, two issues were surfaced when running the
application inside a fresh Docker container:

1. **HTTP 500 "Internal Server Error" on initial API requests**:
   The application started and passed its basic health check, but any API endpoint
   querying the database failed with a 500 error. The container logs revealed:
   ```text
   FileNotFoundError: /app/alembic.ini doesn't exist
   ```
   During the first database session request, `upgrade_to_head` invoked Alembic to
   ensure the schema was at `head`. Alembic's `env.py` executed:
   ```python
   if config.config_file_name is not None:
       fileConfig(config.config_file_name)
   ```
   Because `Dockerfile` copied `pyproject.toml`, `README.md`, and `app/`, but had
   omitted `alembic.ini`, Alembic was passed a configuration path that did not exist on
   the container filesystem, turning a clean startup into an immediate crash.

2. **Form field vertical misalignment in the UI**:
   The platform auto-detection badge (`⚡ Auto-detected: Linux (SSH)`) had been placed
   directly inside a flex row with the `PLATFORM` label:
   ```tsx
   <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
     <label htmlFor="scan-platform">Platform</label>
     {autoDetected && <span>⚡ Auto-detected...</span>}
   </div>
   ```
   On responsive screen widths, this caused the label header to wrap into two lines,
   doubling its height. Because `.scan-form-grid` is an auto-fit CSS grid, the Platform
   dropdown was pushed down by ~20px relative to Hostname, Username, Authentication,
   and Password.

### Why it happened and what we learned

1. **Multi-stage Docker builds must mirror runtime file expectations**:
   Adding Alembic migrations in 0.4.0 created a runtime dependency on `alembic.ini`
   (or on code that gracefully functions without one). When tests run locally in a
   virtualenv at the repository root, `backend/alembic.ini` is always present on disk.
   In the container, only explicitly copied files exist.
   
   The fix was two-fold: copy `backend/alembic.ini` into `/app` in `Dockerfile`, and
   add defensive `Path.is_file()` guards in both `migrations/env.py` and
   `migrations_runtime.py` so programmatic invocations never crash if an ini file is
   omitted.

2. **Form field labels must maintain predictable heights across grid columns**:
   CSS grid columns in a single row do not automatically align their child `<input>`
   elements if their `<label>` elements have different heights. Placing dynamic status
   pills or extra text inside label headers disrupts vertical rhythm. Moving dynamic
   indicators below the form control (as helper text or hints) and setting
   `align-items: start` on the grid ensures all inputs in the top row line up
   pixel-perfect across the entire viewport.

---

## Chapter 7 — Taming information density with top-level workspaces and operator triage cards (v0.4.2)

### What happened

As CveDeck grew from a simple single-target scan form into a multi-phase fleet
vulnerability management and network discovery platform, the primary dashboard view
began accumulating information density:

1. **Visual Overcrowding**: The manual scan form, authentication mode switcher, live
   connection test results, bulk re-scan controls, fleet KPI cards, and machine
   inventory table were all stacked on a single long scrollable page. For operators
   monitoring hundreds of servers, the scan form was unnecessary clutter; for operators
   performing one-off scans, the large fleet table below was visual noise.
2. **Cognitive Fatigue in Triaging**: An operator opening the fleet list wanted immediate
   answers to high-stakes operational questions: *Which servers have Critical P0
   exploits? Which hosts have pending kernel updates? Which hosts haven't been scanned
   in a week?* Answering these required mentally scanning columns, toggling dropdowns,
   or typing complex query filters.

### Why it happened and how we structured it

1. **Separation of Operational Workspaces**:
   We split the top-level application shell (`App.tsx`) into three distinct, dedicated
   workspaces:
   - **`📊 Fleet Overview`**: An uncluttered operational dashboard for monitoring
     inventory, reviewing security posture, and initiating bulk fleet actions.
   - **`🚀 New Scan`**: A dedicated scanning workspace for entering hostnames, selecting
     authentication modes (password, SSH private key, server keyring), and running
     pre-flight connection tests.
   - **`🔍 Network Discovery`**: The zero-touch CIDR sweep and fleet enrollment interface.

2. **Quick Action Triage Cards**:
   Instead of forcing operators to filter manually, we introduced high-contrast,
   keyboard-accessible Quick Triage Cards directly above the fleet table:
   - 🚨 **Critical P0 Hosts**: Filters machines with CVSS 9.0–10.0 vulnerabilities.
   - ⚠️ **High Risk Hosts**: Filters machines with High severity findings.
   - ⏳ **Stale Scans**: Flags infrastructure where `lastScannedAt` is older than 7 days.
   - 🆕 **Enrolled Hosts**: Highlights newly discovered machines in `NEVER_SCANNED` status.
   
   Each card integrates with `toggleButtonProps` from `src/lib/a11y.ts`, responding to both
   Enter and Space keys and toggling back to "all" on second click.

3. **Sub-Tabbed Machine Drill-Down**:
   The machine detail drill-down view was similarly structured into 4 focused sub-tabs:
   `🛡️ Vulnerability Findings` (with 1-click modal inspector), `📋 Overview & Fix Plan`
   (with deduplicated bulk fix script generation), `🌳 Package Blast Radius` (with
   reverse-dependency impact scoring), and `📝 Remediation & Audit` (for compliance
   tracking).

### Closing thought

Across seven chapters the evolution of CveDeck has moved from raw protocol collection
to rigorous spec enforcement, containerized resilience, and finally to human-centered
information architecture. Beautiful software is not just software that looks sleek; it is
software where the right action is obvious, the critical signal is impossible to miss, and
the distance between finding a vulnerability and remediating it is reduced to a single click.

---

## Chapter 8 — Four hundred findings and no way to choose (v0.5.0)

### What happened

Nothing broke. This chapter is about a shortcoming no test could fail on, because
the code was doing exactly what it had been designed to do.

A scan of a modest fleet produced several hundred findings. They were accurate,
correctly deduplicated, correctly attributed to packages, and correctly ranked by
CVSS. And they were unusable. Sorting by CVSS puts a hundred 9.8s at the top of
the list, and a hundred items at the top of a list is the same as no list at all.

The missing question was not *how bad is this?* CVSS answers that. It was **is
anyone actually doing it?** — and nothing in the system had ever asked.

### The two feeds, and why they are not OSV

Two public datasets answer it. CISA's **Known Exploited Vulnerabilities**
catalogue lists CVEs with confirmed, observed exploitation in the wild, each with
a federal remediation deadline. FIRST's **EPSS** assigns every published CVE a
modelled probability of exploitation in the next 30 days.

The instinct was to add them the way OSV was added: a client, a protocol, a call
in the matcher. That would have been wrong, and the reason is worth recording.

OSV answers a question about *a package at a version*, which is specific to the
host being scanned and can only be asked during a scan. KEV and EPSS answer
questions about *a CVE* — nothing to do with any particular host — and both are
published once a day as a single complete file. KEV is one JSON document of
around 1,700 entries. EPSS is a gzipped CSV of roughly 367,000 rows.

Querying those per finding would mean thousands of HTTP requests for data that
one daily download already contains in full. So they became the first locally
cached datasets in the system: `kev_entries`, `epss_scores`, and `feed_refreshes`
to record when each last succeeded. Enrichment runs against the local cache,
adding no network dependency to a scan at all.

That also settled where enrichment goes. `Matcher.match` is pure and heavily
property-tested, and enrichment needs only a CVE id — so it runs *after* matching,
as a separate pass, and the matcher was not touched.

### The bug we did not write

The whole feature turns on a distinction that is very easy to lose:

```python
kev_listed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
```

Nullable, not `default=False`.

`False` means *we checked CISA's catalogue and this CVE is not in it*. `NULL`
means *we never checked*. A boolean column with a default would have collapsed
them, and that collapse produces a dashboard reporting **"0 actively exploited"
across an entire fleet, on the authority of a catalogue that was never
downloaded.**

That is Chapter 1 again in a new costume. There, a `NameError` laundered into
`DATA_SOURCE_UNAVAILABLE` produced a zero-finding scan behind a green success
badge. Here, a missing feed laundered into `False` would produce a zero-exploited
fleet behind the same reassuring silence. Both are the same failure: **the tool
asserting a security conclusion it has no evidence for, in the direction that
stops someone looking further.**

So the three-valued distinction is enforced at every layer, and each layer is
separately tested — nullable columns, a `FindingEnricher` that writes `False` only
when a feed is genuinely usable, `bool | None` in the API schema, `?? null` rather
than `?? false` in the client mapper, and `=== true` rather than a truthiness
check in `isKnownExploited`. The findings table renders three visually distinct
states, and a test asserts they *are* three and not two.

Two supporting rules fell out of the same reasoning. A failed refresh leaves the
previous cache in place, because yesterday's answer beats no answer. And an empty
catalogue arriving with HTTP 200 is treated as a **failure** rather than written —
a feed that changed shape upstream must not be permitted to erase every
exploitation flag in the fleet.

### What Hypothesis found

A property test asserted that with a usable cache, `kev_listed` is never `NULL`.
Hypothesis immediately produced the empty catalogue: zero records, status `OK`,
enrichment returning `NULL` for everything.

The interesting part was deciding who was wrong. The code was right — a
zero-record cache genuinely tells you nothing, and `FeedRefreshService` refuses to
write one anyway, so the state is unreachable in production. The *property* was
wrong: it asserted something about a cache that cannot exist. It was narrowed to
non-empty catalogues, and the empty case pinned separately as deliberate
defensive behaviour. Loosening the assertion to make it pass would have discarded
the very guarantee the test existed to hold.

### The stub that had been there since v0.1.0

`NvdClient` had existed as a bare `Protocol` since the first release, with
`wiring.py` passing `nvd=None` and every scan producing package-level findings
only. It was finally implemented — and deliberately shipped **off**.

NVD permits five requests per rolling thirty seconds without an API key. More
importantly, it answers a much looser question than OSV: "which CVEs mention this
product", against a corpus never designed for inventory matching. So the client
queries by CPE product *and version*, never free text, and caps results at 250
sorted by descending CVSS — an OS-level query can legitimately match thousands of
CVEs spanning a decade, and dumping those onto a host would bury the
package-level findings that are actually actionable.

Because it ships off, `MachineScan.sources_ok` had to keep distinguishing *not
configured* from *unreachable*. A deployment that never opted in must not have
every scan branded partial — that teaches operators to ignore the warning, which
destroys the signal for the deployments that need it.

### Two things that only break on a real fleet

Both passed every test before being caught.

The migration was chained onto `630af2701d55` because the date-prefixed filenames
made it look like the head. It was not; `e451e20b58e2` was. The result was two
Alembic heads — invisible on a fresh database, fatal on a real upgrade. CI now
checks that `alembic heads` returns exactly one.

And the enrichment lookup bound every CVE id into a single `IN` clause. Fine for a
fixture of five findings; `OperationalError` on the first genuine fleet, since
SQLite caps bound parameters at 999. Chunked at 500, with a test at 1,500
findings — because the failure mode is precisely the one a small test cannot reach.

### Closing thought

The measure of this release is not that it added two data sources. It is that a
CVSS 6.5 being exploited today now outranks a CVSS 9.8 nobody has touched, and
that when the tool does not know, it says so.

Every chapter here has circled the same idea from a different angle: a scanner's
worst outcome is not a crash but a confident wrong answer, because a crash sends
someone looking and a clean report sends them away. Chapter 1 was a defect
disguised as an outage. Chapter 2 was a partial scan indistinguishable from a
clean one. This one was a missing feed that would have read as an all-clear.

The code preventing each is small. Recognising which silence is dangerous is the
actual work.

---

## Chapter 9 — Reading the code was not enough (v0.5.1)

### What happened

Chapter 8 added exploitation intelligence and a ranking that put a CVSS 6.5
being exploited above a CVSS 9.8 nobody had touched. The dashboard was then
reviewed the way software usually is: by reading it.

That review found the drill-down was 1,761 lines and that navigation lived in
`useState`. Both true, both worth fixing, neither the actual problem.

The actual problem appeared the moment the app was run against a seeded
twelve-host fleet and screenshotted.

### Ten cards, two units, no label

The fleet summary was two rows of five cards. Row one counted **hosts** — "9
Critical P0 Hosts". Row two counted **findings** — "25 Critical". Same size,
same weight, stacked directly on top of each other, and nothing anywhere said
the units differed.

The exploitation card was worse: a host count with a finding-count sublabel. In
the seed data both happened to be 3, so it read as consistent by luck.

This is invisible in source. Each card is a correct component rendering a
correct number. The defect only exists in the relationship between two of them,
which is to say it only exists on screen.

Four cards now, all counting hosts, each stating its unit — "3 hosts ·
25 findings". Findings totals moved to a strip that deliberately does not look
like a card. Three weak cards — stale, never-scanned, failed — became one
"Needs attention", because separately they were separately ignorable, and
together they answer a question worth asking daily: *whose data can I not trust
right now?*

### The signal we had just built was not on the table

The second screenshot finding was blunter. The fleet table had CRITICAL, HIGH,
MEDIUM and LOW columns and no exploitation column. The three actively exploited
hosts were visually identical to the nine that were not.

Worse, the table sorted alphabetically, so `web-01` — actively exploited — sat
eleventh of twelve. An entire release had gone into establishing that
exploitation outranks severity, and the fleet list still ordered hosts by name.

Both fixed: an Exploited column carrying the same three states as everywhere
else, and a default sort of KEV, then critical, then high.

The lesson is not "add a column". It is that shipping a signal into the data
model is not the same as shipping it to the user, and only one of those is
visible from the source.

### The screen that could not be photographed

Screenshotting the drill-down turned out to be impossible. Every screen in the
dashboard lived at `/`. There was no URL for a host.

That is a mildly annoying limitation when described in a planning document. It
is a different thing entirely when it stops you looking at your own product.

Hash routing, not the History API — and the reason is the deployment, not
taste. The dashboard is served by FastAPI's `StaticFiles` mount and typically
sits behind whatever reverse proxy the operator already runs. `/machines/web-01`
would 404 on refresh unless every one of those deployments grows an SPA
fallback: a support burden paid by users, to buy a prettier URL. A fragment
never reaches the server.

Writing the tests found two bugs before the code shipped, both of which would
have been someone else's confusing afternoon:

`decodeURIComponent` throws on a malformed escape. A shared link is precisely
the thing that arrives truncated by a chat client, so the first hand-mangled URL
would have taken down the whole app rather than landing on the fleet list.

And the first implementation assigned `location.hash` and let the `hashchange`
listener update React state. That fires asynchronously in a browser and never in
jsdom — so the UI would have lagged a frame behind every click in production
while appearing completely broken under test. State is set at the call site now;
the listener handles only navigation that starts outside the hook.

### Light mode was already broken, quietly

Adding a theme toggle should have been small. The CSS was dark-on-`:root` with a
`prefers-color-scheme: light` override, so light mode looked implemented.

It was not. Toasts, partial-scan badges, stale timestamps and empty states were
light-first hardcoded colours, patched back to dark by stray
`prefers-color-scheme: dark` blocks further down the file — leftovers from when
the project was light-first and never tokenised during the switch.

**No `data-theme` attribute can override a media query.** A toggle built on top
of that would have half-worked: most of the page would flip and a scatter of
components would stay dark, looking for all the world like a CSS bug in the new
code rather than a five-release-old inconsistency.

Tokenising those (`--warn-bg`, `--surface-muted`) and deleting the stray blocks
was the actual work; the toggle was the easy part.

It cycles system → light → dark → system rather than toggling a boolean.
"Follow the OS" is a real choice, and a two-state toggle pins the theme on first
click and makes it unreachable forever.

### The duplicate nobody could see

Splitting the drill-down surfaced `severityLabel` and `remediationStatusLabel`
defined both in `lib/labels.ts` and privately in the view. The two
`remediationStatusLabel` implementations **disagreed** — one rendered "In
progress", the other "In Progress".

No user had ever seen the difference, because nothing imported the shared one.
It was dead code. Which is exactly what made it dangerous: a second
implementation is not redundancy, it is a trap set for whoever eventually
imports the wrong one and changes the UI without touching the UI.

Consolidated on the version that actually ships, so no visible text moved.

### The same mistake, one screen over

Fixing the fleet page made the drill-down reachable by URL, which meant it could
be screenshotted, which meant it could be looked at. It had the identical
problem.

Five KPI cards and a full-width progress card, about 250px before the tabs --
and the cards duplicated the tabs directly beneath them. `All Findings (6)`
appeared twice on the same screen, in two different styles, six pixels apart.

Worse: the host page said nothing about exploitation at all. The fleet page had
just been taught to lead with "3 actively exploited"; click into one of those
three and the signal vanished. The same release that put exploitation first on
one screen had left the screen you land on next silent about it.

It is the same lesson arriving twice in one afternoon, which is roughly how
often it needs to arrive before it sticks: the summary at the top of a screen is
not decoration, and nobody reviews it by reading its source.

### The flaky test

Adding around fifty tests made an unrelated one start failing intermittently --
`ScanFormView`, untouched by any of this work.

The cause was mundane. Vitest defaults to a five-second timeout, `userEvent`
simulates real typing with a delay per keystroke, and those form tests genuinely
take one to two seconds each. Twenty-one test files running in parallel on a
loaded machine tipped the slowest of them over.

Worth recording not for the fix -- raise the timeout -- but for the temptation.
The failure did not reproduce in isolation, and the third full run passed. Every
signal available said "just re-run it". A flaky test is worse than a failing one
precisely because it trains that response, and the next flake will be the real
bug that everyone re-runs past.

### Closing thought

Every earlier chapter here is about a silence: a defect reported as an outage, a
partial scan reported as clean, a missing feed that would have read as an
all-clear. This one is about a different kind — a signal that was collected,
stored, ranked, tested, and then not put on the screen where the decision gets
made.

The tests passed the whole time. They were testing the right things. They simply
cannot see two cards sitting next to each other measuring different quantities,
because that is not a property of either card.

Some defects are only visible from the outside. It is worth occasionally being
outside.

---

## Chapter 10 — The palette was never really ours (v0.5.2)

### What happened

The dashboard looked like every other AI-generated dashboard. That was not a
vague impression, and checking it took one minute:

| Token | Value | What it actually is |
| :--- | :--- | :--- |
| `--accent` | `#3b82f6` | Tailwind `blue-500`, unmodified |
| `--critical` | `#f43f5e` | Tailwind `rose-500`, unmodified |
| `--text-muted` | `#94a3b8` | Tailwind `slate-400`, unmodified |
| body font | Inter | The most common typeface in generated UI |
| mono font | JetBrains Mono | Its usual partner |

Every single token was Tailwind's stock palette. Nothing had ever been chosen.

The instructive part is why: a model reaches for `slate-900` and `indigo-600`
because those exact strings appear in a million tutorials. The defaults are not
a style, they are the absence of a decision — and absence of a decision is
itself legible on screen.

### Three directions, and a first attempt that proved nothing

Three directions were mocked as static pages. All three are kept in
[design/](design/), along with the reasoning that chose between them. The first pass was worthless: one
shared template with three colour palettes swapped in. They rendered as three
tints of the same dashboard, which is a fair comparison of palettes and no
comparison at all of *directions*.

The second pass gave each its own structural signature — a gutter lamp, cards
dissolved into ruled rows, hostnames as stamped asset tags — and the difference
became obvious immediately. A direction that lives entirely in its colour values
is a skin, not a direction.

### The comparison that decided itself

Each mockup rendered the findings table twice: severity as four distinct hues,
and severity as a single amber ramp with red reserved for exploitation.

The argument had been theoretical. The screenshot was not. With four hues, nine
red Critical counts and three red exploitation marks compete on the same screen
and the eye resolves neither — the actively exploited hosts are simply lost. With
the ramp they are unmissable.

Two releases had gone into establishing that exploitation outranks severity. The
palette had been quietly arguing the opposite the whole time, and no amount of
reasoning about it would have been as convincing as putting the two side by side.

### What the repaint uncovered

Swapping the tokens changed less than expected, which was the interesting part.
The nav tabs stayed indigo. The Scan buttons stayed indigo. Hostnames refused to
become tags.

Three separate causes, none of them cosmetic:

**`var(--primary)` was referenced nine times and defined nowhere.** Every
"active" state had been falling back to transparent since it was written. The
indigo appearance came from a hardcoded `box-shadow`, not a fill — the feature
had never worked, and nobody noticed because the wrong thing still looked
deliberate.

**138 hardcoded colour literals**, 102 in the stylesheet and 36 in JSX `style`
props, all Tailwind values. A colour written into a rule cannot be reached by
the token layer, and therefore cannot be reached by the theme toggle. Chapter 9
fixed a handful of these and treated it as a contained bug; it was the visible
corner of something four times larger.

**Duplicate rules where the later definition silently won** — two
`.hostname-link` blocks, two `.workspace-tab-btn` blocks. Nothing errors. The
loser simply never applies, and reading either one in isolation tells you the
wrong thing about what renders.

### The measurement that was lying

An earlier claim in this work — that mobile was badly broken with horizontal
overflow — turned out to be an artifact of the tool. Windows headless Chrome
enforces a minimum window width, so `--window-size=390` renders the page at
roughly 600px and crops the image to 390. That looks *exactly* like overflow.

Rendering the same page inside a 390px iframe, which gets a genuine layout
viewport, showed no overflow at all. The real mobile problems were different and
milder: wasted vertical space, cramped cards, a table that needs a lot of
scrolling to reach.

The correction matters more than the finding. A confident wrong measurement had
already been written into a plan and would have justified a chunk of work aimed
at a problem that did not exist. Screenshots feel like evidence in a way that
invites less scrutiny than a number does.

### Closing thought

Nine chapters here are about the product being honest with its users. This one is
about the codebase being honest with itself.

An undefined token that falls back silently, a colour literal that no theme can
reach, a duplicate rule where the loser never runs — none of these fail. They all
render *something*, and something plausible is the hardest defect to see. The
palette had been a default rather than a decision for five releases, and the
thing that finally exposed it was not new code but attempting to change it and
finding out how much did not move.

---

## Chapter 11 — Publishing is a feature, and it had bugs (v0.6.0)

### What happened

The project had been developed for five releases in a folder named after a
working title, in a repository that had never had a remote. Making it public
looked like an errand: point the tree at GitHub and push. It was not an errand.
Three separate things were wrong, and each was invisible in a different way.

### The history was the leak, not the tree

The first instinct was to preserve the eighty-six commits and publish them. A
sweep for the working title across the tracked files came back clean, which felt
like confirmation.

It was the wrong place to look. The name survived in *history* — in a commit
message, and in a changelog entry that had since been rewritten — and one of
those entries carried an absolute filesystem path from the development machine.
Restarting the history is what removed them. The plan up to that point had
included taking a bundle of the old commits "for provenance", which would have
been the single artifact carrying forward precisely what the reset was for.

The reset is recorded rather than hidden, in `CHANGELOG.md` and here. What
actually preserves continuity is not the commit graph: it is the specification,
this document, and a changelog that reaches back to 0.1.0. Those travelled
intact.

### Two hundred and forty citations, covering half the spec

The source cites the specification heavily — `Req X.Y` in a docstring, next to
the behaviour that requirement asks for. That density is the most visible
evidence that the spec is real and maintained, and `AGENTS.md` §0 tells
contributors to keep the two in step.

Counting them properly showed that all of them pointed at Requirements 1 to 7.
The eight requirements added after the original task plan was completed —
network discovery, SSH key authentication, trustworthy reporting, host runtime
context, fleet-scale operation, remediation guidance, demonstration mode — had
no citations anywhere in the code. The demo-mode module, the newest thing in the
repository, referenced the spec not at all.

That is worse than having no citations at all, and the reason is worth keeping:
the seven covered requirements make the convention look complete. A reader who
spot-checks two references, finds both resolve, and concludes the codebase is
traceable has been misled by a sample. Only counting reveals it, and nobody
counts.

Both directions are now checked mechanically — every reference resolves, and
every criterion is cited — because the first direction had been true all along
and the second had been false for eight requirements without anyone noticing.

### The measurement kept being wrong

Three times in this work a confident number turned out to be false, and each was
found only by re-deriving it rather than re-reading it.

The renumbering of the spec was priced at "240 citations across 36 files" and
declined as too invasive on that basis. Measured, it touched one file: nothing
outside the spec referenced the requirements being renumbered. The estimate was
off by a factor of thirty-six and had already changed a decision.

The "240 citations" figure itself was an undercount. Citations are written in
groups — `(Req 4.1, 4.3, 5.1)` — and a scan requiring a `Req` prefix per pair
reads that as one reference instead of three. The real number is nearly double,
and the wrong one had been sitting in the README.

Then the renumbering broke a cross-reference. One requirement described itself
as extending "Req 12", correct when the requirement it meant was numbered 12 and
wrong the moment it became 10. The check written to catch exactly that class of
breakage looked for `Req N.M` and for the word "Requirement", and a bare
`Req N` matched neither.

Chapter 10 already recorded a confident wrong measurement — a mobile overflow
bug that was an artifact of the screenshot tool. The pattern is consistent
enough to be worth naming: a number in a document is not evidence, it is a claim
with an expiry date. The documents no longer state these counts at all. They
point at the script that computes them.

### The guard found a real leak before the first commit

The remaining worry was the ordinary one: that something from a development
machine would reach a public repository by accident. The instinct was to solve
it with a second local folder that the public repository would be copied from —
an airlock made of directories.

That was the wrong shape, for a reason this chapter is otherwise full of:
copying between two trees is what had gone wrong at every previous step, and it
buys no guarantee that `git push` does not already provide. What it was
*actually* reaching for was a mechanical check before anything left, and the
repository had none.

So the airlock became hooks: a commit-time check for credential-shaped files,
private key blocks and provider tokens, and a push-time check that repeats it
over everything a push would publish — the diff as well as the final tree,
because history is published too.

It refused the very first run. A real host address from the development
network was sitting in an enrollment fixture in the discovery tests, and in the
scan form's hostname placeholder, where it had shipped in the dashboard UI for
several releases. `AGENTS.md` §6 forbids exactly that, in exactly those words,
"including in test fixtures" — the sentence had been in the contributor guide
the whole time.

The pre-publication reviews that missed it were not careless. They grepped for
the markers that felt like leaks: a username, an old project name, absolute
paths. An address in a test fixture is indistinguishable from a placeholder,
which is the whole problem. Every address in the repository is now loopback, an
RFC 1918 example, or an RFC 5737 documentation address, and that is stated as a
property in the methodology document rather than left as a habit.

### The last question before pushing

The repository was one command from public. The final review asked something
narrow: should the README call Windows support "coming soon", given that nothing
explained how to prepare a Windows host?

Answering it properly meant asking what a Windows scan actually matched against.
The collector gathered installed programs from the registry and labelled them
with the ecosystem `Windows`. The OSV client queried them under that name. OSV
has no such ecosystem, and says so: HTTP 400, `invalid ecosystem`. OS-level
Windows exposure lives in cumulative KB updates, which nothing mapped, and NVD
was off by default. So a Windows scan could not find anything.

That would have been a wording problem, except for what the client did with the
400. It caught it — along with every other failure, per query — and returned no
advisories. The matcher treats a source as unavailable only when the client
raises. The client never raised. So the scan finished, complete, with zero
findings, and was not marked partial.

The same code path meant that **an OSV outage made any Linux host look clean
too.** Pointing the real client at an unreachable address reproduced it in a
few lines: `osv_status=OK`, no findings. This is Chapter 1's bug — the scan that
always found nothing — back again, and this time in the component the whole
trust story rests on, in the release that was about to be published.

The test suite had a test for exactly this. It passed. It drove the matcher with
a fake client that raised `ConnectError`, and asserted the scan was marked
unavailable, which it was. The test was correct about the matcher and silent
about the client, and the client was the thing that was broken. A seam tested in
isolation is a claim about one side of it.

The fix was small: raise when any query goes unanswered, and never cache a
failure as a clean result. The tests that matter now drive the real client
through a mocked transport, and before being trusted they were run against the
old client and seen to fail. Windows scans are refused outright, with the
reason, until something can match what they collect; the README stopped
describing Windows as scannable, and the demo stopped showing a Windows host
with findings nobody could have produced.

None of this was found by looking for bugs. It was found by taking a small
documentation question seriously enough to follow it into the code.

### Closing thought

Every chapter here is about a system that reported something plausible instead
of something true: a scan that found nothing and called it clean, a fix command
for the wrong package manager, a palette that argued against its own
prioritisation, a token that fell back to transparent.

This chapter is the same failure applied to the repository itself. A clean
`grep` for the wrong string, a citation convention that covered half of what it
appeared to, a count nobody recomputed, an address that looked like a
placeholder — and, at the last moment, a green test standing guard over a seam
the real code never crossed. None of them failed loudly. They all produced a plausible answer,
and plausible is the hardest defect to see — which is the sentence Chapter 10
ended on, arrived at again from a completely different direction.

The response is the one the project has settled on everywhere else: where a
property matters, make it checkable, and then check it. `pytest` for behaviour,
the property tests for the invariants, `check_spec_citations.py` for the spec,
and the hooks for everything that must never leave. Asking people to remember
produces documentation of an intention. A check produces a property.
