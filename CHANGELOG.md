# Changelog

All notable changes to the **CveDeck** project are documented here.

---

## [Unreleased]

### Fixed

- **The interface-structure diagram in the methodology document did not render
  on GitHub.** Its arrows pointed at `Drill-Down Workspace`, a subgraph title
  containing spaces rather than a node mermaid can link to, so GitHub showed a
  parse error in its place. The subgraphs now have IDs. All five diagrams in the
  document were checked with mermaid's own parser, which reproduced GitHub's
  exact error before the fix and accepts every diagram after it.

---

## [0.6.0] - 2026-09-13

The first public release. Launch preparation: the design system finished and
enforced, an icon set, a demo mode, and the repository readied for publication.

### Added

- **Publication guards (`.githooks/`).** A `pre-commit` hook that refuses to
  stage a credential-shaped file — `.env`, a database, a key or certificate, a
  private key block, a provider token — and a `pre-push` hook that repeats the
  check over everything a push would publish. It scans the diff as well as the
  final tree, because history is published too and a secret introduced in one
  commit and removed in the next still leaks.

  The push hook is aware of where it is pushing. A private work-in-progress
  remote gets the content checks alone and completes in about a second; the
  public remote additionally gets branch policy (`main` and `v*` tags only), a
  refusal of any non-fast-forward, an author-email check, version-string
  agreement, the spec-citation invariant and both test suites. That split is
  deliberate: work in progress legitimately has failing tests, and a guard that
  refuses to back it up is a guard that gets switched off. The public remote is
  matched on its URL rather than its name, so renaming a remote cannot route
  around it.

  Enable per clone with `git config core.hooksPath .githooks` — the setting is
  local, so a fresh clone has the hooks off. `CVEDECK_SKIP_TESTS=1` skips only
  the suites while keeping every content and policy check, which is a better
  escape hatch than `--no-verify`.

  This makes the rule in `AGENTS.md` §6 enforced rather than requested. It found
  a real violation on its first run, before the repository had a single commit —
  see **Fixed** below.

  Both hooks also refuse any file that is tracked while an ignore rule says it
  should not be — which only happens through `git add -f`, the one move that
  defeats an ignore rule. The check covers `.gitignore`, `.git/info/exclude` and
  the global excludes file together, so local working files stay local without
  the tracked hook having to name any of them.

  A checkout can declare a role in its own local git config, which is never
  pushed: `cvedeck.role staging` makes the push hook refuse the public
  repository outright, and `cvedeck.role public` makes the commit hook refuse
  anything not produced by a sync. A clone with no role set — any
  contributor's — behaves normally. This supports keeping a private working
  history separate from the published one, with the published folder written
  only by snapshots.

- **`scripts/check_spec_citations.py`.** Verifies the specification invariant in
  both directions: every `Req X.Y` and `Property N` reference resolves, and no
  acceptance criterion is left uncited. Two parsing details matter and were both
  wrong in earlier ad-hoc attempts — citations are written in groups, so
  `(Req 4.1, 4.3, 5.1)` is three references and not one, and a bare `Req N`
  with no sub-number is a reference too. Run by the pre-push hook.

- **`scripts/Verify-Release.ps1`.** The pre-release sequence in one command:
  version agreement, spec citations, both suites, one Alembic head, the
  production build, `npm audit`, then a container build and a demo-mode probe.
  The container check is the one that is both most important and easiest to
  skip — it is the only thing that exercises the built dashboard as a user
  receives it, served as static assets by the backend rather than by the Vite
  dev server.

- **Demo mode (`CVEDECK_DEMO_MODE`).** Seeds a fictional twelve-host fleet into
  an empty database — 144 findings across eleven Linux hosts, plus a Windows
  host enrolled but never scanned — and
  **refuses every route that reaches the network**: `POST /api/scans`,
  `POST /api/discovery/sweep`, and `POST /api/scans/test-connection` all return
  403.

  The refusal is the point. Those routes take a hostname or a CIDR plus
  credentials and connect to them, so a public instance with them enabled is an
  SSH/WinRM client and port scanner any visitor can aim at any address, with the
  traffic originating from the host rather than the visitor. The guard is a
  route-level dependency rather than a check in the handler body, because
  FastAPI resolves a handler's parameter dependencies first: as a body check,
  the `ScannerEngine` was constructed before the guard ran and its own failure
  surfaced instead of the 403.

  The seeded fleet deliberately carries the states worth seeing rather than a
  tidy list of healthy hosts: a host that has never been scanned, one whose
  credentials failed, one unreachable, one scanned while an advisory source was
  down, one last scanned a month ago, findings CISA lists as exploited, and
  findings whose exploitation status was never checked. `kev_listed` holds all
  three of its states, and the tests assert that it keeps them.

  Seeding is guarded on an empty fleet, so restarting a demo container does not
  duplicate it and enabling the flag against a database holding real results is
  a no-op. Reported at `GET /api/health` as `capabilities.demo_mode`.

- **An icon set (`components/Icon.tsx`).** 37 Lucide stroke icons plus the Linux
  and Windows marks, inlined as SVG. No icon dependency and nothing fetched at
  runtime — the same reasoning that vendored the fonts: this is a scanner run on
  isolated networks, where a CDN request never resolves, and a dashboard load
  should not report the host's IP to a third party. Icons are sized in `em` and
  coloured with `currentColor`, so they scale with their type and theme for
  free.

- **Loading skeletons (`components/Skeleton.tsx`).** The fleet list had no
  loading affordance: the first fetch rendered an empty table, which on a cold
  container is indistinguishable from "you have no machines" and from "the
  backend is down". Both empty states are now gated on the loading flag —
  gating only the first moved the problem rather than fixing it, since the
  filter branch then claimed no machines matched filters the user had not set.

- **A favicon and page metadata.** The repository previously contained no images
  at all. The mark is a stamped asset tag, drawn from the "rack and label"
  language, with `color-scheme` and `theme-color` set so the browser paints the
  right ground before the stylesheet lands.

- **A source link in the dashboard header.** CveDeck is served over a network
  under the AGPL, whose section 13 exists so people using software over a
  network can still reach its source. Offering the link in the interface is the
  straightforward way to honour that.

- **`frontend/src/fonts/OFL.txt`.** Four `.woff2` files ship with the
  application; OFL clause 2 requires the licence to accompany them.

- **Repository furniture for publication:** Dependabot configuration (pip, npm,
  GitHub Actions, Docker), issue templates with a `config.yml` routing security
  reports to private advisories rather than public issues, a pull-request
  template, and an advisory `pip-audit` / `npm audit` CI job. The audit job is
  deliberately non-blocking: an advisory can land against a transitive
  dependency at any hour, and a red X on unrelated pull requests trains people
  to ignore red Xs.

### Changed

- **The default host port is 3325, not 8080.** 8080 is the most contested port
  in a self-hosted stack — qBittorrent, Jenkins, UniFi, Traefik, Guacamole and a
  long tail of others default to it — so the documented `docker run` and compose
  setup would collide on exactly the kind of host CveDeck is meant for. 3325
  ("DECK" on a phone keypad) is unassigned in the IANA registry, used by no common
  self-hosted or security tool, and far below every OS's ephemeral port range.
  Only the host-side default changes: the container still listens on 8000, so a
  deployment that maps its own port is unaffected, and `PORT` in `.env` still
  overrides it.

- **Windows scans are refused, and the product no longer claims to scan
  Windows.** `POST /api/scans` returns 422 for any batch containing a Windows
  target, with the reason. WinRM collection exists, but nothing can match what it
  collects: OSV has no Windows ecosystem — it rejects the query with HTTP 400 —
  OS-level Windows exposure lives in cumulative KB updates that nothing here maps
  yet, and NVD is off by default. A Windows scan therefore finished with zero
  findings, which is exactly what a clean host looks like. Refusing is the only
  honest answer until matching exists (new **Requirement 10.8**; Requirement 1.2
  is marked deferred rather than removed).

  A mixed batch is refused whole rather than having its Windows targets dropped,
  since dropping them would report the batch as done when part of it was never
  attempted. The dashboard stops offering what the API refuses: the scan form
  labels Windows *not yet supported* and explains why when auto-detection lands
  on it, per-host quick scans are disabled for Windows hosts in the fleet and
  discovery views, and fleet re-scans leave Windows hosts out and say how many.
  Windows hosts can still be discovered and enrolled.

  The demo fleet follows: its Windows domain controller had been shown as
  successfully scanned with sixteen findings, which advertised the very
  capability being withheld. It is now enrolled and never scanned, and the
  Windows host that showed a connection failure — implying a scan was attempted
  — became a Linux bastion host carrying that state instead. README, the page
  description, `DEPLOYMENT.md` and `SECURITY.md` no longer describe Windows as
  scannable.

- **Exploitation is now the only thing painted red.** The "Actively exploited"
  triage card shared `data-tone="critical"` with the "Critical findings" card
  beside it, so the one distinction the entire ranking is built on was not
  encoded in the palette at all, on the screen where it matters most. It now
  uses `--exploit`, the red the palette reserves for exactly this — and drops
  back to a neutral tone when the KEV feed has never loaded, because a zero
  there is an absence of an answer rather than an all-clear.

- **Every emoji in the interface replaced with icons.** 74 in total. Emoji
  render as three different drawings across Windows, macOS and Linux, cannot
  respond to the theme, and were announced by screen readers alongside the
  labels they sat next to. Two of them also contradicted the palette directly:
  a red beacon on the Critical findings card, where severity must stay amber,
  and a yellow bolt on a scan action, where actions are verdigris.

- **A type scale and a spacing scale.** There were 25 distinct font sizes across
  87 declarations, nine of them between 0.72 and 0.90rem doing the same job —
  0.75 and 0.76 were a rounding error apart, not a decision. Now nine named
  steps. Spacing had one token that almost nothing used; it now has a 4px ramp,
  applied to new and touched rules rather than retrofitted blind.

- **The light palette is defined once.** It existed as two byte-identical
  55-line blocks — one in a `prefers-color-scheme` query, one under
  `[data-theme="light"]` — so every light-theme colour had to be changed twice
  and silently drifted if it was not. Colours are now `light-dark()` pairs in
  `:root`, with three small `color-scheme` rules deciding which half applies.

- **`color-scheme` is now declared.** It never was, so native scrollbars, form
  controls and the browser canvas rendered light while the application rendered
  dark.

- **Radii use their tokens.** Twenty hardcoded values (4, 6, 8, 10 and 12px)
  bypassed the 2/3/4px scale, concentrated on modals, cards and toasts — the
  largest and most-noticed surfaces, and precisely where the documented "the
  10-14px radius everywhere is the tell of a template" intent was being
  contradicted.

- **Shadows and scrims are tokenised**, including one `rgba(0, 0, 0, 0.08)`
  hover state that was invisible in the theme it shipped in.

- **The dashboard version badge reads `GET /api/health`** instead of a literal
  in JSX. The version a user quotes in a bug report is now the version actually
  running, and cannot drift by construction.

- **README rewritten for an outside reader.** Quick start moved above the
  from-source instructions, the feature list rewritten out of its
  marketing register into the voice of the rest of the documentation, badges
  added, and the Kiro credit moved in from a file that is not published.

- **`docker-compose.yml` pulls the published image** rather than building from
  source, so `docker compose up -d` works without a checkout. `build: .` is one
  comment away for development.

- **Backend packaging metadata:** `license`, `authors`, classifiers and
  `[project.urls]` added to `pyproject.toml`; `license` added to
  `package.json`.

### Fixed

- **An OSV outage produced a clean scan instead of a partial one.** This broke
  the promise the project is built around (Requirement 10.1, Property 5), on
  Linux as well as Windows, and it shipped undetected through every earlier
  release.

  `OsvHttpClient` caught every per-query failure and returned no advisories. The
  matcher marks a source unavailable only when the client raises, so an
  unreachable OSV, an HTTP 5xx, or a query OSV rejects all came back as a
  complete scan with zero findings. It also cached those failures as negative
  results for the rest of the scan.

  The matcher's own degradation test passed throughout, because it drove the
  matcher with a fake client that *raised* — proving the matcher correct at a seam
  the real client never reached. The client now raises `OsvUnavailableError`
  whenever any query goes unanswered, caches nothing from a failed call, and nine
  new tests drive the **real** client through a mocked transport: unreachable,
  HTTP 503, and OSV's 400 for an invalid ecosystem, each checked at the client and
  again through the matcher. Eight of them fail against the previous client; the
  ninth guards the healthy path. Found in pre-publication review by asking what a
  Windows scan would actually match against.

- **A real host address from the development network was in a test fixture and
  a UI placeholder.** It was used as an enrollment fixture in the discovery
  tests and as the example hostname in the scan form, so it had shipped in the
  dashboard for several releases. Both now use the repository's documentation
  placeholder, and the discovery test's other fixture moved off that subnet too.

  `AGENTS.md` §6 forbids this in exactly those words — "never commit secrets,
  credentials, or real hostnames from your own network -- including in test
  fixtures" — and the sentence had been in the contributor guide the whole time.
  Several deliberate pre-publication reviews missed it, because they searched
  for the markers that feel like leaks: a username, an old project name,
  absolute paths. An address in a test fixture is indistinguishable from a
  placeholder, which is the entire difficulty. The `pre-commit` hook added above
  caught it on its first run.

  Every address in the repository is now loopback, an RFC 1918 private-range
  example, or an RFC 5737 documentation address, and that is recorded as a
  property in the methodology document rather than left as a habit.

- **The push hook's author-email check passed silently on a first push.** When
  the remote has never seen the branch, the range starts from the empty tree,
  and `git log <tree>..<commit>` is an error rather than a range. With stderr
  discarded, that error read as "no offending commits" — so the check that
  exists to keep a personal address out of a public history did nothing on the
  one push where every commit is new. The range is now built from commits only.
  Earlier testing missed it because the throwaway remote already had history.

- **The local version gates checked two of the four version strings.** The push
  hook and `Verify-Release.ps1` compared `backend/pyproject.toml` with
  `frontend/package.json`, but not `backend/app/api/app.py` — which is what
  `/api/health` reports and therefore what a bug report quotes. The release
  workflow checks all four, so a local "all clear" could still fail in CI after
  the tag already existed. Both now use the same expressions as
  `.github/workflows/release.yml`, and the hook reads the versions from the
  commit being pushed rather than from the working tree.

- **`Verify-Release.ps1` could not run under Windows PowerShell 5.1.** It used
  `-SkipHttpErrorCheck`, which exists only in PowerShell 7, so every demo-mode
  refusal check would have reported a failure; and it combined
  `$ErrorActionPreference = 'Stop'` with redirected native stderr, which on 5.1
  aborts the run at the first warning npm or docker prints. It judges every
  check by exit code, so it now continues on stderr.

- **A spec cross-reference broken by the renumbering.** One requirement
  described itself as extending "Req 12", which was correct when the requirement
  it referred to was numbered 12 and wrong once it became 10. The check written
  to catch this class of breakage looked for `Req N.M` and for the word
  "Requirement"; a bare `Req N` matched neither. The checker now parses bare and
  comma-grouped references.

- **A count in the README that was simply wrong.** The specification has 85
  acceptance criteria, not the 79 previously claimed. The published documents no
  longer state these totals at all — an earlier "240 citations" claim had gone
  stale the same way — and point at `scripts/check_spec_citations.py` instead.

- **The README's headline install command did not work.** It named
  `cvedeck:latest`, an image that exists on no registry; releases publish to
  `ghcr.io/reprodev/cvedeck`. This was the first command a visitor would run.

- **`frontend/package.json` was version `0.0.0`** across every release through
  0.5.2. The release workflow gated the tag against `app.py` and
  `pyproject.toml` but not the frontend, so it drifted unobserved. The gate now
  covers it.

- **`.workspace-tab-btn` was defined twice** with conflicting designs, so the
  solid-accent active state intended for the top navigation never rendered —
  both the navigation and the drill-down sub-tabs fell through to the tinted
  treatment and were indistinguishable. The two are now distinct: the
  navigation changes which application you are in, the sub-tabs filter one
  table.

- **`.search-box` was also defined twice**, with a dead twin carrying a
  different flex basis, input background and focus-ring width.

- **`severity-badge` was not a class.** The discovery view's port and service
  pills carried `badge-low` for colour but never `badge` for shape, so they
  rendered with a tint and no pill.

- **Three discovery cells requested JetBrains Mono**, which is not loaded
  anywhere, and silently fell back to generic monospace instead of IBM Plex
  Mono.

- **`.patch-filter-btn` and its four variants were dead**, left behind when that
  filter row became sub-tabs.

- **`SECURITY.md` pointed at a roadmap that was not a public artifact**; it now
  links `AGENTS.md` §5.

- **Four chapters of `docs/DEVELOPMENT_STORY.md` were still marked
  `(Unreleased)`** long after shipping in 0.4.0.

- **`AGENTS.md` §6 addressed "the user"**, who has no referent to an outside
  reader — agent-harness instruction that had leaked into a contributor
  document.

- **`DEPLOYMENT.md`'s upgrade instructions said `--build`**, which no longer
  applies now that compose pulls. Without `docker compose pull` the old image
  keeps running, the database migrates forward, nothing errors, and the only
  symptom is that the release you expected is not the one running.

### Removed

- **`MOVING-TO-LOCAL-FOLDER.md` and a tracked editor artifact are no longer in
  the repository.** Both were `export-ignore`d, which only affects
  `git archive` and does nothing for `git push`. They are now untracked and
  ignored. The two pure-IDE files under `.kiro/specs/cvedeck/` (a spec UUID and
  a map of task run timestamps) went with them; the specification text itself
  stays, because roughly 240 `Req X.Y` and `Property N` citations across the
  source and tests point into it.

### Changed

- **Node 22, and the frontend toolchain brought up to date.** Node 20 left
  maintenance in April 2026, so the Docker build stage and both CI jobs were
  running an end-of-life runtime. `Dockerfile` now builds on `node:22-alpine`
  (v22.23.2) and CI pins `node-version: "22"`.

  The toolchain moved with it: **vite 5.4 to 8.3**, **vitest 2.0 to 5.0**, and
  **@vitejs/plugin-react 4.3 to 6.1**. That clears all five advisories `npm
  audit` reported -- one critical (`@vitest/mocker` arbitrary file read via a
  redirect mock), one high (`vite` path traversal in optimized-deps `.map`
  handling), and three moderate -- and `npm audit` now reports zero. None of
  them ever reached the shipped image, which serves pre-built static assets, but
  a public repository advertising a critical advisory invites a report that
  costs more to answer than the upgrade did.

  Vitest 5 is what forced the Node bump rather than the other way round: it
  requires `^22.12 || ^24 || >=26`, while vite 8 is content with 20.19.

  `package.json` now declares `engines: { node: "^22.13.0 || ^24.0.0 || >=26.0.0" }`
  -- the actual intersection of what vite, vitest and jsdom require, so a
  contributor on an older runtime gets a clear npm warning instead of confusing
  test failures.

  jsdom stayed on 29 deliberately. It was not one of the advisories, and jsdom
  30 requires `^22.22.2 || ^24.15.0`, which is stricter than anything else in
  the toolchain and excludes Node 24.0 through 24.14 -- a constraint with no
  security benefit attached.

  No source change was needed: 249 frontend tests, the typecheck, and the
  production build all pass unaltered, and the built asset hashes are unchanged.

- **Every acceptance criterion in the spec is now cited from the code.** The
  source carried 240 `Req X.Y` citations, and all of them pointed at
  Requirements 1 to 7. Requirements 8 to 15 — network discovery, SSH key
  authentication, trustworthy scan reporting, host runtime context, fleet-scale
  operation, remediation guidance and demonstration mode — had none, and the
  demo-mode module referenced the spec not at all.

  That is the half of the project's own rule that had quietly stopped being
  followed. `AGENTS.md` §0 names the spec as the source of truth and tells
  contributors to update it alongside any behaviour change; `tasks.md` maps
  tasks to requirements, but it was completed before those eight requirements
  existed, so nothing linked them to the code that implements them. A reader
  checking whether the citations were real would have found seven requirements
  covered and eight decorative.

  All **85 criteria across all 15 requirements** are now cited, verified by
  `scripts/check_spec_citations.py`, which resolves every reference against
  `requirements.md` and `design.md` and separately checks that no criterion is
  left uncited. Docstrings and comments only — no behaviour changed, and the 422
  backend and 249 frontend tests pass unaltered.

- **A stale cross-reference in the spec is corrected.** Requirement 15.6 said it
  extended "Req 12", written when the requirement now numbered 10 was numbered
  12. The renumber above moved the headings but not the in-text references, and
  the check that was supposed to catch this looked for `Req N.M` and the word
  "Requirement", so a bare `Req N` slipped through. It now reads Req 10, and the
  checker parses bare and comma-grouped references too.

- **The specification's requirements are renumbered to run contiguously.** The
  six requirements added after `tasks.md` was completed were numbered 12 to 17,
  leaving nothing at 10 or 11 and making the numbering read as an error rather
  than a gap. They now run from 10:

  | Was | Is | |
  | ---: | ---: | :--- |
  | 12 | **10** | Trustworthy scan reporting |
  | 13 | **11** | SSH key-based authentication |
  | 14 | **12** | Host runtime context |
  | 15 | **13** | Fleet-scale operation |
  | 16 | **14** | Accurate and reachable remediation guidance |
  | 17 | **15** | Public demonstration mode |

  No citation changed. All 240 `Req X.Y` references in the source and tests
  point at Requirements 1 to 7, and nothing outside `requirements.md` mentioned
  the renumbered ones -- not the design document, not `tasks.md`, not this
  changelog. Earlier entries here that cite a requirement number are therefore
  still correct as written.

  Requirements 9 and 11 both cover SSH key authentication, which is what made
  the gap look like a mistake in the first place. The addendum now says so and
  explains how they differ.

### Repository

- **The repository was re-established with fresh history.** Development happened
  in a folder named after a working title the project outgrew, and that name --
  along with a local absolute path -- survived in old commit messages and in a
  since-corrected CHANGELOG entry, even though no tracked file at `HEAD`
  mentioned either. Restarting the history is what removes them; rewriting 86
  commits to scrub two strings would have been more disruptive and less
  complete. Nothing is lost: both side branches were fully merged first, and the
  specification, the changelog, and the development story are the continuous
  record of how the project got here.

- **A code of conduct** (`CODE_OF_CONDUCT.md`), Contributor Covenant 2.1, linked
  from `README.md` and `CONTRIBUTING.md`. It was the only standard file a public
  repository is expected to carry that was still missing.

- **The three design mockups are published** as `docs/design/`, with the
  reasoning that chose between them. They had been kept local and git-ignored as
  evaluation artifacts, but Chapter 10 of the development story argues that
  putting two renderings side by side settled a question no amount of discussion
  had, and that argument is considerably weaker when the renderings themselves
  are not in the repository. They are a snapshot of the decision and are
  deliberately not kept in step with the dashboard.

---

## [0.5.2] - 2026-09-03

A visual identity, and the token cleanup it exposed.

### Changed

- **New design language: "rack and label".** A fleet is physical, so hostnames
  render as stamped asset tags rather than links. Archivo (variable, width axis)
  and IBM Plex Mono replace Inter and JetBrains Mono; an industrial enamel
  palette replaces near-black navy.

  The previous look was the AI-default signature almost literally: every colour
  token was Tailwind's stock palette unmodified (`blue-500`, `rose-500`,
  `slate-400`) and the typefaces were the most common pairing in generated UI.

- **Colour is now scarce and earned.** Three tiers and nothing else: neutral for
  interface, a single amber ramp for severity, and red reserved exclusively for
  confirmed exploitation. Previously an unexploited Critical and an actively
  exploited finding were both red — mocking both treatments side by side showed
  the red criticals swamping the exploitation marks entirely, which quietly
  undercut the ranking the previous two releases were built around.

- The asset tag's **left edge repeats the exploitation state**, so it survives
  peripheral scanning and colour-vision deficiency.

### Fixed

- **`var(--primary)` was referenced nine times and defined nowhere.** Every
  "active" state on the nav tabs, platform filters and blast-radius filters had
  been falling back to transparent since it was written; the indigo appearance
  came from a hardcoded box-shadow, not a fill.
- **138 hardcoded colour literals removed** — 102 in `index.css` outside the
  palette blocks, 36 in JSX `style` props, all Tailwind defaults. None could be
  reached by the token layer, which is why the theme toggle was only ever
  partly working and why a palette swap left indigo everywhere. The v0.5.1 fix
  addressed a handful of these; this is the rest.
- Two competing `.hostname-link` rules and a duplicate `.workspace-tab-btn`
  block, where the later definition silently won.

### Changed — second pass

The first pass over-applied its own rule. "Colour is scarce" is right for the
*data*; applying it to the *interface* as well left the primary action grey on
grey and the whole surface at one flat value.

- **Verdigris accent** — what copper does on real equipment. Chromatically
  opposite the amber ramp, so it carries every interactive element without ever
  competing with severity, and it appears nowhere in the data. The primary
  action looks like one again.
- **Wider surface range.** The previous values sat inside about eight levels, so
  nothing read as layered — disciplined but flat.
- **The severity ramp is legible at the bottom.** It now separates by saturation
  rather than by lightness. The first version pushed Medium and Low so far down
  in value they were unreadable, which only surfaced against a real fleet
  carrying 398 Mediums; the seed had none.
- **A wordmark instead of an emoji and a name.** `cve` sits quiet and `DECK` is
  stamped with the same border, inset and letterspacing as the hostname tags, so
  the logo and the host rows are visibly the same idea.

### Fixed — mobile

- **Roughly 360px of dead vertical space at phone width.** `.toolbar` switches to
  `flex-direction: column` below 700px, and a flex-basis is read along the *main*
  axis — so `flex: 1 1 280px` on the search box stopped meaning "280px wide" and
  started meaning "280px tall, and grow". Two children doing that pushed the
  fleet table a full screen below the fold, on the layout with the least room to
  spare.
- **The fleet table now becomes cards below 700px**, with each cell's field name
  supplied from a `data-label`. The `<table>` element is unchanged; this is a
  re-flow, not a restructure.
- **Column priority by information value.** Medium and Low drop out below 1080px,
  the per-row quick-scan button below 1000px, and platform below 900px — so
  Exploited, Critical and High stay on screen at tablet width instead of sitting
  behind a horizontal scroll nobody performs. Targeted by `data-col` name rather
  than `nth-child`, which would shift the moment a deployment with a
  server-managed SSH key adds the select column.
- **Triage cards go to one column below 520px** and turn horizontal, which reads
  faster and costs a third of the height of the stacked form. Two 175px cards
  could not hold "3 hosts · 3 on CISA KEV" without breaking it over three lines.
- `minmax(0, 1fr)` and `min-width: 0` on the triage grid: a `1fr` track carries
  `min-width: auto` and refuses to shrink below its content, so the long mono
  strings were setting the floor.

- **The drill-down sub-tabs overflowed too.** The Dependency Map grid carried a
  hard `minmax(360px, 1fr)` track floor — wider than the content area of a 390px
  phone, so the track could not shrink and the page grew instead. Inside each
  card, a long package identifier and a severity badge both defaulted to
  `min-width: auto` and pushed each other 52px past the card's own edge.
  By Package was worse at +125px, from unbreakable package identifiers and
  nested drawer tables.

Verified by measurement rather than by eye — `scrollWidth === clientWidth` at
360, 390 and 820px, and across all five drill-down sub-tabs.

### Fixed — a blank dashboard after every upgrade

- **The served frontend now sends cache headers.** Without them, upgrading broke
  the dashboard for anyone whose browser had it open before. The build emits
  content-hashed asset names and `index.html` names the current ones, so a
  cached `index.html` outlives the assets it points at: after an upgrade the
  browser requests hashes that no longer exist, and the page loads with no CSS
  and no JavaScript. Nothing errors. The page is simply blank, and the only cure
  a user can find is clearing site data.

  `index.html` is now revalidated on every load; everything under `/assets/` is
  `immutable` for a year, which is safe precisely because the content hash is in
  the filename. The two policies are opposites on purpose, and a test asserts
  they never converge.

  Found while diagnosing a phone that rendered black: it was serving a cached
  entry point from three builds earlier.

### Removed

- **The runtime request to `fonts.googleapis.com`.** Both families are now
  vendored as latin-subset woff2 under `src/fonts/` (136KB total). This is a
  correctness and privacy fix as much as a design one: on the isolated networks
  this scanner is built for, the fonts silently never loaded and the shipped
  design was not the design operators saw — and every dashboard load reported
  the IP of a machine running a vulnerability scanner to a third party.

Frontend tests: 244, unchanged and unmodified. `vite.config.ts` sets
`css: false` for vitest, so the suite cannot see styling — which makes an
untouched green suite the evidence that this stayed in the visual layer.

---

## [0.5.1] - 2026-09-02

Dashboard usability. Reviewed by running the app against a seeded twelve-host
fleet and looking at it, which is how the first two items below were found --
neither is visible by reading the code.

### Added

- **Exploitation column in the fleet table.** The three actively exploited hosts
  previously looked identical to every other row: the KEV signal existed only in
  a summary card. Carries the same three states used everywhere else -- a badge,
  a muted zero for checked-and-clear, and a dimmer dash for never-checked.
- **Risk ordering by default.** The fleet table sorted alphabetically, which put
  an actively exploited host eleventh of twelve. Default order is now KEV, then
  critical, then high -- the ranking the findings table already used, applied to
  hosts.
- **URL-backed navigation** (`#/fleet`, `#/scan`, `#/machines/<id>`). Screens can
  be linked, bookmarked, and reached with browser back. Previously every screen
  lived at `/`, so a refresh dropped you at the fleet list and sharing "look at
  this host" meant describing where to click.
- **Theme toggle**, cycling system → light → dark → system.

### Changed

- **The fleet summary is one row of four cards instead of ten in two rows.** The
  old layout stacked two five-card grids of identical visual weight where one
  counted *hosts* ("9 Critical P0 Hosts") and the other counted *findings* ("25
  Critical"), with nothing on screen saying so. Every card now counts hosts and
  states its unit ("3 hosts · 25 findings"); findings totals moved to a visually
  distinct strip that doubles as the severity filter.
- Stale, never-scanned and failed folded into one **Needs attention** card. Three
  separately-ignorable cards became one that answers a question worth asking
  daily: whose data can I not trust right now.
- Removed two prose panels -- one restated the card directly above it, the other
  was onboarding text that showed forever -- and the severity dropdown, which the
  new chip row duplicated.
- Roughly 900px of chrome before the first host row, down to about 330px at
  1600px wide: eleven hosts visible instead of four. At 820px the card grid
  wrapped 3+2 with an orphan and is now a clean 2×2.
- **The drill-down header got the same treatment as the fleet page.** Five KPI
  cards and a full-width progress card cost roughly 250px above the tabs, and
  duplicated counts the tabs already carried (`All Findings (6)` appeared in
  both). They are now a single strip: exploitation state, severity chips, and
  remediation progress, sharing `.sev-chip` with the fleet view so the two
  screens read as one product.
- **The host page now says whether anything on it is being exploited.** That was
  absent from the drill-down entirely, so a host flagged on the fleet page said
  nothing about it once opened. Three states as everywhere else: a count, "none
  actively exploited", and a quieter "exploitation unknown" when no finding here
  was ever checked.
- `MachineDrillDownView` split 1,761 → 1,377 lines; `CveDetailModal` and
  `RemediationCell` moved to `components/`. All existing tests passed untouched,
  which is the evidence the extraction preserved behaviour.

### Fixed

- **Light mode could not have worked.** Toasts, partial-scan badges, stale
  timestamps and empty states were light-first hardcoded colours patched back to
  dark by stray `prefers-color-scheme` blocks -- and no `data-theme` attribute
  can override a media query. Those are tokenised now (`--surface-muted`,
  `--warn-bg` / `--warn-text` / `--warn-border`), the stray blocks are gone, and
  the light query is guarded with `:not([data-theme="dark"])` so the toggle works
  in both directions rather than only away from the OS setting.
- **A malformed shared link would have crashed the app.**
  `decodeURIComponent` throws on a bad escape, which a truncated or hand-edited
  URL produces easily. `parseHash` now falls back to the raw segment.
- **Navigation would have lagged a frame behind every click.** The first routing
  implementation assigned `location.hash` and waited for the `hashchange`
  listener, which fires asynchronously in a browser and never in jsdom. State is
  now set at the call site; the listener handles only navigation originating
  outside the hook.
- Two implementations of `remediationStatusLabel` existed, in `lib/labels.ts` and
  privately in the drill-down, and they disagreed ("In progress" vs "In
  Progress"). Nothing imported the shared one, so no user ever saw it -- a trap
  waiting for someone to import the wrong one. Consolidated on the version that
  actually ships, so no visible text changed.
- Hostnames no longer break after their hyphen, which made `db-primary.lan` read
  as two hosts at narrow widths.
- **An intermittent test failure.** Vitest defaults to a 5s timeout, and
  `userEvent` simulates real typing with a delay per keystroke, so the form tests
  legitimately take one to two seconds each. Adding roughly fifty tests pushed
  the slowest of them over the default under parallel load, surfacing as a flake
  in `ScanFormView` -- a file none of this work touched. Raised to 20s. A flaky
  test is worse than a failing one: it teaches people to re-run rather than look.

Frontend tests 192 → 244.

---

## [0.5.0] - 2026-09-02

Threat-intelligence enrichment. Findings now carry evidence of whether anyone is
actually exploiting them, not only how bad they would be if someone did.

### Added

- **CISA KEV integration.** The Known Exploited Vulnerabilities catalogue is
  cached locally and joined against every finding. A finding on the KEV list is
  being exploited in the wild right now, and carries CISA's federal remediation
  due date.
- **FIRST EPSS integration.** Every finding is annotated with its modelled
  probability of exploitation in the next 30 days, and that probability's
  percentile rank. The percentile is shown alongside the raw score because the
  EPSS distribution is heavily skewed -- 0.07 reads as negligible and is in fact
  around the 94th percentile.
- **Real NVD 2.0 client** (`backend/app/scanner/nvd_client.py`). `NvdClient` had
  been a bare Protocol with nothing behind it since the first release. OS-level
  matching is opt-in via `CVEDECK_NVD_ENABLED` and self-throttles to NVD's
  published rate limits, treating a 403/429 as a source outage rather than an
  error so a throttled scan reports partial results instead of reading as clean.
- **`GET /api/feeds`** reports each feed's cache age, record count, and staleness.
- **`POST /api/feeds/refresh`** pulls both feeds. They refresh independently, so
  an outage at one upstream does not cost the other's update.
- **Fleet "Actively Exploited" triage card**, placed first in the triage row: a
  vulnerability being exploited today outranks one that merely scores highly.
- **Exploitation column in the findings table**, with EPSS score and percentile.
- **Risk ordering, on by default** -- KEV, then EPSS, then CVSS. A CVSS 6.5 that
  attackers are using outranks a CVSS 9.8 nobody has touched. A toggle restores
  CVSS order for compliance reporting.
- **Enrichment staleness banner**, shown whenever a feed is stale or unusable.
- **`cvedeck-feeds.timer`** (systemd) refreshes both feeds daily at 03:00 with
  a randomised delay and `Persistent=true`, installed and started by
  `deploy/install.sh`. The randomisation is not cosmetic: every instance firing at
  exactly 03:00 would be a self-inflicted thundering herd on two free public
  services this project depends on. Docker deployments get a cron one-liner in
  `DEPLOYMENT.md`.

### Changed -- BREAKING

- **Renamed throughout to CveDeck.** Done now, before the first public release,
  because it is the only moment it costs nothing: there are no external users to
  break, and after launch the environment-variable prefix would be frozen forever.

  | Was | Now |
  | :--- | :--- |
  | `CVE_SCANNER_*` (20 variables) | `CVEDECK_*` |
  | `cve_scanner.db` | `cvedeck.db` |
  | `cve-scanner:latest` (image) | `cvedeck:latest` |
  | `cve-scanner.service` | `cvedeck.service` |
  | `cvescanner` (service user) | `cvedeck` |
  | `/opt`, `/etc`, `/var/lib/cve-scanner` | `.../cvedeck` |
  | `deploy/nginx/cve-scanner.conf.example` | `deploy/nginx/cvedeck.conf.example` |

  **Upgrading an existing local install:** rename every `CVE_SCANNER_*` variable
  in your env file to `CVEDECK_*`, and rename the database file:

  ```bash
  mv /var/lib/cvedeck/cve_scanner.db /var/lib/cvedeck/cvedeck.db
  ```

  The filename change is silent if you skip it -- the application creates a new
  empty database rather than failing, so an un-renamed file looks like a fleet
  that lost all its history. Rename it before the first start.

  No schema change: the database itself is untouched, only its filename.

### Changed

- `MachineSummary` gained `kev_count`; `CveFindingOut` gained `kev_listed`,
  `kev_due_date`, `epss_score`, and `epss_percentile`.
- Findings are enriched after matching and before persistence, so the signals are
  stored rather than merely displayed. `Matcher.match` remains pure and untouched.

### Invariants

- **An unenriched finding is visibly unenriched.** `kev_listed = null` means "not
  checked"; `kev_listed = false` means "checked, and genuinely not in the
  catalogue". These are never collapsed, in the database, the API, or the UI.
  Presenting a stale or failed feed as "nothing here is being exploited" would be
  a silent false negative -- the same failure mode `last_scan_sources_ok` exists
  to prevent for scan sources.
- **A failed refresh never empties a good cache.** Yesterday's KEV answer beats
  no answer, and an empty catalogue from a 200 response is treated as a failure
  rather than written, because writing it would erase every KEV flag in the fleet.
- **Enrichment cannot cost a scan its findings.** A defect in the enrichment pass
  is logged and the findings persist unenriched; collected inventory is the
  expensive part of a scan and a local cache lookup must not put it at risk.

### Migration

`a1c7f3e9d204` adds `kev_entries`, `epss_scores`, and `feed_refreshes`, indexes
`cve_findings.cve_id`, and adds four nullable enrichment columns. Existing
findings migrate to `NULL`, not to `false` -- they were written before enrichment
existed and nothing checked them.

---

## [0.4.2] - 2026-09-01

A major information architecture and user experience restructuring release.

### Added

- **Top-Level Dedicated Workspaces:**
  Split the UI into 3 clean, dedicated workspaces accessed via the top navigation bar:
  - `📊 Fleet Overview`: Clean operational inventory of monitored infrastructure, KPI summary metrics, and 1-click triage action cards.
  - `🚀 New Scan`: Dedicated scanning workspace providing an uncluttered interface for initiating manual Linux (SSH) and Windows (WinRM) scans, live connectivity testing, and key auth.
  - `🔍 Network Discovery`: Zero-touch network sweep and automated asset onboarding.
- **Fleet Overview Quick Action Triage Cards:**
  Added high-signal, keyboard-accessible quick triage cards above the main machine inventory table:
  - 🚨 *Critical P0 Hosts*: Quickly isolates machines with Critical (CVSS 9.0–10.0) findings requiring immediate patching.
  - ⚠️ *High Risk Hosts*: Filters machines with High severity vulnerabilities.
  - ⏳ *Stale Scans*: Flags hosts whose last scan occurred more than 7 days ago.
  - 🆕 *Enrolled Hosts*: Highlights discovered hosts awaiting their baseline scan.
  Clicking any triage card applies an instant filter to the inventory table; clicking it again or using Space/Enter resets the filter.
- **Structured Machine Drill-Down & Findings Explorer:**
  Reorganized the single-pane machine inspection view into structured, focused sub-tabs:
  - `🛡️ Vulnerability Findings`: Full findings table with severity chips, search, patch readiness filters, and 1-click inspection modal.
  - `📋 Overview & Fix Plan`: Machine posture summary, KPI breakdown, actionable bulk fix script generator, and distribution upgrade guidance.
  - `🌳 Package Blast Radius`: Dependency impact assessment, reverse dependency counts, and leaf component purge indicator.
  - `📝 Remediation & Audit`: Dedicated compliance tracking table for auditing status and notes.

### Fixed

- **Eliminated horizontal overflow in Drill-Down Findings Table:**
  Replaced the cramped master-detail split pane with a full-width responsive findings table and rich inspection modal, providing complete horizontal breathing room for CVE details, severity badges, CVSS scores, remediation status, and inline note editors without clipping or horizontal overflow.

---

## [0.4.1] - 2026-09-01

A deployment reliability and UI refinement patch.

### Fixed

- **Docker container startup failure due to missing `alembic.ini`:**
  During database session initialization, the migration runner attempted to load
  `/app/alembic.ini`, causing `FileNotFoundError` and returning HTTP 500 across API
  endpoints on fresh container boots. `Dockerfile` now explicitly packages
  `backend/alembic.ini` into `/app`, and `app/data/migrations/env.py` and
  `app/data/migrations_runtime.py` include defensive `Path.is_file()` existence checks.
- **Scan Form field vertical misalignment:**
  Placing the platform auto-detection badge (`⚡ Auto-detected: Linux (SSH)`) inside a
  flex row with the `PLATFORM` label forced the label container to wrap into multiple
  lines, displacing the platform select input below neighboring fields. The badge is
  now positioned cleanly underneath the select input as a helper hint, and `.scan-form-grid`
  uses `align-items: start` to preserve horizontal alignment across all inputs.

---

## [0.4.0] - 2026-09-01

A correctness and capability release for the Linux path.

Two defects here share a shape with the one fixed in 0.3.1: an error path that
reported nothing, so the software looked like it was working. The OSV batch
endpoint silently stopped batching, and copy-to-clipboard did nothing at all on
the plain-HTTP origins this tool is actually reached on. Neither surfaced as a
failure. The reasoning behind each is in `docs/DEVELOPMENT_STORY.md`.

A second theme was capability that had been built and never exposed: per-source
status, scan timestamps, the engine's captured error message, and multi-target
batching all existed in the backend and stopped short of the API or the UI.

**Upgrading:** the schema is migrated automatically on first start, including
databases created before this release. Back up your database first; see
DEPLOYMENT.md.

### Fixed - Review pass

Found while reviewing this release before hand-off.

- **A marker inside `/etc/os-release` corrupted the batched context split.**
  The three inventory sections are separated by a delimiter, and the first
  section is arbitrary vendor-supplied text; a delimiter appearing inside it (in
  a `HOME_URL`, say) shifted every later section and produced a garbage kernel
  version with no error. Now split from the right, since only the leading
  section is target-controlled.
- **`useClipboard` left its reset timer running on unmount.** Copying a command
  and hitting "Back to machines" inside the two-second window fired setState on
  an unmounted component.
- **The clipboard's `aria-live` announcement was produced and never rendered**,
  so screen-reader users still got no copy confirmation -- the accessibility gap
  this release set out to close. Now rendered in both the drill-down and the
  CVE modal.
- **`DiscoveryView` seeded its enrolled-host set once and never resynced it**, so
  hosts already in the fleet showed "Add" whenever the machine list resolved
  after the view mounted, which is the normal ordering on a fresh page load.
- Credential validation errors no longer leak Pydantic's `"Value error, "`
  prefix into the operator-facing message.

### Fixed - Critical: the universal ecosystem fallback never batched

- **`_ALL_LINUX_ECOSYSTEMS` contained two names OSV.dev does not recognize**
  (`Arch Linux`, `Fedora`). OSV's `/querybatch` rejects the *entire batch* with
  HTTP 400 when a single query names an invalid ecosystem, so every batch that
  reached the universal fallback failed and silently degraded to the per-package
  error path: one HTTP request per package per ecosystem. On a 1,000-package host
  that is ~10,000 individual requests in place of ~20 batches, defeating the
  "fast scan" design the AGENTS.md matcher invariant describes.
- **Distributions without an OSV ecosystem now map onto the tracker they derive
  from** rather than being queried under a name OSV rejects: Oracle Linux and
  Amazon Linux resolve to Red Hat / AlmaLinux / Rocky Linux, Fedora resolves to
  Red Hat, and Arch takes the universal fallback.
- **Red Hat is queried unversioned.** OSV accepts `Red Hat:9` but returns nothing
  for it, so a version suffix succeeded while silently losing every finding.
- `tests/test_ecosystem_resolution.py` pins the valid/invalid ecosystem sets and
  asserts no input can resolve to a name OSV would reject.

Verified against the live API: the fallback batch now returns 200, and Oracle
Linux 9, Rocky Linux 9, Alpine 3.18, and an unknown distribution return 27, 49,
19, and 219 findings respectively.

### Fixed - Copy to clipboard silently did nothing on a LAN

- Both copy helpers guarded on `if (navigator.clipboard)` and did nothing when it
  was absent -- no error, no fallback. `navigator.clipboard` is undefined in any
  non-secure context, i.e. every origin except HTTPS and localhost, which is
  exactly how this tool is reached (`http://192.168.1.50:8000`). The headline
  "1-click fix" was a no-op for most real deployments, and the promise had no
  `.catch()`, so a rejected write became an unhandled rejection.
- New `useClipboard` hook: async API, `document.execCommand` fallback, an error
  toast on failure, and an `aria-live` announcement so the copy confirmation is
  not purely visual.

### Added - Schema migrations (Alembic)

- **Alembic migration story** (`backend/alembic.ini`, `backend/app/data/migrations/`).
  Previously `Base.metadata.create_all` was the entire story: correct for a fresh
  database, and no answer at all for an existing one, so any column added after
  v0.3.0 would have broken every deployed instance on upgrade.
- **`app/data/migrations_runtime.py:upgrade_to_head`** runs on first engine use for
  both the local and online databases, handling three cases: an empty database is
  created from ORM metadata and stamped `head`; a pre-Alembic database (tables but no
  `alembic_version`) is stamped at the baseline revision and migrated forward; an
  already-managed database is upgraded. Idempotent and safe on every startup.
- The Alembic env resolves the database URL through `app/config.py` rather than
  `alembic.ini`, so migrations always target the database the application uses and
  `app/config.py` remains the only module reading the environment.
- `render_as_batch` is enabled because the default SQLite deployment cannot
  `ALTER COLUMN`; it is a no-op on PostgreSQL.
- `tests/test_migrations.py` (5 tests) covers the fresh, pre-Alembic, and idempotent
  paths, and asserts existing rows survive a migration.

---

### Added - SSH key authentication (roadmap Phase A and B)

- **`Credentials` accepts `private_key` and `passphrase`** (both `SecretStr`),
  with `password` now optional and a validator requiring exactly one method.
  Password-only auth excluded every passwordless Linux environment.
- **`parse_private_key`** loads Ed25519/ECDSA/RSA keys in PEM or OpenSSH format
  from memory -- never written to disk, since a per-request credential written to
  a temp file outlives the request that supplied it. A wrong or missing
  passphrase is reported distinctly from a malformed key, and parsing happens
  before a client is allocated so a bad key is never reported as a connection
  failure.
- **Phase B server-managed key**: `CVEDECK_DEFAULT_SSH_KEY_PATH`,
  `CVEDECK_DEFAULT_SSH_KEY_PASSPHRASE`, and `CVEDECK_DEFAULT_SSH_USER`.
  A Linux target may omit credentials entirely and authenticate with the server
  key, which is what makes a credential-free fleet re-scan possible. The key is
  re-read per scan so rotation needs no restart. Windows has no fallback --
  WinRM has no SSH-key equivalent, so a missing credential is an error.
- A credential that cannot be resolved fails **that target only**, matching the
  engine's per-target fault isolation for targets that never reach the engine.
- `POST /api/scans/test-connection` resolves credentials identically, so
  pre-flight and the real scan can never disagree.

### Added - Richer Linux inventory

- **Running kernel (`uname -r`) and reboot-required detection.** A host can be
  fully patched and still running the vulnerable kernel it booted from, which a
  package-list-only scan reports as clean. Detected via
  `/var/run/reboot-required` (Debian/Ubuntu) and `needs-restarting -r` (RHEL).
- **Batched into one SSH round trip** with the os-release read, since each round
  trip pays full network latency. Output is captured into a shell variable rather
  than redirected, so the command contains no write redirect and the read-only
  collector invariant still holds.
- `Inventory` gains `kernel_version` and `reboot_required`.

### Added - Distribution coverage

- Oracle Linux (`ol`), Amazon Linux (`amzn`), SLES (`sles`/`sled`), and Raspbian
  are detected in `_parse_os_release`, with `ID_LIKE` used for derivatives.
- **The unknown-distribution fallback is no longer `deb`.** Silently assuming
  Debian produced confidently wrong matches; unrecognized distributions now
  resolve to `unknown`, which routes to the universal fallback.
- openSUSE is tested before SLES, since `opensuse-leap` contains `suse`.

### Added - Trust signals: telling "clean" apart from "broken"

A scan that ran against an unreachable advisory source reported `success` with a
reduced finding count, rendered as a green badge, and was indistinguishable from
a genuinely clean host. Several other states were equally invisible.

- **Data-source health is now reported.** `MatchResult.nvd_status` / `osv_status`
  previously dead-ended in the matcher. `MachineScan` gains `unavailable_sources`
  and `sources_ok`, persisted per machine as `target_machines.last_scan_sources_ok`
  and surfaced in the fleet table as a `⚠ Partial` badge plus a warning toast.
  A source that is not *configured* (NVD, currently) is not counted as unavailable,
  so the warning stays a signal rather than constant noise.
- **`ScanStatus.NEVER_SCANNED`.** Enrollment stamped `CONNECTION_FAILURE` on new
  rows, so every host added from network discovery showed a red failure badge
  before anything had tried to reach it. The new status renders neutral. Existing
  rows are backfilled where `last_scanned_at IS NULL`; rows that genuinely failed
  to connect keep their status.
- **`MachineScanOut.message`.** The engine already captured the originating
  exception and threw it away at the API boundary, leaving the UI to show a bare
  `auth_failure` with no hint whether the cause was a bad password, a bad
  username, or a rejected key.
- **`last_scanned_at` is exposed.** The column existed since v0.1.0 and was never
  serialized, so staleness was unknowable. The fleet table now shows relative time
  and flags scans older than 7 days.
- **`record_status` hook now receives the whole `MachineScan`** rather than just a
  `ScanStatus`, so it can persist the timestamp and source health together.

### Added - Fleet workflow

- **Bulk re-scan.** `startScan` has always accepted an array and the backend has
  always batched with per-target fault isolation; the UI only ever sent a
  single-element array, so re-scanning twenty hosts meant twenty trips through the
  form, retyping credentials each time. The fleet table now has row selection,
  "Re-scan selected", and "Re-scan all shown", using the server-managed SSH key so
  no credentials are retyped.
- **`GET /api/health` reports deployment capabilities.** The re-scan controls are
  hidden when no server key is configured, rather than offered and then failing.
- **Sortable fleet table.** No table in the app was sortable; "which hosts have the
  most criticals" was answered by whatever order the API returned. Sorting is
  keyboard-operable and exposes `aria-sort`. Timestamps sort on the parsed value,
  not the rendered "3d ago" string, and nulls sort last in both directions.

### Added - Remediation

- **`src/lib/remediation.ts`** owns distro tooling, package-name parsing, and
  fix detection, replacing logic duplicated across five surfaces of a 1,791-line
  view.
- **Bulk fix plan**: one script upgrading every fixable package on a host,
  deduplicated (a host commonly has a dozen CVEs against one `openssl`) and
  sorted. Generated only -- nothing is executed, per the manual-remediation
  invariant.
- **Structured `package_name` / `fixed_version` / `has_fix` on findings.** The
  frontend previously searched `package_identifier` for the substring
  `"fixed in"` in nine places, making the exact prose an unversioned API
  contract. Parsed server-side, once.
- **`inventories.kernel_version` and `reboot_required` are persisted.**
  Collecting them without storing them would repeat the missing-last-mile
  mistake this release already fixed twice.

### Added - Frontend

- **`ToastProvider`** (`src/components/Toast.tsx`) replaces four unrelated error
  surfaces: App's undismissable banner, DiscoveryView's red card, ScanFormView's
  result box, and a native blocking `alert()`. Announced via `aria-live`; errors
  are pinned rather than auto-dismissed.
- **`src/lib/labels.ts`** consolidates `severityLabel` (duplicated in two views),
  `statusLabel` (defined in ScanFormView where MachineListView could not reach it,
  so the fleet table rendered the raw enum `connection_failure`), plus
  `relativeTime` / `isStale` / `statusTone`.
- **`src/test-utils/factories.ts`** so a new domain field does not break every
  test fixture that ever constructed one.
- `prefers-reduced-motion` support.

### Fixed - Remediation commands were wrong for most hosts

Per-distribution tooling was chosen in the frontend by substring-matching the
*package identifier*, which produced confidently wrong commands.

- **`copyFixCommand` hardcoded apt** and was wired to the three most-used copy
  surfaces (the By-CVE list, the By-Package table, and the inspector pane), so an
  AlmaLinux or Alpine host was handed `sudo apt install --only-upgrade <pkg>` --
  while the modal, for the same CVE, correctly said `sudo dnf upgrade -y`. Deleted;
  every site now uses the shared tooling.
- **`includes("ol")` matched `tool`, `tools`, `console`, `symbol`, `protocol`, and
  `golang`**, routing Debian packages to `dnf`; `includes("arch")` matched
  `libarchive`, `noarch`, and `search`, routing them to `pacman`. Matching is now
  anchored to the ecosystem prefix.
- **Windows hosts were offered `sudo apt`.** A Windows finding has no Linux
  ecosystem prefix, so every one fell through to the default branch. Tooling is now
  derived from the machine's platform, with a real `winget` path.
- **Two hardcoded purge commands**, one of which had a label (`apt purge`) that did
  not match the command it copied (`apt remove --purge`).
- **Ubuntu Pro / ESM / `do-release-upgrade` advice rendered on every host**,
  including RHEL and Alpine where those commands do not exist. Now gated on Ubuntu.
- **Arch now gets `pacman -Syu`, not a single-package upgrade.** Partial upgrades
  are explicitly unsupported upstream and routinely break the system.
- An unrecognized distribution emits a `#` comment rather than a guessed command.

### Fixed - Platform inference disagreed with itself

- `inferPlatform` existed in both `App.tsx` and `DiscoveryView.tsx` with different
  rules: DiscoveryView treated port 445 as Windows (misclassifying every Samba
  file server), while App.tsx ignored 445 and let an open port 22 force `linux`
  regardless of an explicit Windows banner. The same host got one answer from the
  Discovery tab's Scan button and the other from the scan form. Now one
  implementation in `src/lib/platform.ts` with the precedence documented.

### Fixed - Empty states named the wrong filter

- The fleet view rendered `No machines match ""` whenever the **platform** filter
  was what excluded the rows, because it assumed the search box was responsible.
  The drill-down blamed severity even when the search box or patch filter was.
  Both now name the filters actually in effect and offer to clear them.
- The first-run state points at network discovery instead of only reporting
  emptiness.

### Fixed - Frontend

- **API errors discarded the response body** (`client.ts`). Every failure read
  `Request POST /api/... failed with status 422`, throwing away FastAPI's `detail`
  -- the only text saying what was actually wrong. Now parsed, including flattening
  422 validation arrays, with HTML error pages ignored rather than dumped into the UI.
- **No request timeout existed**, so a hung backend left the scan button disabled
  with no recourse but a page reload. Requests now abort on a deadline and raise
  `ApiTimeoutError`.
- **Stale UI state on navigation.** The error banner and the scan-result panel
  persisted across tab switches indefinitely; both now clear, and the banner is
  dismissible.

### Fixed - Accessibility

- **The CVE modal was a keyboard trap.** `role="dialog" aria-modal="true"` sat on
  the backdrop -- which was also the click-to-close target -- with no Escape
  handler, no focus trap, no initial focus, no accessible name, and no focus
  restoration. `useDialogA11y` supplies all of it.
- **The fleet view's five metric cards were unreachable by keyboard**: plain
  `<div>`s with `onClick` and no `role`, `tabIndex`, or key handler. The
  drill-down's equivalents had role and tabIndex but handled only Enter, so Space
  did nothing. Both now use `toggleButtonProps`, which handles Enter and Space and
  exposes `aria-pressed`.
- `:focus-visible` styling extended beyond native controls to the elements that
  behave as controls without being one.
- Responsive rules for phone widths: `main` no longer keeps 3rem of fixed
  horizontal padding on a 375px viewport, the workspace tabs scroll rather than
  overflow, and toasts span the viewport.

## [0.3.1] - 2026-09-01

### Fixed - Critical: live scans silently returned zero findings

- **`_DEFAULT_POOL_SIZE` was referenced but never defined** (`app/scanner/osv_client.py`).
  The constant is used to configure `httpx.Limits` in the branch of
  `OsvHttpClient.match_packages` that constructs its own HTTP client - the branch
  taken by every deployment, since `wiring.build_osv_client()` injects no client.
  Every real scan raised `NameError`, which `Matcher.match` caught and recorded as
  `DATA_SOURCE_UNAVAILABLE`, producing **zero findings while the UI reported a green
  `success` badge**. The full test suite passed throughout because every existing OSV
  test injects an `http_client` and so never executed that branch.
  Defined as `50`, matching the pooling figures already documented in the AGENTS.md
  matcher invariant (50 keepalive / 100 max connections).
- **`Matcher.match` no longer launders defects into data-source outages**
  (`app/scanner/matcher.py`). `NameError`, `TypeError`, `AttributeError`, and
  `ImportError` now propagate instead of being reported as
  `DATA_SOURCE_UNAVAILABLE`; per-target fault isolation in `ScannerEngine` still
  prevents a single bad target from aborting a batch or returning HTTP 500.
  Genuine network/HTTP failures still degrade gracefully (Property 5 unchanged).
  Both branches now log via `logging.exception` - previously the failure was
  invisible in logs.

### Added

- **`tests/test_osv_client_live_path.py`** (6 tests) closes the coverage blind spot
  by exercising `OsvHttpClient` and `wiring.build_osv_client()` with **no** injected
  client, asserting the pool limits, that the self-constructed client is closed, that
  the matcher reports `OK` on the live path, that programming errors propagate, and
  that real outages still degrade to `DATA_SOURCE_UNAVAILABLE`.

Verified against the live OSV.dev API: an Ubuntu 22.04 package set that previously
yielded 0 findings now returns 160 with correct `fixed in ...` versions.

## [0.3.0] - 2026-08-31

### Phase 1: Zero-Touch Network Asset Discovery
- **Backend `NetworkDiscoveryEngine`** (`app/scanner/discovery.py`):
  - ICMP ping sweep via subprocess `ping` to detect live hosts regardless of open TCP ports.
  - Multi-port TCP connect scanning on enterprise ports (`22` SSH, `80` HTTP, `443` HTTPS, `445` SMB, `3389` RDP, `5985` WinRM).
  - Unauthenticated banner grabbing: SSH daemon identification strings (RFC 4253), HTTP `Server` headers, and SMB1 protocol negotiation to fingerprint OS and software versions without credentials.
  - Concurrent host scanning with 50-thread `ThreadPoolExecutor` for fast subnet sweeps.
  - Best-effort OS identification from banner content and open port combinations.
  - CIDR validation and `/20` (4096 address) safety limit to prevent resource exhaustion.
- **API Endpoint** (`POST /api/discovery/sweep`):
  - Accepts a CIDR range and optional port list; returns discovered hosts with IP, hostname, open ports, service banners, product/version, and OS guess.
  - 32 new backend tests covering banner parsing, OS guessing, host scanning, engine sweep, and API contract.
- **Frontend `DiscoveryView`** (`src/views/DiscoveryView.tsx`):
  - CIDR input form with instant sweep trigger.
  - 3-column KPI summary (Hosts Scanned, Hosts Discovered, Target Subnet).
  - Master-Detail split pane: host table (IP, hostname, OS, ping, open ports) with sticky detail inspector showing service banners, product versions, and raw banner output.
  - Top-level navigation tabs (`🛡️ Scan & Machines` / `🔍 Network Discovery`) in the app header.
- **Fleet Enrollment & Quick Scan Workflow**:
  - Backend `POST /api/discovery/enroll` endpoint to register discovered network hosts directly into the fleet roster (`target_machines` database table).
  - Repository `upsert_target_machine` helper maintaining `sync_status = PENDING_SYNC` for database synchronization.
  - Frontend "➕ Add to Fleet" per-host action and "➕ Enroll All Discovered Hosts (N)" bulk action in [`DiscoveryView`](frontend/src/views/DiscoveryView.tsx).
  - "⚡ Scan" / "⚡ Launch Credentialed Scan" quick-scan buttons on both Discovery and Fleet views that pre-populate target IP/hostname and platform in the Scan form.
  - **Network Discovery Persistence & Tab Caching**: Discovered network sweep results and CIDR inputs are cached across tab switches and browser refreshes in `sessionStorage`.
  - **Automatic Platform Auto-Detection**: Typing or selecting a host in `ScanFormView` automatically infers and selects `Linux (SSH)` vs `Windows (WinRM)` from fleet roster and network banner sweep records with an `⚡ Auto-detected` indicator.
  - **Fast Connection Failure Handlers**: WinRM and SSH collectors perform 2.5s TCP pre-flight reachability checks and 5s operation timeouts so unreachable or blocked hosts fail fast instead of hanging on 30s urllib socket timeouts.
- **RFC 4180 CSV Export Across Key Views** ([`src/lib/csvExport.ts`](frontend/src/lib/csvExport.ts)):
  - **Fleet Overview**: `📥 Export Fleet CSV` button downloading all fleet machine metrics, severity breakdown, and scan status.
  - **Machine CVE Drill-Down**: `📥 Export Findings CSV` button downloading all visible or filtered vulnerabilities, package identifiers, CVSS scores, remediation notes, and reverse dependency blast-radius indicators.
  - **Network Discovery**: `📥 Export Discovery CSV` button downloading discovered network hosts, IP addresses, hostnames, open ports, detected services, and raw banners.
  - Full cell escaping (commas, quotes, line breaks) and timestamped filenames.
- **Multi-Distribution Linux Ecosystem & Remediation Expansion**:
  - **Comprehensive Package Managers**: `LinuxCollector` queries package databases across Debian/Ubuntu/Mint/Pop!_OS (`dpkg`), RHEL/CentOS/AlmaLinux/Rocky/Fedora/Oracle/Amazon (`rpm`), Alpine Linux (`apk`), Arch Linux/Manjaro (`pacman`), and openSUSE/SLES (`zypper`/`rpm`).
  - **Precise Ecosystem Tagging**: Automatically derives exact OSV ecosystems from `/etc/os-release` (`Ubuntu:XX.YY:LTS`, `Debian:XX`, `AlmaLinux:X`, `Rocky Linux:X`, `Alpine:vX.YY`, `Arch Linux`, `Fedora`, `openSUSE`, `Red Hat`, `Wolfi`).
  - **Universal Linux Family Fallback**: 5-tier resolution pipeline in `_resolve_ecosystems` featuring package format family mappings (`deb`, `rpm`, `apk`, `pacman`, `zypper`), release suffix heuristics (`el8/9`, `fc38-40`, `suse`, `arch`, `-rN`), and a universal fallback querying all 10 canonical Linux ecosystems in parallel for 100% vulnerability coverage across untagged, custom, or embedded environments.
  - **Adaptive Distribution Remediation in UI**: Detail inspector dynamically generates native package manager upgrade and purge commands (`apt`, `dnf`, `apk`, `pacman`, `zypper`) tailored to the target host's specific Linux distribution.
- **Agentless SSH Authentication Architecture & Hardened Environment Strategy** ([`docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md`](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md)):
  - Documented enterprise authentication architecture for CIS-hardened environments where password authentication is disabled (`PasswordAuthentication no`).
  - Formalized a 3-phase roadmap: **Phase A** (Per-Scan Private Key & Passphrase in `Credentials`, in-memory `paramiko.PKey` parsing, UI key toggle), **Phase B** (Server-Managed Default Scanner Keyring `CVEDECK_DEFAULT_SSH_KEY_PATH` for 1-click fleet scans), and **Phase C** (Ephemeral Signed SSH Certificates via HashiCorp Vault / Teleport).
  - Documented security considerations: `SecretStr` secret sanitization, zero-disk in-memory parsing, Ed25519/RSA format support, target host least-privilege `~/.ssh/authorized_keys` options, and fault isolation.
  - Added Requirement 9 to `.kiro/specs/cvedeck/requirements.md`.
- **Roadmap & Linux-First Execution Strategy** ([`docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md`](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md)):
  - Established Linux-First operational focus as the primary production scanning workflow (Debian/Ubuntu/RHEL agentless SSH, reverse-dependency graph, OSV tracker, and automated 1-click remediation).
  - Formalized Windows development across three dedicated research tracks: Track 1 (Inbound WinRM, HTTPS 5986, and UAC `LocalAccountTokenFilterPolicy` zero-modification research), Track 2 (Zero-Port Outbound Push Collector `POST /api/scans/ingest`), and Track 3 (Microsoft MSRC API & NIST NVD CPE cumulative Quality Update mapping).
- **Pre-Flight SSH/WinRM Connection & Identity Testing**:
  - **Backend `POST /api/scans/test-connection`** ([`backend/app/api/actions.py`](backend/app/api/actions.py)): Fast 2.5s TCP pre-flight connect checks and 4.0s read-only identity probes (`uname -a`, `os-release`, WMI) returning live latency in ms, connection status (`SUCCESS`, `AUTH_FAILURE`, `CONNECTION_FAILURE`), and detected OS banner.
  - **Frontend "🔌 Test Connection" Pre-Flight Button** ([`frontend/src/views/ScanFormView.tsx`](frontend/src/views/ScanFormView.tsx)): Allows operators to verify host reachability and credentials before launching a full scan, displaying instant inline status badges with round-trip latency and detected OS details.
- **Interactive Package Blast-Radius Explorer & Dependency Inspector** ([`frontend/src/views/MachineDrillDownView.tsx`](frontend/src/views/MachineDrillDownView.tsx)):
  - Dedicated **Dependency Map & Blast Radius Visualizer** (`🌳 Dependency Map` workspace tab) with real-time risk classification (`🚫 High Blast Radius: Required by N installed apps` vs `✓ Standalone Leaf Component: 0 host dependents`).
  - Interactive filter chips (`All Components`, `🚫 High Blast Radius`, `✓ Standalone Leaf Components`) to isolate safe-to-purge packages from critical infrastructure shared libraries.
  - Card-based package tree view displaying dependent applications, required libraries, linked CVEs, and 1-click distro-tailored upgrade or purge commands.
- **Fleet OS & Platform Filtering** ([`frontend/src/views/MachineListView.tsx`](frontend/src/views/MachineListView.tsx)):
  - Interactive platform filter chips (`All`, `🐧 Linux`, `🪟 Windows`) with live fleet host counts in the toolbar.
  - Visual platform chips on table rows for clear fleet segmentation.
- **Linux-First Platform Auto-Detection & Login UX Hardening**:
  - **Port & Banner Precedence** ([`backend/app/scanner/discovery.py`](backend/app/scanner/discovery.py), [`frontend/src/App.tsx`](frontend/src/App.tsx)): Prioritizes Linux distribution banners (`Ubuntu`, `Debian`, `RHEL`, `CentOS`, `AlmaLinux`, `Rocky`, `Alpine`, `Arch`, `Fedora`, `openSUSE`, `OpenSSH`) and port 22 (SSH) over auxiliary file-sharing ports (port 445 / Samba) and web ports, eliminating false-positive Windows classifications on Linux file servers.
  - **Context-Aware Login Forms** ([`frontend/src/views/ScanFormView.tsx`](frontend/src/views/ScanFormView.tsx)): Displays dynamic badges (`⚡ Auto-detected: Linux (SSH)` in green vs `⚡ Auto-detected: Windows (WinRM)` in blue) and dynamically tailored username/password placeholders (`e.g. root, ubuntu, or debian (SSH)` vs `e.g. Administrator or DOMAIN\user (WinRM)`).
- **Scanner Engine Fault Isolation & Timeout Architecture**:
  - **Timeout Separation** ([`backend/app/scanner/collectors.py`](backend/app/scanner/collectors.py)): Separated socket connection timeout (`_CONNECT_TIMEOUT = 5.0s`) from package query execution timeout (`_COMMAND_TIMEOUT = 45.0s`) in `LinuxCollector`, preventing socket timeouts when streaming large package databases (1,000+ packages) over SSH.
  - **Comprehensive Fault Isolation** ([`backend/app/scanner/engine.py`](backend/app/scanner/engine.py)): Enhanced `_scan_target` to isolate all runtime exceptions, recording them cleanly as `CONNECTION_FAILURE` per-target rather than propagating up to the HTTP layer as 500 errors.
  - **Matcher Graceful Degradation** ([`backend/app/scanner/matcher.py`](backend/app/scanner/matcher.py)): Protected upstream advisory querying (`OSV` / `NVD`) with exception isolation to mark data sources as `DATA_SOURCE_UNAVAILABLE` during network glitches without failing the local scan.
- **API Client** (`src/api/client.ts`):
  - `discoverySweep()`, `enrollHosts()`, and `testConnection()` methods with full snake_case → camelCase wire mapping.
- **Types** (`src/types.ts`):
  - Added `DiscoveredService`, `DiscoveredHost`, `DiscoverySweepResult`, `HostEnrollInput`, `TestConnectionInput`, and `TestConnectionResult` interfaces.

---

## [0.2.1] - 2026-08-31

### Performance & UI Scalability Overhaul
- **High-Concurrency OSV Scanner Engine**:
  - Boosted concurrent HTTP advisory fetching workers to 25 (`_DEFAULT_MAX_WORKERS = 25`) with `httpx.Limits(max_keepalive_connections=50, max_connections=100)` connection pooling.
  - Implemented thread-safe in-memory advisory caching (`self._advisory_cache`) across scans to eliminate redundant network round trips for shared/identical packages.
  - Optimized dependency blast-radius mapping with $O(N)$ reverse-dependency lookups.
- **Master-Detail Split Pane & Client-Side Pagination**:
  - Re-architected Machine Drill-Down View into a responsive Master-Detail layout: left-side findings table with right-side live Detail Inspector.
  - Added full client-side pagination (`15 | 25 | 50 | 100` items per page) across all views (By CVE, By Package, Dependency Map) ensuring instant (<5ms) rendering even on machines with 1,000+ findings.
  - Added dedicated top-level **Workspace Tabs** (`🚀 Ready to Fix`, `⏳ Pending Vendor Patch`, `📋 All Findings`, `📦 By Package`, `🌳 Dependency Map`) for fast single-click context switching.
- **Windows NTLM Transport Compatibility**:
  - Configured `WindowsCollector` (`collectors.py`) default session factory with `transport="ntlm"` and `server_cert_validation="ignore"` for native Windows NTLM authentication support.
- **Zero-Touch Network Discovery Roadmap**:
  - Documented Section 8 in [`docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md`](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md) detailing automated subnet discovery (ARP/ICMP/TCP SYN sweeps) and unauthenticated banner/service fingerprinting (SMB, HTTP, SSH) to discover and evaluate network endpoints without requiring manual per-host dial-in.

---

## [0.2.0] - 2026-08-31

### Added
- **Live OSV.dev Vulnerability Matcher (`OsvHttpClient`)**:
  - Implemented `app.scanner.osv_client.OsvHttpClient` satisfying the `OsvClient` protocol.
  - Added high-performance batch querying via `POST /v1/querybatch` to evaluate hundreds of installed packages in bulk.
  - Added concurrent detailed advisory lookups via `POST /v1/query` with connection pooling and thread pooling.
  - Implemented canonical CVE identifier resolution across OSV advisory IDs, aliases, and upstreams (including Ubuntu security advisories e.g. `UBUNTU-CVE-*`).
  - Implemented official CVSS v3.1 specification vector calculation to derive exact numeric base scores from raw vector strings.
  - Added release-specific fixed version extraction (matching target distribution releases, e.g. Ubuntu 24.04 `noble`).
- **Agentless Dependency Scanner & Blast Radius Analysis**:
  - Enhanced [`LinuxCollector`](backend/app/scanner/collectors.py) to extract package dependencies (`dpkg-query -W -f='${Package}\t${Version}\t${Depends}\n'`).
  - Implemented automated reverse-dependency mapping and blast radius risk assessment (`low`, `medium`, `high`) in the backend API to identify which installed applications depend on a given component.
  - Added **Blast Radius** indicators and expandable **Dependency & Impact Drawers** to the Drill-Down view (`MachineDrillDownView.tsx`).
  - Added dedicated **🌳 Dependency Map** view mode to visualize the full component dependency graph before performing selective package upgrades.
- **Interactive CVE Intelligence & Detail Modal (`CveDetailModal`)**:
  - Made all CVE IDs throughout the application clickable (with interactive `↗` links) to open an in-depth slide-out vulnerability drawer.
  - Added direct 1-click upstream advisory links to:
    - 🏛️ **NIST NVD Database** (`https://nvd.nist.gov/vuln/detail/CVE-...`)
    - 🛡️ **Ubuntu Security Tracker** (`https://ubuntu.com/security/CVE-...`)
    - 📦 **Open Source Vulnerability (OSV) Database** (`https://osv.dev/vulnerability/CVE-...`)
    - 🔍 **MITRE CVE Dictionary** (`https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-...`)
  - Added real-time **Removal & Dependency Impact Assessment**:
    - Displays `🚫 DO NOT REMOVE THIS PACKAGE (High Impact)` with full list of active dependent applications (`depended_on_by`) to prevent breaking services.
    - Displays `⚠️ CHECK USAGE BEFORE PURGING (Standalone Component)` for 0-dependency leaf packages.
  - Added integrated remediation status and audit notes updater directly inside the modal.
- **Patch Availability Filtering & Alternative Remediation Guidance**:
  - Added interactive **Patch Readiness Filter Bar** (`All`, `🚀 Ready to Fix`, `⏳ Pending Patch`) to filter findings based on repository update availability.
  - Added **Strategic Remediation Guidance Banner** for vulnerabilities currently awaiting an upstream vendor patch, providing 1-click command copy helpers:
    - *Purge Unused Leaf Packages:* (`sudo apt remove --purge <pkg>`) for standalone packages with 0 dependencies.
    - *Ubuntu Pro (ESM) Extended Security Check:* (`sudo pro status && sudo pro enable esm-apps`) for LTS community/universe backports.
    - *OS Distribution Upgrade Check:* (`sudo do-release-upgrade -c`) for upstream baseline upgrades.
  - Added inline **`[🗑️ Purge: sudo apt purge <pkg>]`** quick actions in both By Package and Dependency Map views for unpatched leaf packages.
- **Vulnerability Matching Precision & Distribution Isolation**:
  - Implemented strict package-name verification in [`_extract_fixed_version`](backend/app/scanner/osv_client.py) to prevent companion packages (e.g. `xorg-server`) from leaking fix versions into target binaries (e.g. `xwayland`).
  - Isolated Ubuntu targets strictly to Canonical's Ubuntu database in OSV to prevent Debian-specific version suffixes (e.g. `+deb12u3`, `+deb13u1`) from appearing on Ubuntu machines.
  - Verified and documented scanning provenance, 3-tier classification, and parsing methodology in [`docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md`](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md).
- **Finding Deduplication & Fix Prioritization**:
  - Upgraded [`osv_client.py`](backend/app/scanner/osv_client.py) to deduplicate multi-record OSV responses per `(cve_id, package_name)`, automatically selecting the record with the actionable fix version to eliminate duplicate finding rows.
- **Remediation & Fix Version Display**:
  - Enhanced package identifiers to include the target fix version (e.g. `deb:curl@8.5.0-2ubuntu10 (fixed in 8.5.0-2ubuntu10.6)`).
  - Updated the frontend drill-down view (`MachineDrillDownView.tsx`) to display the affected package and fix version directly underneath each CVE.
  - Added 1-click `sudo apt install --only-upgrade <package>` command copy helpers.
- **Fixed & Resolved Issues**:
  - Fixed duplicate vulnerability accumulation on re-scan: `Repository.save_findings` now replaces prior findings for the machine so subsequent scans reflect the exact current vulnerability state.
  - Fixed false positive fix reporting for unpatched CVEs: packages without released updates cleanly display `⏳ Pending vendor patch` and hide misleading copy commands.
  - Fixed duplicate records appearing when an advisory contains both unversioned and versioned fixed release ranges for the same package.
- **Dashboard UX Overhaul**:
  - Added interactive KPI summary metric cards (`All Findings`, `Critical`, `High`, `Medium`, `Low`) across Fleet Overview and Drill-Down views for 1-click filtering.
  - Added instant client-side search bars in both Fleet and Drill-Down views.
  - Added "By CVE" vs. "By Package" view toggle to consolidate redundant CVE rows by affected software component.
  - Added modern glassmorphism design system in `index.css` with Inter font, glowing severity badges, and responsive layouts.
- **Runtime Dependencies & Configuration**:
  - Added `httpx==0.28.1` to runtime `backend/requirements.txt` and `backend/pyproject.toml` for containerized deployments.
  - Added `CVEDECK_OSV_API_URL` and `CVEDECK_HTTP_TIMEOUT` deployment environment variables in `backend/app/config.py` and documented them in `DEPLOYMENT.md`.
  - Added comprehensive unit and mocked network tests in `backend/tests/test_osv_client.py`.

---

## [0.1.0] - 2026-08-31

### Initial Release (Spec-First Architecture)

#### 1. Core Domain & Severity Engine
- Defined shared domain enums (`Platform`, `Severity`, `ScanStatus`, `SourceStatus`, `SyncStatus`, `RemediationStatus`).
- Total CVSS v3.x severity band derivation (`0.0-3.9 Low`, `4.0-6.9 Medium`, `7.0-8.9 High`, `9.0-10.0 Critical`).
- In-memory domain models (`TargetMachine`, `Inventory`, `Package`, `OsInfo`, `Credentials`).

#### 2. Agentless Collectors
- **Linux Collector (`paramiko`)**: Connects over SSH; executes read-only queries (`cat /etc/os-release`, `dpkg-query`, `rpm -qa`). Installs nothing on target hosts.
- **Windows Collector (`pywinrm`)**: Connects over WinRM; executes read-only PowerShell (`Get-CimInstance Win32_OperatingSystem`, Registry uninstall keys).
- Transport error mapping: maps network failures to `ConnectionError` and invalid credentials to `AuthError`.

#### 3. Fault-Isolated Scanner Engine
- Per-target fault isolation: connection failure (`CONNECTION_FAILURE`) or auth failure (`AUTH_FAILURE`) on one host never aborts scanning of remaining targets in a batch.
- Persists collected inventory and findings per machine upon successful collection.
- Graceful degradation: handles unavailable/unreachable data sources without crashing.

#### 4. Persistence Layer & Extensible Data Model
- SQLAlchemy ORM schema supporting both SQLite and PostgreSQL.
- Identical schema for `Local_Database` and `Online_Database` to enable synchronization.
- First-class support for `package_identifier` and `dependency_path_id` (`DependencyPath` self-referential hierarchy) to support future dependency chain visualizations without schema migrations.
- Complete repository layer providing thread-safe session transactions, machine listings, severity tally queries, and remediation note storage.

#### 5. Remediation Tracking & Synchronization Services
- **Remediation Service**: Manual-only tracking (`add` / `update` status and free-text notes). No background scheduler or automated triggers.
- **Sync Service**: Reconciles local database state with remote `Online_Database`, marking unpropagated rows as `PENDING_SYNC` and converging when online connectivity is restored.

#### 6. Outward-Facing Backend API (FastAPI)
- `GET /api/machines`: Scanned machine list with severity-grouped CVE tallies.
- `GET /api/machines/{id}`: Machine details (404 on unknown).
- `GET /api/machines/{id}/cves?severity=`: Filterable CVE findings list.
- `GET /api/cves?severity=`: Global CVE list filtered by severity.
- `POST /api/scans`: Manually triggered multi-target batch scan.
- `POST /api/machines/{id}/cves/{cve_id}/remediation`: Add remediation record.
- `PUT /api/remediation/{record_id}`: Update remediation record.
- `POST /api/sync`: Manually trigger database sync (503 if online DB unconfigured).
- `GET /api/health`: Liveness probe.

#### 7. Web Dashboard (React + TypeScript)
- Built with Vite, React 18, and custom CSS design system supporting dark/light mode (`prefers-color-scheme`).
- Views:
  - `ScanFormView`: Target registration and scan trigger with per-target status reporting.
  - `MachineListView`: Host listing with interactive severity counts and severity filters.
  - `MachineDrillDownView`: CVE drill-down with severity badges, CVSS scores, remediation status dropdowns, and note editors.
- Wire key mapper (`client.ts`) bridging backend `snake_case` JSON with frontend `camelCase` TypeScript interfaces.

#### 8. Deployment Infrastructure
- Multi-stage Dockerfile packaging Vite frontend build and FastAPI backend into a single container image.
- Non-root runtime user with volume remapping (`PUID`/`PGID`).
- Docker Compose configuration (`docker-compose.yml`, `.env.example`).
- Systemd installation script and Nginx TLS reverse proxy template (`deploy/`).
