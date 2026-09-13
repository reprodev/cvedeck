# CveDeck

[![CI](https://github.com/reprodev/cvedeck/actions/workflows/ci.yml/badge.svg)](https://github.com/reprodev/cvedeck/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Container](https://img.shields.io/badge/ghcr.io-reprodev%2Fcvedeck-2496ed?logo=docker&logoColor=white)](https://github.com/reprodev/cvedeck/pkgs/container/cvedeck)

An agentless vulnerability management tool. A central server remotely scans
Linux machines for known CVEs, matches collected inventory against
public vulnerability data (OSV.dev for package-level advisories, NVD for
OS-level CVEs and CVSS scoring), enriches every finding with real-world
exploitation intelligence (CISA KEV and FIRST EPSS), stores results in a local
database with sync to an online database, and presents everything on a web
dashboard. It also exposes its own JSON API so other applications can pull the
data.

The point of the enrichment is prioritisation. A fleet of thirty hosts routinely
produces several hundred High and Critical findings, and a list sorted by CVSS
alone gives you no way to find the three that matter this week. CVSS says how bad
a vulnerability would be *if* exploited; KEV says whether it is being exploited
right now; EPSS says how likely that is to start. CveDeck ranks by all three.

All actions are manual to start with (no scheduled scans, no automated
remediation). The data model is structured to support a future
dependency/application-path visualization without restructuring stored data.

## What it does

**Scans without agents.** SSH (`paramiko`) for Linux. Nothing is installed on
the target. SSH takes a password or an Ed25519/ECDSA/RSA key, parsed in memory
and never written to disk. A pre-flight connection test reports reachability,
credentials, and the OS banner before you commit to a scan.

**Windows is not supported yet, and CveDeck says so rather than guessing.**
Windows hosts can be discovered and added to the fleet, and inventory can be
collected over WinRM, but CveDeck cannot yet match Windows software or cumulative
updates against vulnerability data. A Windows scan would therefore finish with
no findings, which looks exactly like a clean host, so Windows scans are refused
with that reason instead. Windows support is on the roadmap — see
[Windows research tracks](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md#9-target-architecture-roadmap-linux-first-execution--windows-research-tracks).

**Ranks by exploitation, not just severity.** Every finding is annotated with
whether CISA lists it as actively exploited (with the federal remediation due
date), and with FIRST's modelled probability of exploitation in the next 30
days plus that probability's percentile. The default order is KEV, then EPSS,
then CVSS. Both feeds are cached locally and joined offline — one download a
day, not one API call per finding.

**Says when it does not know.** An unenriched finding reports as *unknown*, not
as *not exploited*. If the KEV feed has never loaded or has gone stale, the
dashboard says so and the exploitation column shows a dash. `GET /api/feeds`
reports each feed's age, record count, and staleness. Likewise, a scan that ran
while an advisory source was unreachable is reported as partial rather than
clean, and a host enrolled but never scanned says so rather than showing a
failure.

**Covers the distributions people actually run.** Inventory parsing and OSV
matching across Debian, Ubuntu, Raspbian, RHEL, CentOS, AlmaLinux, Rocky,
Oracle, Amazon Linux, Fedora, Alpine, Arch, openSUSE, SLES, Wolfi, and
Chainguard, through a five-tier resolution pipeline. A distribution without its
own OSV tracker resolves onto the upstream it derives from; an unrecognised one
queries every canonical ecosystem rather than guessing at a single answer. The
running kernel and pending-reboot state are collected too, so a fully patched
host still running the kernel it booted from is not reported as clean.

**Tells you what you can actually fix.** Findings are split three ways: those
with a vendor patch available in the target's repository, those awaiting an
upstream build, and those cleared on a re-scan. For the first group it generates
the upgrade command for that machine's own package manager (`apt`, `dnf`, `apk`,
`pacman`, `zypper`), plus a bulk script covering every fixable package
on a host. Commands are generated for you to review — CveDeck never executes
anything on a target.

**Shows what a removal would break.** A dependency explorer distinguishes a
package that eleven applications require from a standalone leaf you can purge
safely, so remediation does not take a service down with it.

**Finds hosts you forgot about.** Subnet sweeps over ICMP, TCP connect, and
unauthenticated SSH/HTTP/SMB banner reads, with one-click enrollment of what
turns up. No credentials are sent during discovery.

**Gets out of the way.** Split-pane drill-down with CVSS gauges and links out to
NVD, the Ubuntu Security Tracker, and OSV.dev; tabbed workspaces; severity and
platform filters; client-side pagination; light, dark, and system themes;
linkable URLs for every screen; and RFC 4180 CSV export for the fleet, a host's
findings, or a discovery sweep. Remediation status and notes are stored locally,
with optional sync to a remote database.

## Architecture

- **Backend (`backend/`)**: Python 3.11+, FastAPI, Pydantic, SQLAlchemy, `paramiko`, `pywinrm`, `httpx`. Scanner engine, live OSV matcher, persistence, remediation + sync services, and the outward-facing API.
- **Frontend (`frontend/`)**: React + TypeScript (Vite). Master-Detail drill-down view, tabbed workspaces, exploitation-first triage summaries, severity filtering, dependency graphs, URL-linkable screens, and a light/dark/system theme.

## Quick start

The whole application ships as one container image that serves the API and the
dashboard on a single port, with the database in a directory you mount. No
checkout needed:

```bash
docker run -d -p 3325:8000 -v /srv/cvedeck:/data ghcr.io/reprodev/cvedeck:latest
```

Then open <http://localhost:3325>.

Or with compose -- save this as `docker-compose.yml` and run `docker compose up -d`:

```yaml
services:
  cvedeck:
    image: ghcr.io/reprodev/cvedeck:latest
    container_name: cvedeck
    restart: unless-stopped
    ports:
      - "3325:8000"
    volumes:
      # The database lives here. Back this directory up.
      - ./data:/data
    environment:
      PUID: "1000"
      PGID: "1000"
      TZ: "UTC"
```

The application has **no authentication of its own**. Do not expose it to the
internet without putting a reverse proxy and access control in front of it --
see DEPLOYMENT.md.

### Try it with demo data

An empty dashboard says very little. To see a populated fleet without enrolling
any hosts:

```bash
docker run -d -p 3325:8000 -e CVEDECK_DEMO_MODE=true ghcr.io/reprodev/cvedeck:latest
```

This seeds a fictional twelve-host fleet -- including a host that has never been
scanned, one whose credentials failed, one scanned while an advisory source was
down, and findings whose exploitation status was never checked -- and **disables
scanning, discovery, and connection tests**. Leave it off on any instance you
actually scan with: a public instance with scanning enabled is an SSH/WinRM
client and port scanner that any visitor can aim at any address, from your IP.

## Running from source

```bash
# Backend -- serves the API on :8000
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                              # optional, but it should pass
uvicorn app.api.app:app --reload

# Frontend -- dev server on :5173, proxies /api to :8000
cd frontend
npm install
npm test                                            # optional
npm run dev
```

See [backend/README.md](backend/README.md) and [AGENTS.md](AGENTS.md) for the
deeper conventions.

## Deployment

A docker-compose.yml and a systemd install script (deploy/) are also provided.
See DEPLOYMENT.md for configuration, backups, PostgreSQL, reverse proxies, and
the security notes -- the application has no authentication of its own, so read
those before exposing it.

## Spec and design

The full requirements, design, and task plan live in
[.kiro/specs/cvedeck/](.kiro/specs/cvedeck/) (requirements.md, design.md,
tasks.md). Start there to understand intended behavior before changing code --
the source and tests carry `Req X.Y` and `Property N` citations pointing back
into those documents, and every acceptance criterion in the spec is cited at the
place that implements it — `scripts/check_spec_citations.py` verifies both
directions.

For details on vulnerability feed ingestion, distribution isolation, and parsing logic,
see [docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md](docs/SCANNING_PROVENANCE_AND_METHODOLOGY.md).

For the narrative of how the project evolved -- the bugs that shaped the
architecture and the reasoning behind each invariant -- see
[docs/DEVELOPMENT_STORY.md](docs/DEVELOPMENT_STORY.md).

The three mockups the current design was chosen from are kept in
[docs/design/](docs/design/), with the reasoning that picked one of them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to set up, test, and submit a
change, and [AGENTS.md](AGENTS.md) for the deeper conventions, invariants, and
guidance for both human and LLM contributors. Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
Note that CveDeck performs **no authentication on any endpoint** by default and
is designed to run behind a reverse proxy or on a trusted network segment.

## Credits

CveDeck was built spec-first with [Kiro](https://kiro.dev), an agentic IDE. The
requirements and design documents under [.kiro/specs/cvedeck/](.kiro/specs/cvedeck/)
were written before the code and kept in step with it, which is why the source
cites them so heavily. [docs/DEVELOPMENT_STORY.md](docs/DEVELOPMENT_STORY.md)
describes how that worked in practice, including the parts that did not.

Vulnerability data comes from [OSV.dev](https://osv.dev),
[NVD](https://nvd.nist.gov), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
and [FIRST EPSS](https://www.first.org/epss/). CveDeck is not affiliated with
any of them.

Typefaces are [Archivo](https://github.com/Omnibus-Type/Archivo) and
[IBM Plex Mono](https://github.com/IBM/plex), both under the SIL Open Font
License — see [frontend/src/fonts/OFL.txt](frontend/src/fonts/OFL.txt).

## License

Copyright (C) 2026 reprodev

[GNU Affero General Public License v3.0](LICENSE).

You can run, modify, and self-host CveDeck freely. The AGPL's network clause
means that if you offer a modified version to others as a hosted service, you
must publish your changes under the same license.
