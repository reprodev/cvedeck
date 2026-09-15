# Contributing to CveDeck

Thanks for considering a contribution. CveDeck is an agentless vulnerability
scanner that people point at their whole fleet with SSH access, so the bar for
changes is a little higher than for a typical side project — a bug here can
either expose a host or, worse, quietly tell someone they are safe when they are
not.

This document covers what you need to know to make a change that will be merged.
`AGENTS.md` is the deeper reference; this is the short version.

---

## Getting set up

```bash
# Backend (Python 3.11+)
cd backend
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"        # or: pip install -r requirements-dev.txt
pytest

# Frontend (Node 22+)
cd frontend
npm install
npm test
npm run typecheck
```

### Enable the hooks

```bash
git config core.hooksPath .githooks
```

Do this once per clone. `core.hooksPath` is local configuration, so it does not
travel with the repository and a fresh clone has the hooks **off**.

They refuse to commit a file that looks like a credential — an `.env`, a
database, a key or certificate, a private key block, or a provider token — and
refuse to push a branch whose tests are red or whose version strings disagree.
This is the mechanical half of the rule in `AGENTS.md` §6; the hooks exist
because asking politely does not scale, and because a secret that reaches a
public history cannot be recalled.

If a hook refuses something legitimate, that is a bug in the hook worth
reporting — a guard with false positives is a guard people switch off. Prefer
fixing the pattern over `--no-verify`, which skips every check including the
secret scan.

Run the whole thing:

```bash
docker compose up -d --build     # dashboard on http://localhost:3325
```

`--build` matters here: `docker-compose.yml` pulls the published image by
default, so without it you would be testing the last release rather than your
checkout. (Uncommenting `build: .` in that file has the same effect
permanently.)

The first local start prints a setup code to the terminal, and the dashboard
asks for it. To skip that in development, start the backend with
`CVEDECK_ADMIN_USERNAME` and `CVEDECK_ADMIN_PASSWORD` set, or with
`CVEDECK_AUTH=disabled`.

To see a populated dashboard without enrolling any hosts, run the backend with
`CVEDECK_DEMO_MODE=true`. It seeds a fictional fleet, disables scanning and
needs no login -- see DEPLOYMENT.md "Demo mode".

Or run the two halves separately — the Vite dev server proxies `/api` to
`localhost:8000`:

```bash
cd backend  && uvicorn app.api.app:app --reload
cd frontend && npm run dev
```

---

## The one rule that matters most

**Never let a missing answer look like a good answer.**

This is the single most important property of a vulnerability scanner and most of
the non-obvious code in this repo exists to protect it. A scanner that reports
"no findings" because a data source was unreachable is worse than one that
crashes, because the user acts on it.

Concretely, in this codebase:

- An unreachable data source is recorded as `DATA_SOURCE_UNAVAILABLE`, and the
  machine's `last_scan_sources_ok` goes false. It is never silently skipped.
- `kev_listed = null` means "not checked". `kev_listed = false` means "checked,
  and genuinely not in CISA's catalogue". **These are never collapsed** — not in
  the database, not in the API, not in the UI. A stale feed must not render as
  "nothing here is being exploited".
- A failed feed refresh leaves the previous cache in place. Overwriting a good
  KEV catalogue with an empty one would erase every exploitation flag in a fleet.
- `Matcher.match` re-raises `NameError` / `TypeError` / `AttributeError` /
  `ImportError` instead of reporting them as an outage. Do not widen those
  handlers back to a bare `except Exception`: a defect reported as an outage
  produces a zero-finding scan behind a green success badge. This happened once
  already — see CHANGELOG 0.3.1.

If your change makes one of these distinctions harder to see, it will be asked
about in review.

---

## Other invariants

`AGENTS.md` §3 is the full list. The ones contributors trip over most:

**Collectors are read-only.** They may issue inventory-read commands only —
`os-release`, package queries, kernel and reboot probes, `Get-CimInstance`,
registry reads. Never an install, remove, or write. The test
`test_linux_ssh_issued_commands_are_read_only` treats *any* `>` other than
`2>/dev/null` as a write; capture output into a shell variable instead of
redirecting. Do not loosen that guard to make a command pass.

**Keys never touch disk.** `Credentials` carries exactly one of `password` or
`private_key`, both `SecretStr`. Keys are parsed in memory via
`parse_private_key`, before a client is allocated, so a bad key is reported as a
key problem rather than a connection failure.

**Routes are protected by default.** Login is enforced on whole routers, so a
new route needs no auth code. Making a route public is a security change: it
goes on the allowlist in `tests/test_auth_enforcement.py`, in the spec and in
DEPLOYMENT.md, and it will be asked about in review.

**Per-target fault isolation.** A `ConnectionError` becomes
`CONNECTION_FAILURE`, an `AuthError` becomes `AUTH_FAILURE`, a refused SSH host
key becomes `HOST_KEY_MISMATCH` or `HOST_KEY_UNKNOWN`, and none of them ever
aborts the batch or produces an HTTP 500. One unreachable host must not cost you
the other thirty.

**Layers stay separate.** ORM models (`app/data/schema.py`), Pydantic domain
models (`app/models.py`), and API schemas (`app/api/schemas.py`) are three
distinct things. Map between them; do not collapse them.

**Config goes through `app/config.py`.** Nothing else reads `os.environ`, so
every knob a deployment can turn is discoverable in one place — and every new one
gets a row in `DEPLOYMENT.md`.

**Enum string values are persisted.** Changing one is a data migration, not a
rename.

---

## Tests

Every behaviour change needs a test. The split is deliberate:

- **Pure/logic layers** get property-based tests — Hypothesis on the backend,
  fast-check on the frontend, minimum 100 iterations.
- **I/O layers** (SSH/WinRM, API contracts, UI) get example and integration
  tests.

**API tests sign in explicitly.** Build the app with
`override_auth(create_app())` from `tests/auth_helpers.py`. Don't disable login
for the whole suite: `tests/test_auth_enforcement.py` relies on the real gate,
and a new route that answers without signing in will fail it -- which is the
point.

**Never make a live network call in a test.** Feed clients and API clients are
tested against recorded fixture payloads with a mocked transport
(`httpx.MockTransport`). A suite that depends on CISA being up is a suite that
fails on a plane.

Schema changes need an Alembic revision *and* a migration test. Check the current
head with `alembic heads` rather than guessing from filenames — the date prefixes
do not always match the revision chain, which has caught people out.

---

## Making a change

1. Open an issue first for anything substantial. A short discussion beats a
   rejected PR.
2. Branch off `main`.
3. Make the change, with tests.
4. Run everything:
   ```bash
   cd backend  && pytest
   cd frontend && npm test && npm run typecheck
   ```
5. Update `CHANGELOG.md` under an `## [Unreleased]` heading.
6. Update `DEPLOYMENT.md` if you added a config knob, and `AGENTS.md` §3 if you
   added or changed an invariant.
7. Open the PR. Describe what changes for a *user*, not only what changed in the
   code.

### Commit messages

Conventional Commits — `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`,
with an optional scope: `fix(scanner): ...`.

### Code style

Match the surrounding code. The comment style in this repo is worth matching
specifically: comments explain *why* a thing is the way it is, especially when
the obvious alternative is wrong. Several modules would be re-broken within a
month without them.

---

## Code of Conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). Reports go to the address named there.

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under **AGPL-3.0**, the same as the project. By
opening a pull request you agree to license your contribution under those terms.
