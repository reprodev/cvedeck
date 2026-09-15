# Deployment

The CveDeck ships as a single container image that serves both the
API and the dashboard on one port, with all state in one mounted directory. A
native systemd installation is also supported for hosts without Docker.

> **Read [Authentication](#authentication) and [Security](#security) before
> exposing this anywhere.** Login is built in and on by default, but the scan
> endpoint accepts credentials for the machines it scans, so use HTTPS for
> anything beyond a trusted network.

## Quick start (Docker)

```bash
docker run -d \
  --name cvedeck \
  -p 3325:8000 \
  -v /srv/cvedeck:/data \
  -e PUID="$(id -u)" -e PGID="$(id -g)" \
  --restart unless-stopped \
  ghcr.io/reprodev/cvedeck:latest
```

The dashboard is then at `http://<host>:3325` and the API at
`http://<host>:3325/api`. The database is written to `/srv/cvedeck/cvedeck.db`
on the host and survives container replacement.

On first start there is no account. The log prints a one-time setup code:

```bash
docker logs cvedeck
```

Open the dashboard, enter the code, and choose a username and password. See
[Authentication](#authentication) for creating the account without the setup
page, and for API tokens.

To build from source instead -- for an architecture that is not published, or
when developing -- run `docker build -t cvedeck:latest .` from a checkout and
use `cvedeck:latest` in place of the `ghcr.io` reference above.

## Quick start (Docker Compose)

```bash
cp .env.example .env   # edit PORT, DATA_DIR, PUID/PGID as needed
docker compose up -d
docker compose logs -f
```

## Configuration

Every setting is an environment variable; all of them are optional.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CVEDECK_DATA_DIR` | `.` (`/data` in the image) | Directory holding the SQLite database. Created if missing. |
| `CVEDECK_DB_URL` | SQLite file inside the data directory | Full SQLAlchemy URL. Set to `postgresql+psycopg://user:pass@host/db` to use PostgreSQL. |
| `CVEDECK_STATIC_DIR` | unset (`/app/static` in the image) | Directory holding the built dashboard. Unset means the API serves no static files. |
| `CVEDECK_ONLINE_DB_URL` | unset | Online database for `POST /api/sync`. Unset means sync reports HTTP 503. |
| `CVEDECK_SSH_PORT` | `22` | Port the Linux collector and the connection test dial. |
| `CVEDECK_SCAN_HISTORY_LIMIT` | `50` | Scan runs kept per machine, with what each one found new and resolved. Older runs are pruned when a new one is recorded; a machine's latest successful run is always kept. At least 1. |
| `CVEDECK_SSH_HOST_KEY_POLICY` | `tofu` | What to do with a host whose SSH key is not pinned yet. `tofu` pins the key it presents on the first successful connection; `strict` refuses it. A host that presents a different key from its pinned one is refused under both. Any other value is an error. |
| `CVEDECK_WINRM_PORT` | `5985` | Port the Windows collector dials (`5986` for HTTPS). Windows scans are refused in this release — see the note under Security. |
| `CVEDECK_OSV_API_URL` | `https://api.osv.dev/v1` | Base URL for the OSV.dev REST API. |
| `CVEDECK_HTTP_TIMEOUT` | `15.0` | Timeout in seconds for vulnerability source HTTP requests. |
| `CVEDECK_KEV_FEED_URL` | CISA KEV catalogue JSON | Source for the Known Exploited Vulnerabilities catalogue. |
| `CVEDECK_EPSS_FEED_URL` | FIRST EPSS current scores (`.csv.gz`) | Source for the EPSS exploitation-probability score set. |
| `CVEDECK_FEED_TIMEOUT` | `120.0` | Timeout in seconds for a whole-feed download. Separate from `CVEDECK_HTTP_TIMEOUT` because the EPSS set is a multi-megabyte file, not a per-package query. |
| `CVEDECK_FEED_MAX_AGE_HOURS` | `48.0` | How old a cached feed may be before the dashboard reports it stale. Both feeds publish daily, so the default tolerates one missed publication. |
| `CVEDECK_NVD_ENABLED` | `false` | Enable OS-level CVE matching against NVD. Off by default: NVD's rate limits make an unkeyed fleet scan slow, and the package-level OSV path already covers most Linux exposure. |
| `CVEDECK_NVD_API_KEY` | _(unset)_ | NVD API key. Raises the request limit from 5 to 50 per 30 seconds. Free from `nvd.nist.gov/developers/request-an-api-key`. Strongly recommended if `CVEDECK_NVD_ENABLED` is on. |
| `CVEDECK_NVD_API_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Base URL for the NVD 2.0 CVE API. |
| `CVEDECK_DEFAULT_SSH_KEY_PATH` | _(unset)_ | Path to a server-managed SSH private key. When set, a Linux scan target may omit credentials entirely and authenticate with this key -- this is what enables a fleet re-scan without retyping credentials per host. Re-read on every scan, so rotating the file takes effect without a restart. |
| `CVEDECK_DEFAULT_SSH_KEY_PASSPHRASE` | _(unset)_ | Passphrase for the above key, if it is encrypted. |
| `CVEDECK_DEFAULT_SSH_USER` | _(unset)_ | Username paired with the server-managed key when a target supplies none. |
| `CVEDECK_DEMO_MODE` | `false` | Run as a public demo: seed a fictional fleet into an empty database and **refuse** scans, discovery sweeps, and connection tests. See "Demo mode" below. Leave off on any instance you actually scan with. |
| `CVEDECK_CORS_ORIGINS` | unset | Comma-separated origins. Only needed if the dashboard is served from a different host than the API. |
| `CVEDECK_AUTH` | `enabled` | Set to `disabled` to serve the dashboard and API without login, for an instance already behind an authenticating proxy. Any other value, including a typo, leaves login on. A warning is logged on every start while it is off. |
| `CVEDECK_ADMIN_USERNAME` | unset | With a password, creates this account on start-up if none exists. Never changes an existing account. |
| `CVEDECK_ADMIN_PASSWORD` | unset | Password for the account above, at least 12 characters. |
| `CVEDECK_ADMIN_PASSWORD_FILE` | unset | Read the password from this file instead, for Docker secrets. Takes precedence over `CVEDECK_ADMIN_PASSWORD`. |
| `CVEDECK_COOKIE_SECURE` | `auto` | Mark the session cookie `Secure`: `auto` does so when the request arrived over HTTPS, `true` always, `false` never. Set `true` behind a TLS proxy that uvicorn does not trust for `X-Forwarded-Proto`. |

Container-only extras: `PUID` / `PGID` (default `1000`) set the ownership of
files written to the data volume, and `TZ` sets the timezone.

## Data and backups

Everything persistent lives in one file: `<data dir>/cvedeck.db`. The schema
is created automatically on first start, so a fresh empty directory is a valid
starting state — there is no migration step to run.

To back up, stop the container and copy the file:

```bash
docker compose stop
cp /srv/cvedeck/cvedeck.db /backups/cvedeck-$(date +%F).db
docker compose start
```

To upgrade to a newer release, pull and recreate:

```bash
docker compose pull
docker compose up -d
```

`docker compose pull` is the part that matters. Without it, compose reuses the
image already on the host and silently keeps running the old version -- the
database is migrated forward on start, so nothing errors and the only symptom is
that the release you expected is not the one running. Check with
`curl localhost:3325/api/health`, which reports the running version.

If you are running a source build (`build: .` uncommented in
`docker-compose.yml`), rebuild explicitly instead:

```bash
docker compose up -d --build
```

The data directory is untouched either way.

## PostgreSQL

The image includes the `psycopg` driver, so switching stores needs no rebuild:

```bash
-e CVEDECK_DB_URL=postgresql+psycopg://cve:secret@db.internal/cvedeck
```

Tables are created on first start as with SQLite. This is also the prerequisite
for running more than one uvicorn worker — see [Scaling](#scaling).

## Native Linux install (systemd)

For hosts without Docker. Requires Python 3.11+ with `venv`, plus Node and npm
to build the dashboard.

```bash
git clone https://github.com/reprodev/cvedeck.git && cd cvedeck
sudo ./deploy/install.sh
```

This creates a `cvedeck` system user, installs the application to
`/opt/cvedeck`, the database to `/var/lib/cvedeck`, and configuration to
`/etc/cvedeck/cvedeck.env`, then enables the service. It binds to
`127.0.0.1:8000` only — put a TLS reverse proxy in front of it using
[`deploy/nginx/cvedeck.conf.example`](deploy/nginx/cvedeck.conf.example).

```bash
systemctl status cvedeck
journalctl -u cvedeck -f
```

The first start logs a setup code for creating the account:

```bash
journalctl -u cvedeck | grep -A4 'no account yet'
```

Re-running `install.sh` upgrades in place and leaves the database and
environment file alone.

## Keeping threat intel fresh

Findings are enriched with two public datasets: the **CISA Known Exploited
Vulnerabilities** catalogue (is this being exploited in the wild right now?) and
the **FIRST EPSS** score set (how likely is it to be, in the next 30 days?).
Together with CVSS these are what let the dashboard rank a fleet's findings by
real-world urgency instead of by theoretical severity alone.

Unlike OSV, these are not queried per package during a scan. Both are small
complete files published daily, so they are downloaded whole and cached locally,
then joined offline. Enrichment therefore adds no network dependency to a scan.

### Refreshing

There is no scheduler in the application yet, so the refresh is triggered
externally. The API requires a login, so a script uses an API token (create one
under **Settings** in the dashboard):

```bash
curl -fsS -X POST -H "Authorization: Bearer $CVEDECK_TOKEN" \
  http://localhost:3325/api/feeds/refresh
```

```json
{"ok": true,
 "results": [{"feed_name": "kev",  "status": "ok", "record_count": 1687},
             {"feed_name": "epss", "status": "ok", "record_count": 366848}]}
```

The two feeds refresh independently, so an outage at one upstream does not cost
the other's update — `ok` is `false` if either failed, with the reason in
`error_detail`.

**Daily is enough**, because that is how often both upstreams publish.

The systemd installer (`deploy/install.sh`) sets this up for you as
`cvedeck-feeds.timer`, which runs at 03:00 with a 30-minute randomised
delay and `Persistent=true` so a machine that was asleep still catches up. It
runs `cvedeck-admin refresh-feeds` on the host, against the database directly,
so it needs no token:

```bash
systemctl list-timers cvedeck-feeds.timer     # when it next runs
systemctl start cvedeck-feeds.service         # refresh right now
journalctl -u cvedeck-feeds.service           # why a refresh failed
```

For Docker, add a cron entry on the host. Either run the same command inside the
container, which needs no token:

```cron
17 3 * * * docker exec --user 1000:1000 cvedeck cvedeck-admin refresh-feeds >/dev/null
```

or call the API with a token kept in a file only root can read:

```cron
17 3 * * * curl -fsS -X POST -H "Authorization: Bearer $(cat /root/.cvedeck-token)" http://localhost:3325/api/feeds/refresh >/dev/null
```

### Checking cache health

```bash
curl -fsS -H "Authorization: Bearer $CVEDECK_TOKEN" http://localhost:3325/api/feeds
```

Each feed reports `last_refreshed_at`, `record_count`, `stale`, and `usable`.
`last_refreshed_at` advances **only on success**, so a feed that has been failing
for a week reports week-old data rather than a fresh-looking timestamp from its
last retry. The dashboard raises a banner whenever any feed is stale or unusable.

### What happens when a refresh fails

Two behaviours matter here, and both are deliberate:

**A failed refresh never empties a good cache.** The previous catalogue is left
in place, because yesterday's answer beats no answer. An empty catalogue
returned with HTTP 200 is also treated as a failure rather than written — a feed
that changed shape upstream must not be able to erase every exploitation flag in
your fleet.

**An unenriched finding reports as _unknown_, never as _not exploited_.** If the
KEV feed has never loaded, findings carry `kev_listed: null` and the dashboard
shows a muted `— unknown` rather than a reassuring "Not on KEV". A blank
exploitation column is **not** a clean bill of health; check `GET /api/feeds`
before reading it as one. This is the same reasoning as `last_scan_sources_ok`
for scan sources — a missing answer must never be presentable as a good one.

### Air-gapped or mirrored deployments

Point the feed URLs at an internal mirror:

```bash
CVEDECK_KEV_FEED_URL=https://mirror.internal/known_exploited_vulnerabilities.json
CVEDECK_EPSS_FEED_URL=https://mirror.internal/epss_scores-current.csv.gz
```

The KEV client accepts CISA's JSON verbatim; the EPSS client accepts the CSV
either gzipped or plain, sniffing the magic bytes rather than trusting a
`Content-Encoding` header.

---

## Authentication

Login is built in and required by default. There is one account, with a
password, and any number of API tokens for scripts.

### First run

With no account, CveDeck prints a one-time setup code to its log at start-up:

```text
WARNING [app.api.dependencies] CveDeck has no account yet.
WARNING [app.api.dependencies] Open the dashboard and enter this setup code to create one:
WARNING [app.api.dependencies]     TFMA-FS53-U7RC
```

The dashboard shows a **Create your account** page that asks for it. The code
works once, for 24 hours or until the next restart, which prints a new one.
There is no default password: whoever reaches a new instance first cannot claim
it without also being able to read its logs.

Upgrading from 0.6.0 or earlier follows the same path. The fleet, findings and
remediation notes are untouched; the first start after upgrading prints a setup
code.

### Creating the account without the setup page

Set both of these, and the account is created on start-up if none exists:

```bash
-e CVEDECK_ADMIN_USERNAME=admin \
-e CVEDECK_ADMIN_PASSWORD_FILE=/run/secrets/cvedeck_admin_password
```

`CVEDECK_ADMIN_PASSWORD` works too, but puts the password in your compose file
and in `docker inspect`. Neither variable ever changes an existing account, so
leaving them set does not undo a password changed later in the dashboard.

### Passwords and sessions

- Passwords need at least 12 characters, with no other rules. They are stored as
  salted scrypt hashes.
- Signing in sets an `HttpOnly`, `SameSite=Strict` cookie. A session ends after
  7 days unused, or 30 days after sign-in, whichever comes first.
- Changing the password in **Settings** signs out every other browser.
- After 5 failed attempts from one address for one username, further attempts
  are refused for 30 seconds, doubling up to 15 minutes. The count is kept in
  memory, so a restart clears it.

### API tokens

Create tokens under **Settings** in the dashboard. A token is shown once, when it
is created; CveDeck keeps only a hash. Send it as a bearer token:

```bash
curl -H "Authorization: Bearer cvd_..." http://localhost:3325/api/machines
```

A token can do anything the account can, except change the password or manage
tokens. Revoke one in **Settings** and it stops working immediately.

### Locked out

Reset the password from the host. Run it as the user that owns the data
directory, so SQLite does not leave a root-owned file behind:

```bash
docker exec -it --user 1000:1000 cvedeck cvedeck-admin reset-password
```

It prompts for the new password (or reads it from stdin with
`--password-stdin`) and signs out every session. For a native install, run
`/opt/cvedeck/venv/bin/cvedeck-admin reset-password` as the `cvedeck` user with
`/etc/cvedeck/cvedeck.env` loaded.

### Turning login off

If CveDeck already sits behind something that authenticates people -- Authelia,
Authentik, oauth2-proxy, a VPN you trust -- you can switch the built-in login
off with `CVEDECK_AUTH=disabled`. Everything is then open to anyone who can
reach the port, and the log says so on every start. Only `disabled`, `off`,
`false`, `no` or `0` turn it off; anything else leaves login on.

Demo mode (`CVEDECK_DEMO_MODE=true`) never asks for a login.

### Behind a reverse proxy

- Pass the original `Host` header through (`proxy_set_header Host $host;` in
  nginx). Requests that change something must come from the dashboard's own
  origin, and that check compares the browser's `Origin` with `Host`.
- For the `Secure` cookie flag and accurate client addresses in the throttle and
  logs, uvicorn has to trust the proxy's `X-Forwarded-*` headers. It trusts
  `127.0.0.1` by default, which covers the systemd install with nginx on the same
  host. For a proxy in another container, set `FORWARDED_ALLOW_IPS` to its
  address, or set `CVEDECK_COOKIE_SECURE=true`.

## Reverse proxies

If you front the application with nginx, Traefik, or Caddy, **raise the read
timeout to several minutes**. `POST /api/scans` is synchronous: it connects to
every requested target over SSH or WinRM inline and only responds once the whole
batch finishes. Nginx's 60-second default will cut off any multi-host scan. The
example config sets `proxy_read_timeout 900s`.

## SSH key authentication

Scans authenticate with either a password or an SSH private key
(Ed25519/ECDSA/RSA, PEM or OpenSSH format). Keys supplied per request are parsed
in memory and never written to disk.

For unattended fleet scanning, mount a dedicated key and point the service at it:

```bash
docker run -d   -v /srv/cvedeck/keys:/keys:ro   -e CVEDECK_DEFAULT_SSH_KEY_PATH=/keys/scanner_ed25519   -e CVEDECK_DEFAULT_SSH_USER=cvedeck   ...
```

Give that key its own unprivileged account on each target. The collector only
issues read commands, so it needs no sudo and no write access anywhere. A
`command=` restriction or `ForceCommand` in `authorized_keys` is a reasonable
extra containment step, but note the collector runs a small set of shell
pipelines rather than a single fixed command.

Windows targets have no equivalent fallback: WinRM has no SSH-key analogue, so a
Windows target without credentials is rejected rather than attempted.

## Demo mode

`CVEDECK_DEMO_MODE=true` turns an instance into a showcase:

```bash
docker run -d -p 3325:8000 -e CVEDECK_DEMO_MODE=true ghcr.io/reprodev/cvedeck:latest
```

It does two things.

**It seeds a fictional twelve-host fleet** into an empty database, covering the
states worth seeing: a host that has never been scanned, one whose credentials
failed, one that could not be reached, one scanned while an advisory source was
down, a host last scanned a month ago, findings CISA lists as actively
exploited, and findings whose exploitation status was never checked and so
report as unknown. Seeding is guarded on an empty fleet, so restarting the
container does not duplicate it and enabling the flag against a database with
real results in it does nothing.

**It refuses every route that reaches the network** -- `POST /api/scans`,
`POST /api/discovery/sweep`, and `POST /api/scans/test-connection` all return
403. This is the more important half. Those routes take a hostname or a CIDR
plus credentials and connect to them, so a public instance with them enabled is
an SSH/WinRM client and port scanner that any visitor can aim at any address,
with the traffic originating from your server rather than theirs.

The dashboard shows a banner while demo mode is on, and
`GET /api/health` reports it under `capabilities.demo_mode`.

**It needs no login.** A demo is meant to be clicked around by strangers, and
the routes that could do harm are already refused.

## Security

Login is required by default (see [Authentication](#authentication)). Every API
route except the health check and the sign-in routes refuses a request without a
session or an API token, and the API documentation at `/api/docs` is behind
sign-in too. `GET /api/health` stays public for container health checks and
proxies, and reports only status, version, demo mode and whether login is
required until you sign in.

There is a single account, and everyone signed in can do everything: scan,
sweep a subnet, edit remediation notes, and manage tokens.

`POST /api/scans` accepts the username and password for each target machine in
the request body. Those credentials are held in memory for the duration of the
request and are never written to the database or the logs, but they do travel
over the wire to this service.

Therefore:

- Prefer not to publish the port to the internet at all. If you do, put a TLS
  reverse proxy in front: over plain HTTP, the password, the session cookie and
  target credentials all cross the network readable.
- If you set `CVEDECK_AUTH=disabled`, the login protection above no longer
  applies. Only do that behind something that authenticates people.
- Use TLS end to end if scan requests cross any untrusted network — otherwise
  target credentials are sent in plaintext.
- Give the scanner accounts the least privilege that still allows reading
  package inventory. The collectors only run read-only commands (`cat
  /etc/os-release`, `dpkg-query`/`rpm -qa`, `Get-CimInstance`, and a registry
  read), and install nothing on the target.
- SSH host keys are pinned on the first successful connection to each host, and
  a host that later presents a different key is refused before any credential
  is sent. The machine's page shows the pinned fingerprint and a **Forget host
  key** action for a host you have rebuilt. The first connection is still trust
  on first use; check the fingerprint against the host, or set
  `CVEDECK_SSH_HOST_KEY_POLICY=strict` to refuse hosts that have no pin.
- **Windows scans are refused.** `POST /api/scans` returns 422 for any batch
  containing a Windows target, because collected Windows inventory cannot yet be
  matched against vulnerability data and a scan would report the host as clean
  without having checked it. The WinRM settings below apply once Windows matching
  exists; prefer HTTPS then (`CVEDECK_WINRM_SCHEME=https`,
  `CVEDECK_WINRM_PORT=5986`), since the default transport on 5985 is unencrypted
  at the transport layer.

Outbound access the scanner needs: TCP 22 to Linux targets.

## Scaling

The image runs a single uvicorn worker on purpose. The SQLAlchemy engine is a
process-wide singleton and SQLite permits only one writer, so additional workers
would contend on the database. To scale, move to PostgreSQL with
`CVEDECK_DB_URL` first, then raise `--workers`.

Because scans run inline within the request, a scan of many hosts occupies a
worker thread for its full duration. Prefer several smaller batches over one
very large one.

## Known limitations

- **NVD matching is opt-in and off by default.** Package-level matching via
  OSV.dev is fully operational and always on. OS-level matching against NIST NVD
  is implemented but gated behind `CVEDECK_NVD_ENABLED` because NVD's rate
  limits (5 requests per 30 seconds without a key) make an unkeyed fleet scan
  slow. Set `CVEDECK_NVD_API_KEY` before enabling it.
- **Threat-intel feeds are refreshed manually.** `POST /api/feeds/refresh` pulls
  the CISA KEV catalogue and the FIRST EPSS score set into a local cache; there
  is no scheduler yet, so run it on a cron (daily is sufficient -- both publish
  daily). `GET /api/feeds` reports each feed's age and whether it is stale, and
  the dashboard shows a banner when enrichment is degraded.
- **Enrichment applies at scan time, not retroactively.** Refreshing the feeds
  updates the cache; findings pick up the new signals on their next scan.
- **An unenriched finding is reported as unknown, never as safe.** If the KEV
  feed has never loaded, findings carry `kev_listed: null` rather than `false`,
  and the UI renders that as "unknown". Do not read a blank exploitation column
  as a clean bill of health -- check `GET /api/feeds` first.
- **`POST /api/sync` requires `CVEDECK_ONLINE_DB_URL`.** Without it the
  endpoint returns HTTP 503.
- **No scheduled scanning.** Every scan and every remediation update is manual
  and API-driven, by design.
- **Fixes are judged per distribution release.** A finding counts as fixable only
  when the host's own release ships the fix. When only a newer release does
  (Debian 14 for a Debian 13 host), the dashboard labels it "Fixed only in
  Debian 14" and the fix plan leaves it out: upgrading packages cannot clear it.
  Fedora, Amazon Linux and SUSE have no per-release data in OSV, so fixes for them
  are shown as "upstream fix, unconfirmed". An end-of-life release that OSV no
  longer tracks (an old Ubuntu interim) may return no findings at all -- upgrade
  to a supported release.
- **One account, no roles.** Anyone signed in, and any API token, can do
  everything except manage the account. Multiple users and read-only tokens are
  not implemented.
- **Upgrades migrate automatically.** The schema is brought to head on first
  engine use. A database created by v0.3.0 or earlier (tables, but no
  `alembic_version`) is adopted at the baseline revision and migrated forward on
  the first start after upgrading, so no manual step is needed. **Back up your
  database before upgrading** anyway -- see "Data and backups" above. To inspect
  or drive migrations by hand, run `alembic current` / `alembic upgrade head`
  from `backend/`; the URL is resolved from the same environment the app reads.

## Verifying a deployment

```bash
# Health
curl -fsS http://localhost:3325/api/health

# Dashboard is being served
curl -fsS http://localhost:3325/ | grep -q 'id="root"' && echo "dashboard ok"

# The API refuses anonymous requests...
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3325/api/machines
# -> 401

# ...and answers with a token created under Settings
export CVEDECK_TOKEN=cvd_...
curl -fsS -H "Authorization: Bearer $CVEDECK_TOKEN" http://localhost:3325/api/machines

# Scans reach the engine (an unreachable host is recorded, not an error)
curl -fsS -X POST http://localhost:3325/api/scans \
  -H "Authorization: Bearer $CVEDECK_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"targets":[{"id":"m1","hostname":"192.0.2.1","platform":"linux",
       "username":"scanner","password":"unused"}]}'
# -> 200 with {"machine_scans":[{"machine_id":"m1","status":"connection_failure",...}]}
```

After that last call, `GET /api/machines` lists `m1` — confirming the scan path
persisted to the mounted database.

```bash
# Threat-intel caches are populated and fresh
curl -fsS -H "Authorization: Bearer $CVEDECK_TOKEN" http://localhost:3325/api/feeds
# -> [{"feed_name":"kev","status":"ok","usable":true,"stale":false,...},
#     {"feed_name":"epss","status":"ok","usable":true,"stale":false,...}]
```

On a brand-new deployment both feeds report `never_refreshed` with
`usable: false` until the first refresh runs. That is expected, and it is why
findings show exploitation status as unknown rather than as "not exploited" —
a zero in the fleet's "Actively Exploited" card means nothing until `usable` is
`true`.
