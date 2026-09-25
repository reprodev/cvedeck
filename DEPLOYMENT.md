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
  --security-opt no-new-privileges:true \
  --restart unless-stopped \
  ghcr.io/reprodev/cvedeck:latest
```

`-p 3325:8000` listens on every interface, and Docker's port publishing
bypasses host firewalls such as ufw. Use `-p 127.0.0.1:3325:8000` when a
reverse proxy on the same host is the only way in. The compose file does the
same with `BIND_ADDR`, and also drops every capability the container does not
need -- see `docker-compose.yml`.

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

### Verifying the image

Every release image carries a signed build-provenance attestation, made by the
release workflow in `github.com/reprodev/cvedeck` from the tagged commit.
Check it before you run a new version:

```bash
gh attestation verify oci://ghcr.io/reprodev/cvedeck:0.8.14 --owner reprodev
```

A pass means the image was built by this repository's release workflow and
has not changed since. The image also carries an SBOM and BuildKit provenance,
readable with `docker buildx imagetools inspect ghcr.io/reprodev/cvedeck:0.8.14
--format '{{ json .SBOM }}'`. The release is refused if the image has a critical
vulnerability that has a published fix.

To run exactly the image you verified, pin it by digest rather than by tag -- a
tag can be moved, a digest cannot:

```bash
docker buildx imagetools inspect ghcr.io/reprodev/cvedeck:0.8.14   # prints the digest
# then use ghcr.io/reprodev/cvedeck@sha256:<digest> in `docker run` or compose
```

Images from 0.8.13 and earlier carry no attestation.

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
| `CVEDECK_WINRM_PORT` | `5985` | Port the Windows collector and the connection test dial (`5986` for HTTPS). Windows scans are refused in this release, and a Windows connection test currently fails before connecting — see the note under Security. |
| `CVEDECK_WINRM_SCHEME` | `http` | Transport for the WinRM endpoint: `http` or `https`. Any other value is an error. Will apply to the connection test and to scans once WinRM works (see Security). The default sends the NTLM exchange unencrypted. |
| `CVEDECK_OSV_API_URL` | `https://api.osv.dev/v1` | Base URL for the OSV.dev REST API. |
| `CVEDECK_HTTP_TIMEOUT` | `15.0` | Timeout in seconds for vulnerability source HTTP requests. |
| `CVEDECK_KEV_FEED_URL` | CISA KEV catalogue JSON | Source for the Known Exploited Vulnerabilities catalogue. |
| `CVEDECK_EPSS_FEED_URL` | FIRST EPSS current scores (`.csv.gz`) | Source for the EPSS exploitation-probability score set. |
| `CVEDECK_FEED_TIMEOUT` | `120.0` | Timeout in seconds for a whole-feed download. Separate from `CVEDECK_HTTP_TIMEOUT` because the EPSS set is a multi-megabyte file, not a per-package query. |
| `CVEDECK_FEED_REFRESH_HOURS` | `24.0` | How often the application refreshes the intel feeds itself, starting at startup. `0` switches the built-in refresh off, for a deployment that drives it from its own scheduler. Each refresh also reapplies the feeds to findings already stored. Demo mode forces this to `0`. Reported at `GET /api/health`, which reports the interval actually running. |
| `CVEDECK_FEED_MAX_AGE_HOURS` | `48.0` | How old a cached feed may be before the dashboard reports it stale. Both feeds publish daily, so the default tolerates one missed publication. |
| `CVEDECK_NVD_ENABLED` | `false` | Enable OS-level CVE matching against NVD. Off by default: NVD's rate limits make an unkeyed fleet scan slow, and the package-level OSV path already covers most Linux exposure. |
| `CVEDECK_NVD_API_KEY` | _(unset)_ | NVD API key. Raises the request limit from 5 to 50 per 30 seconds. Free from `nvd.nist.gov/developers/request-an-api-key`. Strongly recommended if `CVEDECK_NVD_ENABLED` is on. |
| `CVEDECK_NVD_API_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Base URL for the NVD 2.0 CVE API. |
| `CVEDECK_DEFAULT_SSH_KEY_PATH` | _(unset)_ | Path to a server-managed SSH private key. When set, a Linux scan target may omit credentials entirely and authenticate with this key -- this is what enables a fleet re-scan without retyping credentials per host. Re-read on every scan, so rotating the file takes effect without a restart. |
| `CVEDECK_DEFAULT_SSH_KEY_PASSPHRASE` | _(unset)_ | Passphrase for the above key, if it is encrypted. |
| `CVEDECK_DEFAULT_SSH_USER` | _(unset)_ | Username paired with the server-managed key when a target supplies none. |
| `CVEDECK_DEMO_MODE` | `false` | Run as a public demo: seed a fictional fleet into an empty database (with its own fictional intel cache), and **refuse every change** -- scans, discovery sweeps, connection tests, the intel refresh, and every edit a visitor could make. See "Demo mode" below. Leave off on any instance you actually scan with. |
| `CVEDECK_CORS_ORIGINS` | unset | Comma-separated origins. Only needed if the dashboard is served from a different host than the API. `*` is refused at start-up: with credentials allowed, it would admit every site. |
| `CVEDECK_ALLOWED_HOSTS` | unset | Comma-separated host names this instance answers to; `*.example.lan` matches subdomains, and loopback is always accepted. Any other `Host` gets a 400. Unset accepts any name. Set it whenever login is off -- see "DNS rebinding" under Security. |
| `CVEDECK_AUTH` | `enabled` | Set to `disabled` to serve the dashboard and API without login, for an instance already behind an authenticating proxy. Any other value, including a typo, leaves login on. A warning is logged on every start while it is off. |
| `CVEDECK_ADMIN_USERNAME` | unset | With a password, creates this account on start-up if none exists. Never changes an existing account. |
| `CVEDECK_ADMIN_PASSWORD` | unset | Password for the account above, at least 12 characters. |
| `CVEDECK_ADMIN_PASSWORD_FILE` | unset | Read the password from this file instead, for Docker secrets. Takes precedence over `CVEDECK_ADMIN_PASSWORD`. |
| `CVEDECK_COOKIE_SECURE` | `auto` | Mark the session cookie `Secure`: `auto` does so when the request arrived over HTTPS, `true` always, `false` never. Set `true` behind a TLS proxy that uvicorn does not trust for `X-Forwarded-Proto`. |

Container-only extras: `PUID` / `PGID` (default `1000`) set the ownership of
files written to the data volume, and `TZ` sets the timezone. `PUID=0` or
`PGID=0` is refused, since it would run CveDeck as root; set
`CVEDECK_ALLOW_ROOT=1` if you really mean it. Everything in the data volume is
readable by that user and group only (files `0640`, the directory `0750`), and
files an older release left world-readable are closed on the next start.

`FORWARDED_ALLOW_IPS` is read by uvicorn, not CveDeck: the addresses whose
`X-Forwarded-*` headers are trusted. See "Behind a reverse proxy".

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

**The application refreshes them itself, every 24 hours, starting at startup.**
Nothing needs setting up: a fresh container has current intel within a minute of
booting, and keeps it current.

Each refresh also **reapplies the feeds to the findings already stored**, so a
newly catalogued exploitation appears on your existing findings rather than
waiting for the next scan of each host (Req 10.15). A download that carries
exactly the records already cached is recognised and skipped: nothing is
rewritten and no findings are re-read, and the refresh reports the feed as
`unchanged`. Most days, both feeds are. Findings that change are
marked for synchronization again, so a deployment with `CVEDECK_ONLINE_DB_URL`
propagates the new signals too.

Demo mode refuses the refresh entirely and ships a fictional cache of its own
instead, so a demo instance keeps the seeded findings whose exploitation status
was never checked and never reaches the network for intel. `GET /api/health`
reports `feed_refresh_hours: 0` there, because that is what is actually running.

`CVEDECK_FEED_REFRESH_HOURS` changes the interval; `0` switches the built-in
refresh off, for a deployment that would rather drive it from a scheduler it
already runs. `GET /api/health` reports the interval in effect, so you can tell
"this is handled for me" from "I still need a cron" without reading the
container's environment.

This is on by default because the alternative failed quietly. Before 0.8.7 the
refresh was external-only, and a deployment whose owner never set up the cron ran
on a KEV catalogue that aged silently — rendering a confident "0 actively
exploited" from a catalogue nobody had fetched. A missing cron was
indistinguishable from good news.

#### Triggering a refresh yourself

Still supported, and useful for an immediate refresh or when the built-in one is
switched off. The API requires a login, so a script uses an API token (create one
under **Settings** in the dashboard):

```bash
curl -fsS -X POST -H "Authorization: Bearer $CVEDECK_TOKEN" \
  http://localhost:3325/api/feeds/refresh
```

```json
{"ok": true,
 "findings_updated": 14,
 "results": [{"feed_name": "kev",  "status": "ok", "record_count": 1687},
             {"feed_name": "epss", "status": "ok", "record_count": 366848,
              "unchanged": true}]}
```

The two feeds refresh independently, so an outage at one upstream does not cost
the other's update — `ok` is `false` if either failed, with the reason in
`error_detail`. `unchanged: true` means the download succeeded and carried
exactly what was already cached, so the catalogue was not rewritten and no
findings were re-read; `record_count` is still the size of the cache in effect.

**Daily is enough**, because that is how often both upstreams publish.

The systemd installer (`deploy/install.sh`) sets this up for you as
`cvedeck-feeds.timer`, which runs at 03:00 with a 30-minute randomised
delay and `Persistent=true` so a machine that was asleep still catches up. It
runs `cvedeck-admin refresh-feeds` on the host, against the database directly,
so it needs no token. Because the timer owns the job there, the installer also
writes `CVEDECK_FEED_REFRESH_HOURS=0` into `/etc/cvedeck/cvedeck.env`, leaving
one scheduler rather than two; set it back to `24` if you disable the timer:

```bash
systemctl list-timers cvedeck-feeds.timer     # when it next runs
systemctl start cvedeck-feeds.service         # refresh right now
journalctl -u cvedeck-feeds.service           # why a refresh failed
```

For Docker, the built-in refresh covers this. If you have set
`CVEDECK_FEED_REFRESH_HOURS=0` and want to drive it yourself, add a cron entry on
the host. Either run the same command inside the container, which needs no
token:

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
  are refused for 30 seconds, doubling up to 15 minutes. After 20 from one
  address across all usernames, the address is slowed the same way -- trying a
  new made-up username each time no longer escapes it. The counts are kept in
  memory, so a restart clears them.

### API tokens

Create tokens under **Settings** in the dashboard. A token is shown once, when it
is created; CveDeck keeps only a hash. Send it as a bearer token:

```bash
curl -H "Authorization: Bearer cvd_..." http://localhost:3325/api/machines
```

A token can do anything the account can, except change the password or manage
tokens. Revoke one in **Settings** and it stops working immediately; **Revoke
all tokens** there ends every one at once, for a leak you cannot pin to one.

### Locked out

Reset the password from the host. Run it as the user that owns the data
directory, so SQLite does not leave a root-owned file behind:

```bash
docker exec -it --user 1000:1000 cvedeck cvedeck-admin reset-password
```

It prompts for the new password (or reads it from stdin with
`--password-stdin`), signs out every session and revokes every API token -- it
is the recovery after a compromise, so it ends every way in. Recreate the tokens
your scripts need afterwards. For a native install, run
`/opt/cvedeck/venv/bin/cvedeck-admin reset-password` as the `cvedeck` user with
`/etc/cvedeck/cvedeck.env` loaded.

### Turning login off

If CveDeck already sits behind something that authenticates people -- Authelia,
Authentik, oauth2-proxy, a VPN you trust -- you can switch the built-in login
off with `CVEDECK_AUTH=disabled`. Everything is then open to anyone who can
reach the port, and the log says so on every start. Only `disabled`, `off`,
`false`, `no` or `0` turn it off; anything else leaves login on.

Demo mode (`CVEDECK_DEMO_MODE=true`) never asks for a login.

With login off, a state-changing request that says it came from another site
-- by its `Origin`, `Referer` or `Sec-Fetch-Site` header -- is refused. A
request that says nothing, which is every script, is still served. That stops
a web page elsewhere from posting to the instance through a user's browser, but
not DNS rebinding: set `CVEDECK_ALLOWED_HOSTS` as well (see Security). The log
warns on start while login is off and it is unset.

### Behind a reverse proxy

- Pass the original `Host` header through (`proxy_set_header Host $host;` in
  nginx). Requests that change something must come from the dashboard's own
  origin, and that check compares the browser's `Origin` with `Host`;
  `CVEDECK_ALLOWED_HOSTS` checks it too.
- CveDeck sends its own content policy, framing, referrer and `nosniff`
  headers. Add only `Strict-Transport-Security` at the proxy, as the example
  config does; a second content policy there would be enforced alongside the
  first.
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

Keep the key file readable by the container user alone (`chmod 0400`, owned by
`PUID:PGID`) -- anyone who can read it can log in to every host it is
authorized on. Give that key its own unprivileged account on each target. The collector only
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

**It seeds a fictional thirteen-host fleet** into an empty database, covering the
states worth seeing: a host that has never been scanned, one whose credentials
failed, one that could not be reached, one scanned while an advisory source was
down, a host last scanned a month ago, findings CISA lists as actively
exploited, and findings whose exploitation status was never checked and so
report as unknown. Seeding is guarded on an empty fleet, so restarting the
container does not duplicate it and enabling the flag against a database with
real results in it does nothing.

**It is read-only.** Every request that could change stored state -- every
method but `GET`, `HEAD` and `OPTIONS` outside the sign-in routes -- returns
403. That is enforced once, on the routers as a whole, so a route added later is
refused without anyone naming it. Before 0.8.13 the refusals were per route,
and three write routes were missed: remediation edits, the sync, and discovery
enroll, which overwrites an existing machine's hostname, platform and scan
status. Any visitor could rewrite the demo fleet for every visitor after them.

Among those, the ones that reach the network are the reason the mode exists:
`POST /api/scans`, `POST /api/discovery/sweep`, `POST /api/scans/test-connection`
and `POST /api/feeds/refresh`. The first three take a hostname or a CIDR
plus credentials and connect to them, so a public instance with them enabled is
an SSH/WinRM client and port scanner that any visitor can aim at any address,
with the traffic originating from your server rather than theirs. The feed
refresh downloads several megabytes from CISA and FIRST on every press, with no
login and no rate limit, and rewrites the demo's own seeded intel on the way
through.

The feed refresh is refused in two places, not one. The route is refused like
every other write, and `refresh_feeds_and_reapply` refuses before it downloads
anything, whatever called it -- which is what also covers `cvedeck-admin
refresh-feeds`, run inside the container where no HTTP guard applies. 0.8.9
guarded only the route and placed the second check after the download, so the
CLI still replaced the fixture; the position of that check is the fix in
0.8.10.

The dashboard shows a banner while demo mode is on, and
`GET /api/health` reports it under `capabilities.demo_mode`.

**It needs no login.** A demo is meant to be clicked around by strangers. What
makes that safe is that nothing a visitor sends can change anything, enforced
at the router and pinned by a test that walks every route
(`backend/tests/test_demo_mode.py`). A route added later inherits the refusal.
A background job does not -- it is not a request -- so anything new that
changes stored state on a schedule needs its own demo check, as the feed
refresh has.

## Security

Login is required by default (see [Authentication](#authentication)). Every API
route except the health check and the sign-in routes refuses a request without a
session or an API token, and the OpenAPI schema at `/api/openapi.json` is
behind sign-in too. There is no interactive API page: FastAPI's Swagger UI loads
its code from a CDN, which would tell a third party that your address runs
CveDeck, so it was removed in 0.8.14. Load the schema into an API tool you run
locally instead. `GET /api/health` stays public for container health checks and
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
- **DNS rebinding.** A web page elsewhere can point its own host name at your
  instance's address; the browser then treats the dashboard as that page's own,
  so the `Origin` check passes. What gives it away is the `Host` header, which
  still carries the attacker's name. Set `CVEDECK_ALLOWED_HOSTS` to the names you
  use for CveDeck and every other name is refused. It matters most with login
  off, where nothing else stands in the way of a scan with the server's SSH key.
- **The security log.** Lines from the `app.security` logger record each scan,
  discovery sweep and connection test with who asked and from where (and whether
  the server-managed key was used), each forgotten host key, refused cross-site
  requests, unknown or revoked API tokens, and throttled sign-ins. No credential
  appears in any of them. `docker logs cvedeck 2>&1 | grep app.security`.
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
  without having checked it. **A Windows connection test fails too**, before it
  connects: it builds its WinRM session with equal read and operation timeouts,
  which pywinrm 0.5 rejects, so no password is sent anywhere. The collector
  behind future Windows scans also switches certificate validation off. Both
  are known and will be fixed with Windows matching; when that lands, set
  `CVEDECK_WINRM_SCHEME=https` and `CVEDECK_WINRM_PORT=5986` outside a lab.

Outbound access the scanner needs: TCP 22 to Linux targets, and the configured
WinRM port to any Windows host you run a connection test against.

## Scaling

The image runs a single uvicorn worker on purpose. The SQLAlchemy engine is a
process-wide singleton and SQLite permits only one writer, so additional workers
would contend on the database. To scale, move to PostgreSQL with
`CVEDECK_DB_URL` first, then raise `--workers`.

Because scans run inline within the request, a scan of many hosts occupies a
worker thread for its full duration. Prefer several smaller batches over one
very large one.

## Known limitations

- **Kernel packages are not matched against advisories yet.** Every other
  package is looked up under its source package and its own name (since
  0.8.15); the kernel is not, and each host's page says how many kernel packages
  went unchecked. Its findings are not "none" -- they were not asked for.
- **NVD matching is opt-in and off by default.** Package-level matching via
  OSV.dev is fully operational and always on. OS-level matching against NIST NVD
  is implemented but gated behind `CVEDECK_NVD_ENABLED` because NVD's rate
  limits (5 requests per 30 seconds without a key) make an unkeyed fleet scan
  slow. Set `CVEDECK_NVD_API_KEY` before enabling it.
- **Threat-intel feeds refresh themselves every 24 hours** (since 0.8.7), at
  startup and on the interval, with no external trigger. Set
  `CVEDECK_FEED_REFRESH_HOURS=0` to switch that off and drive
  `POST /api/feeds/refresh` or `cvedeck-admin refresh-feeds` yourself.
  `GET /api/feeds` reports each feed's age and whether it is stale, and the
  dashboard shows a banner when enrichment is degraded.
- **A feed refresh reapplies to findings already stored** (since 0.8.8), so a
  CVE added to the KEV catalogue overnight is marked on the findings you already
  have, without re-scanning the hosts that carry it. The refresh response and
  `cvedeck-admin refresh-feeds` both report how many findings changed. What a
  refresh cannot do is find *new* findings: matching a host's packages against
  advisories still happens only during a scan.
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
