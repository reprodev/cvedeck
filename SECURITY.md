# Security Policy

CveDeck is given SSH or WinRM access to every host in a fleet, so a vulnerability
in it is a vulnerability in everything it scans. Reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.**

Use either of these — both are monitored, and neither is a second-class route:

- **GitHub Security Advisories** — the *Security* tab on
  [github.com/reprodev/cvedeck](https://github.com/reprodev/cvedeck) →
  *Report a vulnerability*. Opens a private thread visible only to you and the
  maintainers, and is the better channel if you want to be credited on a CVE:
  advisories issue CVE IDs directly and give us a private fork to develop the
  fix in.
- **security@cvedeck.com** — if you would rather not use GitHub, found the issue
  by way of the website rather than the repository, or your disclosure process
  runs on email.

Please include:

- What the issue is and what an attacker could do with it
- Steps to reproduce, or a proof of concept
- The version or commit you tested
- Your deployment shape, if relevant (Docker or systemd, SQLite or PostgreSQL,
  behind a reverse proxy or not)

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 7 days |
| Fix or mitigation plan | communicated once the assessment is done |
| Public disclosure | coordinated with you, after a fix ships |

This is a small project, so these are honest targets rather than a contractual
SLA. If you have not heard back within a week, please chase — it means something
went wrong, not that the report was ignored.

You will be credited in the advisory and the changelog unless you would rather
not be.

## Scope

**In scope** — the scanner backend, the dashboard, the collectors, the Docker
image, the deployment scripts under `deploy/`, and anything that could:

- expose or exfiltrate target-host credentials
- turn the scanner into a vector against the hosts it scans
- allow remote code execution, SSRF, SQL injection, or path traversal
- **carry an attack out of the product in an export.** A CSV is opened in a
  spreadsheet that evaluates formulas, and much of what CveDeck exports came off
  a scanned host rather than from the operator.
- **cause the scanner to under-report vulnerabilities.** A bug that makes a
  vulnerable host read as clean is a security issue here, not merely a
  correctness one, because users act on that answer.

**Out of scope** — the known limitations documented below, findings that require
an attacker to already have the privileges the report assumes, and issues in
upstream data sources (report those to CISA, FIRST, OSV, or NVD).

## Known limitations, by design

These are documented rather than hidden, and are **not** vulnerabilities. They
are also why the deployment guidance is what it is.

**One account, no roles.** Login is required by default, but there is a single
account, and anyone signed in -- or holding an API token -- can scan, sweep
subnets and edit remediation records. Tokens cannot change the password or
manage tokens, and nothing finer-grained exists. A bypass of the login itself
*is* in scope.

**Login can be switched off.** `CVEDECK_AUTH=disabled` serves everything without
authentication, for instances behind an authenticating proxy. An instance
configured that way and exposed directly is a deployment choice, not a
vulnerability.

**Plain HTTP exposes credentials.** CveDeck does not terminate TLS itself. Over
HTTP, the password, the session cookie and scan credentials are readable on the
network; put a TLS reverse proxy in front anywhere beyond a trusted network.

**Failed-login throttling is in memory.** It resets on restart and is per
process, which fits the single-worker deployment. Behind a proxy that uvicorn
does not trust, every client shares the proxy's address.

**The first connection to a host trusts its SSH key.** CveDeck pins each host's
key the first time a scan or connection test to it succeeds, and refuses the
host, before sending any credential, if it ever presents a different key. That
first connection is still trust on first use: something in the middle of it
gets pinned instead of the host. Compare the fingerprint shown on the machine's
page with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host, or set
`CVEDECK_SSH_HOST_KEY_POLICY=strict` so unpinned hosts are refused. An instance
upgraded from 0.7.3 or earlier has no pins, so its next scan of each host is a
first use.

**WinRM defaults to HTTP.** Windows scans are refused in this release, so no
WinRM connection is made by a scan — but **a connection test does connect**, and
on the default `http` transport on port 5985 the NTLM exchange crosses the
network unencrypted. Set `CVEDECK_WINRM_SCHEME=https` and
`CVEDECK_WINRM_PORT=5986` before testing a Windows host outside a lab; both
settings apply to the connection test today, and to scans when Windows matching
lands. The test names the endpoint it reached, so a result reading `http://…`
is telling you the password went out in the clear.

**Credentials are held in memory during a scan.** They arrive in the request
body, are wrapped in `SecretStr` so they are not logged or serialized, and are
never written to disk — but they are in process memory for the duration of the
scan, and in the request body in transit. Use TLS.

**The server-managed SSH key is a standing credential.** When
`CVEDECK_DEFAULT_SSH_KEY_PATH` is set, anyone who can reach the API can
trigger a scan using that key. Give it a dedicated, unprivileged, read-only
account on each target — not root.

## Hardening checklist

- Bind to `127.0.0.1` and front it with nginx; TLS, and `auth_basic` at minimum.
  See `deploy/nginx/cvedeck.conf.example`.
- Use the hardened systemd unit in `deploy/systemd/`, or run the container as a
  non-root user with `PUID`/`PGID`.
- Give the scanner a dedicated read-only account on each target host.
- Keep the database volume off world-readable storage — it holds your fleet's
  full software inventory, which is a useful document for an attacker.
- Keep the image current. Watch releases for security fixes.

## Supported versions

Pre-1.0, only the latest release receives security fixes. Once 1.0 ships, this
will become a proper support window.
