# CveDeck - Backend

Agentless vulnerability scanner backend. Python 3.11+, FastAPI, Pydantic,
SQLAlchemy, `paramiko` (SSH/Linux), `pywinrm` (WinRM/Windows).

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -e ".[dev]"
```

`pip install -e ".[dev]"` resolves dependencies loosely. To reproduce the exact
versions the container and server builds use:

```bash
pip install -r requirements-dev.txt   # runtime + test pins
pip install -e . --no-deps
```

Add `.[postgres]` (or the `psycopg` pin already in `requirements.txt`) to run
against PostgreSQL instead of SQLite.

## Tests

```bash
pytest
```

Property-based tests run a minimum of 100 iterations each (Hypothesis profile
`cvedeck`, registered in `tests/conftest.py`).

## Running it

```bash
uvicorn app.api.app:app --port 8000
```

The module-level `app` is built with `create_app(wire_production=True)`, which
installs the concrete scanner engine and sync service from `app/api/wiring.py`
and serves the built frontend when `CVEDECK_STATIC_DIR` points at one. Tests
and other callers use the bare `create_app()`, whose scan/sync dependencies stay
unconfigured so nothing can reach a real host by accident.

Configuration is read from the environment through `app/config.py`. The two that
matter most:

- `CVEDECK_DATA_DIR` - where the SQLite database is written (default: the
  working directory, so `./cvedeck.db`).
- `CVEDECK_DB_URL` - full SQLAlchemy URL, overriding the above.

See [DEPLOYMENT.md](../DEPLOYMENT.md) for the full variable reference and for
running this as a container or a systemd service.

## Threat-intel feeds

Findings are enriched with CISA KEV (actively exploited in the wild) and FIRST
EPSS (probability of exploitation in the next 30 days). Both are downloaded whole
and cached locally rather than queried per finding, so a fresh database starts
with no enrichment at all:

```bash
curl -X POST http://localhost:8000/api/feeds/refresh   # populate the caches
curl http://localhost:8000/api/feeds                   # check their age
```

Enrichment applies at scan time, so a refresh takes effect on the next scan
rather than retroactively. Until a feed has loaded, findings report exploitation
status as `null` -- meaning *not checked*, which the UI renders as unknown. That
is deliberately distinct from `false` (*checked, and not in the catalogue*); see
`app/services/enrichment.py` for why the two are never collapsed.

OS-level matching against NVD is implemented but off by default. Enable it with
`CVEDECK_NVD_ENABLED=true`, ideally alongside a free `CVEDECK_NVD_API_KEY`
-- unkeyed, NVD permits only 5 requests per rolling 30 seconds.

## Layout

- `app/` - application package
  - `app/config.py` - environment-driven deployment settings
  - `app/scanner/` - scanner engine, collectors, matching, and the data-source
    clients (`osv_client`, `nvd_client`, `kev_client`, `epss_client`)
  - `app/data/` - persistence (SQLAlchemy models, repositories, Alembic migrations)
  - `app/services/` - remediation, sync, and threat-intel enrichment
  - `app/api/` - FastAPI app, routers, and production wiring
- `tests/` - pytest + Hypothesis test suite

No test reaches the network: every data-source client is exercised against
recorded fixture payloads through `httpx.MockTransport`. A suite that depends on
CISA or NIST being reachable fails offline.

The exception proves the same point. `tests/test_host_keys.py` runs a real
paramiko SSH server on a loopback port, because the claims it makes -- that a
changed host key is refused *before* any credential is sent, and that a pinned
key type is still negotiated by a host offering several -- are properties of an
actual handshake, and a fake client would assert them about itself. Nothing
leaves the machine.
