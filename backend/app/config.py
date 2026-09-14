"""Deployment configuration read from the process environment.

Everything a deployment needs to vary -- where the database lives, where the
built frontend lives, which ports the collectors dial -- is resolved here so no
other module reads ``os.environ`` directly. Values are read at call time (not at
import time) so tests and embedding processes can set the environment before the
app is created.

The defaults reproduce the previous behavior exactly: with no environment set,
the database is still ``./cvedeck.db`` relative to the process working
directory, no static files are served, and the collectors use their standard
ports. A container sets ``CVEDECK_DATA_DIR`` and ``CVEDECK_STATIC_DIR``
to move state onto a mounted volume and serve the dashboard.

See DEPLOYMENT.md for the full environment variable reference.
"""

from __future__ import annotations

import os
from pathlib import Path

# Default remoting ports, mirroring app.scanner.collectors.
_DEFAULT_SSH_PORT = 22
_DEFAULT_WINRM_PORT = 5985


def data_dir() -> Path:
    """Directory holding writable state (currently just the SQLite file).

    Defaults to the process working directory so local development is
    unchanged. Containers set this to the mounted volume (``/data``).
    """
    return Path(os.environ.get("CVEDECK_DATA_DIR", "."))


def database_url() -> str:
    """SQLAlchemy URL for the Local_Database.

    ``CVEDECK_DB_URL`` wins when set (use it to point at PostgreSQL, e.g.
    ``postgresql+psycopg://user:pass@host/db``). Otherwise a SQLite file inside
    :func:`data_dir` is used.
    """
    url = os.environ.get("CVEDECK_DB_URL")
    if url:
        return url
    return f"sqlite:///{(data_dir() / 'cvedeck.db').as_posix()}"


def online_database_url() -> str | None:
    """SQLAlchemy URL for the Online_Database, or ``None`` when unconfigured.

    When unset, ``POST /api/sync`` reports the feature as unconfigured rather
    than failing with a server error.
    """
    return os.environ.get("CVEDECK_ONLINE_DB_URL") or None


def static_dir() -> Path | None:
    """Directory holding the built frontend, or ``None`` to serve no static files.

    When set, the API mounts it so the dashboard and the API share one origin --
    which is what the frontend expects, since it calls ``/api/...`` relative to
    wherever it was served from.
    """
    raw = os.environ.get("CVEDECK_STATIC_DIR")
    if not raw:
        return None
    return Path(raw)


def cors_origins() -> list[str]:
    """Allowed CORS origins, empty when the API and dashboard share an origin.

    Only needed when the frontend is served from a different host than the API;
    the single-container deployment leaves this unset.
    """
    raw = os.environ.get("CVEDECK_CORS_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def ssh_port() -> int:
    """TCP port the Linux collector dials for SSH."""
    return _int_env("CVEDECK_SSH_PORT", _DEFAULT_SSH_PORT)


def winrm_port() -> int:
    """TCP port the Windows collector dials for WinRM (5986 for HTTPS)."""
    return _int_env("CVEDECK_WINRM_PORT", _DEFAULT_WINRM_PORT)


def winrm_scheme() -> str:
    """URL scheme for the WinRM endpoint (``http`` or ``https``)."""
    scheme = os.environ.get("CVEDECK_WINRM_SCHEME", "http").strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError(
            f"CVEDECK_WINRM_SCHEME must be 'http' or 'https', got {scheme!r}"
        )
    return scheme


def default_ssh_key_path() -> Path | None:
    """Path to a server-managed SSH private key, or ``None`` when unset.

    When configured, a scan target may omit credentials entirely and the Linux
    collector authenticates with this key. That is what makes a one-click fleet
    re-scan possible: without it, every host in a batch needs its credentials
    retyped into the request.

    The key is read at scan time rather than cached, so rotating it on disk
    takes effect without a restart.
    """
    raw = os.environ.get("CVEDECK_DEFAULT_SSH_KEY_PATH")
    if not raw or not raw.strip():
        return None
    return Path(raw.strip())


def default_ssh_key_passphrase() -> str | None:
    """Passphrase for the server-managed SSH key, or ``None`` when unset."""
    raw = os.environ.get("CVEDECK_DEFAULT_SSH_KEY_PASSPHRASE")
    return raw if raw else None


def default_ssh_user() -> str | None:
    """Username paired with the server-managed SSH key, or ``None`` when unset."""
    raw = os.environ.get("CVEDECK_DEFAULT_SSH_USER")
    if not raw or not raw.strip():
        return None
    return raw.strip()


def osv_api_url() -> str:
    """Base URL for the OSV.dev REST API."""
    return os.environ.get("CVEDECK_OSV_API_URL", "https://api.osv.dev/v1")


def kev_feed_url() -> str:
    """URL of the CISA Known Exploited Vulnerabilities catalogue (JSON)."""
    return os.environ.get(
        "CVEDECK_KEV_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json",
    )


def epss_feed_url() -> str:
    """URL of the current FIRST EPSS score set (gzipped CSV)."""
    return os.environ.get(
        "CVEDECK_EPSS_FEED_URL",
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    )


def nvd_api_url() -> str:
    """Base URL for the NVD 2.0 CVE API."""
    return os.environ.get(
        "CVEDECK_NVD_API_URL",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
    )


def nvd_api_key() -> str | None:
    """NVD API key, or ``None`` when unset.

    Without a key NVD allows 5 requests per rolling 30 seconds; with a free key
    that rises to 50. The client throttles itself to whichever limit applies,
    so an unkeyed deployment works -- it is just slower.
    """
    raw = os.environ.get("CVEDECK_NVD_API_KEY")
    if not raw or not raw.strip():
        return None
    return raw.strip()


def nvd_enabled() -> bool:
    """Whether OS-level NVD matching runs during a scan.

    Off by default: NVD's rate limits make an unkeyed scan of a large fleet
    slow, and the package-level OSV path already covers most of what a Linux
    host is vulnerable to. A deployment opts in explicitly, ideally with a key.
    """
    raw = os.environ.get("CVEDECK_NVD_ENABLED", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def feed_max_age_hours() -> float:
    """How old a cached feed may be before it is reported as stale.

    KEV and EPSS both publish daily, so a cache older than this has missed at
    least one publication. Defaults to 48 hours -- one missed publication is
    tolerable, two means something is wrong and the dashboard should say so.
    """
    raw = os.environ.get("CVEDECK_FEED_MAX_AGE_HOURS")
    if raw is None or not raw.strip():
        return 48.0
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(
            f"CVEDECK_FEED_MAX_AGE_HOURS must be a float, got {raw!r}"
        ) from exc


def feed_timeout() -> float:
    """HTTP timeout in seconds for a whole-feed download.

    Separate from :func:`http_timeout` because the EPSS set is a multi-megabyte
    download, not a per-package API call, and sharing the per-query timeout
    would make an otherwise healthy refresh look like an outage.
    """
    raw = os.environ.get("CVEDECK_FEED_TIMEOUT")
    if raw is None or not raw.strip():
        return 120.0
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(
            f"CVEDECK_FEED_TIMEOUT must be a float, got {raw!r}"
        ) from exc


def http_timeout() -> float:
    """HTTP client timeout in seconds for data-source queries."""
    raw = os.environ.get("CVEDECK_HTTP_TIMEOUT")
    if raw is None or not raw.strip():
        return 15.0
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"CVEDECK_HTTP_TIMEOUT must be a float, got {raw!r}") from exc


def demo_mode() -> bool:
    """Whether to run as a public demo (Req 15.7).

    Demo mode does two things: it seeds a fictional fleet into an empty
    database so the dashboard has something to show, and it refuses to run
    scans. The refusal is the important half -- a public demo that accepted a
    hostname and credentials would be an open SSH/WinRM client pointed at
    whatever a stranger typed, which is a service worth abusing.

    Off unless explicitly enabled. Accepts the usual truthy spellings so that
    ``CVEDECK_DEMO_MODE=true`` in a compose file behaves as anyone would
    expect.
    """
    raw = os.environ.get("CVEDECK_DEMO_MODE", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def auth_enabled() -> bool:
    """Whether the dashboard and API require a login (Req 16.9).

    On unless ``CVEDECK_AUTH`` is explicitly one of the "off" spellings. Every
    other value -- including a typo such as ``disable`` or ``flase`` -- leaves
    login on. This is the opposite default to :func:`demo_mode`, and for the
    same reason: each setting fails towards the safe state, and for access
    control the safe state is locked.
    """
    raw = os.environ.get("CVEDECK_AUTH", "").strip().lower()
    return raw not in {"disabled", "off", "false", "0", "no"}


def cookie_secure() -> str:
    """When to mark the session cookie ``Secure``: ``auto``, ``true`` or ``false``.

    ``auto`` (the default) sets it when the request arrived over HTTPS. Behind a
    TLS-terminating proxy that only works if uvicorn trusts the proxy's
    ``X-Forwarded-Proto`` (``--proxy-headers``); ``true`` forces it regardless.
    An unrecognised value is treated as ``auto``.
    """
    raw = os.environ.get("CVEDECK_COOKIE_SECURE", "").strip().lower()
    if raw in {"true", "1", "yes", "on"}:
        return "true"
    if raw in {"false", "0", "no", "off"}:
        return "false"
    return "auto"


def admin_username() -> str | None:
    """Username to pre-create on first start, or ``None`` (Req 16.4)."""
    raw = os.environ.get("CVEDECK_ADMIN_USERNAME", "").strip()
    return raw or None


def admin_password() -> str | None:
    """Password to pre-create on first start, or ``None`` (Req 16.4).

    ``CVEDECK_ADMIN_PASSWORD_FILE`` wins when set, so the password can come from
    a Docker secret rather than sitting in a compose file. A trailing newline in
    the file is removed, since editors add one. A file that cannot be read is an
    error rather than a silent fall-through, because falling through would start
    the instance with no account and a setup code nobody expected.
    """
    path = os.environ.get("CVEDECK_ADMIN_PASSWORD_FILE", "").strip()
    if path:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n") or None
    raw = os.environ.get("CVEDECK_ADMIN_PASSWORD", "")
    return raw or None


def _int_env(name: str, default: int) -> int:
    """Read an integer environment variable, failing loudly on a bad value."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc

