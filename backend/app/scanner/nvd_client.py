"""HTTP client for OS-level CVE matching against the NVD 2.0 API.

Implements the :class:`~app.scanner.matcher.NvdClient` protocol, which has
existed as a bare Protocol since the first release with nothing behind it --
:mod:`app.api.wiring` passed ``nvd=None`` and every scan produced package-level
findings only.

**Why this is harder than the OSV path.** OSV answers "which advisories affect
this exact package at this exact version", which is a precise question. NVD
answers "which CVEs mention this product", which is a keyword search against a
corpus that was never designed for inventory matching. The result is inherently
noisier, and this client is deliberately conservative about what it returns:

- It searches by CPE-style OS product name, not by free text over the whole
  description, so a CVE that merely *mentions* Ubuntu does not land on every
  Ubuntu host.
- It caps the result set. An OS query can legitimately match thousands of CVEs
  spanning a decade; dumping all of them onto a host's finding list would bury
  the package-level findings that are actually actionable.

**Rate limits are the operational constraint.** NVD permits 5 requests per
rolling 30 seconds without an API key and 50 with one (free from
nvd.nist.gov/developers/request-an-api-key). This client throttles itself to
whichever applies, and treats a 403/429 as an outage rather than an error --
the matcher records ``DATA_SOURCE_UNAVAILABLE`` and the scan completes with a
visible partial-results warning instead of failing.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

from app.models import OsInfo
from app.scanner.cvss import cvss_v3_base_score, cvss_v4_base_score
from app.scanner.http_bounds import MIB, request_limited
from app.scanner.matcher import RawCve

_LOGGER = logging.getLogger(__name__)

_DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT = 30.0

# NVD's published rolling-window limits. The client paces itself to just inside
# these rather than retrying after a rejection, because NVD's response to
# sustained over-limit traffic is a temporary IP block, not a 429 per request.
_WINDOW_SECONDS = 30.0
_REQUESTS_PER_WINDOW_UNKEYED = 5
_REQUESTS_PER_WINDOW_KEYED = 50

# NVD pages at 2000 results maximum. One page is plenty: an OS-level query that
# overflows it is too broad to be actionable, and the findings that matter for
# a specific host come from the package-level OSV path regardless.
_RESULTS_PER_PAGE = 2000
_MAX_FINDINGS = 250

# HTTP statuses that mean "you are being throttled or blocked", as distinct
# from a malformed request. These become an outage, not a defect.
_THROTTLE_STATUSES = frozenset({403, 429, 503})

#: One page of up to 2000 CVE records; a ceiling, see app/scanner/http_bounds.py
#: (Req 10.18).
_MAX_NVD_PAGE = 128 * MIB


class _RateLimiter:
    """A minimal rolling-window limiter shared across threads.

    Not a token bucket: NVD's limit is expressed as N requests per rolling 30
    seconds, and a bucket that refills smoothly would drift over that boundary
    under bursty use.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max_requests
        self._window = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until another request may be issued."""
        while True:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [
                    t for t in self._timestamps if now - t < self._window
                ]
                if len(self._timestamps) < self._max_requests:
                    self._timestamps.append(now)
                    return
                sleep_for = self._window - (now - self._timestamps[0])
            time.sleep(max(sleep_for, 0.05))


def _cpe_product(os_info: OsInfo) -> str | None:
    """Map collected OS details onto an NVD CPE product name.

    Returns ``None`` for an OS with no useful NVD product mapping, which the
    caller turns into an empty result rather than a broad keyword search that
    would attach unrelated CVEs to the host.
    """
    name = (os_info.name or "").strip().lower()
    if not name:
        return None

    if "ubuntu" in name:
        return "cpe:2.3:o:canonical:ubuntu_linux"
    if "debian" in name:
        return "cpe:2.3:o:debian:debian_linux"
    if "alma" in name:
        return "cpe:2.3:o:almalinux:almalinux"
    if "rocky" in name:
        return "cpe:2.3:o:rocky:rocky_linux"
    if "alpine" in name:
        return "cpe:2.3:o:alpinelinux:alpine_linux"
    if "fedora" in name:
        return "cpe:2.3:o:fedoraproject:fedora"
    if "red hat" in name or "rhel" in name:
        return "cpe:2.3:o:redhat:enterprise_linux"
    if "suse" in name:
        return "cpe:2.3:o:suse:linux_enterprise_server"
    if "windows server" in name:
        return "cpe:2.3:o:microsoft:windows_server"
    if "windows" in name:
        return "cpe:2.3:o:microsoft:windows_10"
    return None


def _cpe_name(os_info: OsInfo) -> str | None:
    """Build the full CPE 2.3 match string for an OS, version included.

    The version is what keeps this narrow. ``ubuntu_linux`` alone matches every
    Ubuntu CVE ever published; ``ubuntu_linux:22.04`` matches the ones scoped to
    the release actually installed.
    """
    product = _cpe_product(os_info)
    if product is None:
        return None
    version = (os_info.version or "").strip()
    if not version:
        return None
    return f"{product}:{version}:*:*:*:*:*:*"


def _parse_cvss_from_metrics(metrics: dict[str, Any]) -> float | None:
    """Extract a CVSS base score from an NVD ``metrics`` block.

    Prefers v4.0, then v3.1, then v3.0, then v2, taking the published
    ``baseScore`` when there is one and recomputing the vector otherwise
    through :mod:`app.scanner.cvss`, so NVD and OSV cannot disagree about what
    a vector is worth.

    Every branch *falls through* rather than returning when it cannot produce a
    score. An unparseable v3.1 vector used to return its parser's result
    directly, which was fine only while that parser always returned a number;
    now that it reports ``None`` for a vector it cannot read, returning here
    would skip the v2 score sitting in the same block (Req 2.7).
    """
    for key, parser in (
        ("cvssMetricV40", cvss_v4_base_score),
        ("cvssMetricV31", cvss_v3_base_score),
        ("cvssMetricV30", cvss_v3_base_score),
    ):
        for metric in metrics.get(key) or []:
            if not isinstance(metric, dict):
                continue
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and 0.0 <= float(score) <= 10.0:
                return float(score)
            vector = data.get("vectorString")
            if isinstance(vector, str):
                parsed = parser(vector)
                if parsed is not None:
                    return parsed

    for metric in metrics.get("cvssMetricV2") or []:
        if not isinstance(metric, dict):
            continue
        score = (metric.get("cvssData") or {}).get("baseScore")
        if isinstance(score, (int, float)) and 0.0 <= float(score) <= 10.0:
            return float(score)

    return None


def parse_nvd_response(payload: Any) -> list[RawCve]:
    """Normalize an NVD 2.0 response body into :class:`RawCve` records.

    Pure, so the response shape can be tested against recorded fixtures without
    HTTP. CVEs that are rejected upstream, or that carry no usable CVSS score,
    are dropped: a finding with an invented severity is worse than no finding,
    because it competes for attention with measured ones.

    This deliberately differs from the OSV path, which since 0.8.6 keeps an
    advisory it cannot score and reports it as ``Severity.UNSCORED`` (Req 2.7).
    The asymmetry is not an oversight, and it is not settled either:

    - OSV advisories arrive already matched to an installed package, so an
      unscored one is a real finding about real software.
    - NVD matching is CPE-based and returns everything associated with an
      operating-system CPE, capped at ``_MAX_FINDINGS``. Keeping unscored CVEs
      would let a CPE that returns many of them crowd out measured findings --
      and the sort above deliberately places unscored FIRST so truncation cannot
      drop them, which makes that crowding worse rather than better.

    Sizing that safely needs real NVD response data across several CPEs, which
    is why 0.8.7 documented the difference instead of changing the behaviour:
    trading a known conservative rule for an unmeasured one, in a release about
    not presenting guesses as measurements, would have been the wrong move. NVD
    matching is also off by default (``CVEDECK_NVD_ENABLED``), so this affects
    deployments that opted in.
    """
    if not isinstance(payload, dict):
        return []
    vulnerabilities = payload.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return []

    by_cve: dict[str, RawCve] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        # "Rejected" entries are withdrawn CVE assignments. Reporting one as a
        # finding sends someone chasing a vulnerability that does not exist.
        if str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
            continue
        metrics = cve.get("metrics")
        if not isinstance(metrics, dict):
            continue
        score = _parse_cvss_from_metrics(metrics)
        if score is None:
            continue
        by_cve[cve_id] = RawCve(cve_id=cve_id, cvss_score=score)

    return list(by_cve.values())


class NvdHttpClient:
    """Concrete NVD 2.0 client for OS-level CVE matching."""

    def __init__(
        self,
        base_url: str = _DEFAULT_NVD_API_URL,
        *,
        api_key: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        max_findings: int = _MAX_FINDINGS,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._timeout = timeout
        self._max_findings = max_findings
        self._http_client = http_client
        self._limiter = _RateLimiter(
            _REQUESTS_PER_WINDOW_KEYED if api_key else _REQUESTS_PER_WINDOW_UNKEYED,
            _WINDOW_SECONDS,
        )
        # Two hosts on the same OS release ask the identical question, and a
        # fleet is usually mostly one or two releases. Caching per client
        # instance turns a 40-host batch into two or three NVD requests.
        self._cache: dict[str, list[RawCve]] = {}

    def match_os(self, os_info: OsInfo) -> list[RawCve]:
        """Return OS-level CVEs applicable to ``os_info``.

        Returns an empty list for an OS with no NVD product mapping, rather
        than falling back to a keyword search that would attach loosely related
        CVEs to the host.

        Raises:
            ConnectionError: When NVD throttles or is unreachable. The matcher
                converts this into ``DATA_SOURCE_UNAVAILABLE``, so the scan
                reports partial results instead of a clean bill of health.
        """
        cpe_name = _cpe_name(os_info)
        if cpe_name is None:
            _LOGGER.debug(
                "No NVD CPE mapping for OS %r %r; skipping OS-level match",
                os_info.name,
                os_info.version,
            )
            return []

        if cpe_name in self._cache:
            return self._cache[cpe_name]

        should_close = False
        if self._http_client is not None:
            client = self._http_client
        else:
            client = httpx.Client(timeout=self._timeout)
            should_close = True

        headers = {"apiKey": self._api_key} if self._api_key else {}
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": str(_RESULTS_PER_PAGE),
        }

        try:
            self._limiter.acquire()
            response = request_limited(
                client, "GET", self._base_url, limit=_MAX_NVD_PAGE, params=params, headers=headers
            )
            if response.status_code in _THROTTLE_STATUSES:
                raise ConnectionError(
                    f"NVD returned {response.status_code} "
                    f"({'rate limited' if response.status_code != 503 else 'unavailable'}). "
                    "Set CVEDECK_NVD_API_KEY to raise the request limit."
                )
            response.raise_for_status()
            findings = parse_nvd_response(response.json())
        except ConnectionError:
            raise
        except Exception as exc:
            raise ConnectionError(f"NVD request failed: {exc}") from exc
        finally:
            if should_close:
                client.close()

        # Highest-scoring first, then truncated: if the cap has to drop
        # something, it should drop the least severe rather than whatever
        # happened to sort last.
        #
        # A scoreless CVE sorts *first*, not last (Req 10.11, 10.12). The
        # truncation below is the reason: dropping the one finding nobody
        # measured, because it had no number to sort by, is the silent
        # all-clear this release exists to remove. `False < True`, so the
        # first key puts the unscored ahead of the scored.
        findings.sort(
            key=lambda f: (
                f.cvss_score is not None,
                -(f.cvss_score or 0.0),
                f.cve_id,
            )
        )
        findings = findings[: self._max_findings]

        self._cache[cpe_name] = findings
        _LOGGER.info(
            "NVD matched %d OS-level CVEs for %s", len(findings), cpe_name
        )
        return findings
