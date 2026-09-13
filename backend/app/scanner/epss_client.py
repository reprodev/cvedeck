"""Client for the FIRST EPSS (Exploit Prediction Scoring System) score set.

EPSS is the complement to KEV. Where KEV is a binary, observed fact about a few
thousand CVEs, EPSS assigns *every* published CVE a modelled probability
(0.0-1.0) of being exploited in the next 30 days. Together they turn a
CVSS-sorted list into a genuinely ordered one: KEV says "this is happening",
EPSS says "this is likely to", and CVSS says "this would be bad if it did".

The ``percentile`` field matters as much as the score. A raw EPSS of 0.08 reads
as negligible until you know it ranks above 94% of all scored CVEs -- the
distribution is extremely skewed, with the overwhelming majority of CVEs below
0.01, so absolute scores mislead and ranks do not.

The feed is a single gzipped CSV of roughly 280,000 rows published daily, so it
is downloaded whole and joined locally rather than queried per CVE. As in
:mod:`app.scanner.kev_client`, parsing (:func:`parse_epss_csv`) is pure and
separated from fetching so it can be tested against fixtures without HTTP.
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
from dataclasses import dataclass

import httpx

_LOGGER = logging.getLogger(__name__)

_DEFAULT_EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_DEFAULT_TIMEOUT = 120.0

# The feed's first line is a metadata comment, e.g.
#   #model_version:v2025.03.14,score_date:2026-09-01T00:00:00+0000
# The real CSV header ("cve,epss,percentile") follows it. csv.DictReader would
# otherwise take the comment as the header and every row would parse to garbage.
_COMMENT_PREFIX = "#"


@dataclass(frozen=True)
class EpssRecord:
    """One CVE's EPSS probability and its percentile rank."""

    cve_id: str
    score: float
    percentile: float


def _parse_probability(raw: str) -> float | None:
    """Parse a probability field, rejecting anything outside 0.0-1.0.

    Out-of-range values are rejected rather than clamped: a value above 1.0 is
    evidence the column layout changed upstream, and clamping would quietly
    persist a wrong number as though it were measured.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= value <= 1.0:
        return None
    return value


def parse_epss_csv(text: str) -> list[EpssRecord]:
    """Normalize the decompressed EPSS CSV into :class:`EpssRecord` rows.

    Skips the leading ``#model_version`` comment line, then reads the remaining
    rows by header name rather than by position, so an added upstream column
    does not shift the score into the percentile.

    Malformed rows are skipped individually. As with KEV, partial data beats no
    data: a handful of unparseable rows should not cost the whole 280k-row set.

    Args:
        text: The decompressed CSV content.

    Returns:
        One record per usable row, de-duplicated by CVE id (last wins).
    """
    lines = text.splitlines()
    start = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIX):
            continue
        start = index
        break
    else:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    if reader.fieldnames is None:
        return []

    # Header names are normalized so a stray space or case change upstream does
    # not silently produce zero rows.
    field_map = {
        (name or "").strip().lower(): name for name in reader.fieldnames
    }
    cve_field = field_map.get("cve") or field_map.get("cve_id")
    score_field = field_map.get("epss") or field_map.get("score")
    percentile_field = field_map.get("percentile")
    if cve_field is None or score_field is None or percentile_field is None:
        _LOGGER.warning(
            "EPSS feed header not recognized: %r", reader.fieldnames
        )
        return []

    by_cve: dict[str, EpssRecord] = {}
    for row in reader:
        cve_id = (row.get(cve_field) or "").strip().upper()
        if not cve_id:
            continue
        score = _parse_probability((row.get(score_field) or "").strip())
        percentile = _parse_probability((row.get(percentile_field) or "").strip())
        if score is None or percentile is None:
            continue
        by_cve[cve_id] = EpssRecord(
            cve_id=cve_id, score=score, percentile=percentile
        )

    return list(by_cve.values())


class EpssHttpClient:
    """Downloads and parses the live FIRST EPSS score set."""

    def __init__(
        self,
        url: str = _DEFAULT_EPSS_URL,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._http_client = http_client

    def fetch(self) -> list[EpssRecord]:
        """Download the score set and return its normalized rows.

        Transport and decode failures propagate so the caller records a failed
        refresh rather than replacing a good cache with an empty one.
        """
        should_close = False
        if self._http_client is not None:
            client = self._http_client
        else:
            client = httpx.Client(timeout=self._timeout, follow_redirects=True)
            should_close = True

        try:
            response = client.get(self._url)
            response.raise_for_status()
            text = _decompress(response.content)
        finally:
            if should_close:
                client.close()

        records = parse_epss_csv(text)
        _LOGGER.info("EPSS score set fetched: %d records", len(records))
        return records


def _decompress(payload: bytes) -> str:
    """Return the feed body as text, gunzipping it when it is gzipped.

    The transparent-decompression behaviour of an HTTP client depends on
    whether the server sends ``Content-Encoding: gzip`` (in which case the body
    arrives already decoded) or serves the ``.gz`` file as an opaque download
    (in which case it does not). Sniffing the magic bytes handles both without
    depending on which one the CDN in front of the feed chooses today.
    """
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload).decode("utf-8", errors="replace")
    return payload.decode("utf-8", errors="replace")
