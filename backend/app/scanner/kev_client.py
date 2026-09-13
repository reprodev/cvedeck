"""Client for CISA's Known Exploited Vulnerabilities (KEV) catalogue.

KEV answers the one question CVSS cannot: *is anyone actually exploiting this?*
A CVSS 9.8 with no observed exploitation is usually not this week's problem; a
CVSS 6.5 on the KEV list is, because CISA only adds a CVE once exploitation has
been observed in the wild.

Unlike :mod:`app.scanner.osv_client`, which queries per package during a scan,
the whole catalogue is a single JSON document of a few thousand entries. It is
therefore downloaded whole on a cadence and joined locally -- one request a day
instead of one per finding, which is both faster and the access pattern CISA
publishes the feed for.

Parsing is separated from fetching (:func:`parse_kev_catalog` is pure) so the
brittle part -- upstream field naming -- is testable against recorded fixtures
without any HTTP.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)

_DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_DEFAULT_TIMEOUT = 120.0

# CISA publishes "known" / "unknown" here rather than a boolean. Anything that
# is not an affirmative "known" is treated as not-known: overstating ransomware
# association would be the more damaging error, since it is the signal most
# likely to trigger an out-of-hours response.
_RANSOMWARE_AFFIRMATIVE = "known"


@dataclass(frozen=True)
class KevRecord:
    """One normalized KEV catalogue entry."""

    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware_use: bool = False
    notes: str | None = None


def _clean(value: Any) -> str | None:
    """Normalize an upstream string field to a non-empty string or ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_kev_catalog(payload: Any) -> list[KevRecord]:
    """Normalize a decoded KEV catalogue document into :class:`KevRecord` rows.

    Tolerant by design. A malformed individual entry is skipped rather than
    failing the import, because losing one entry is a far better outcome than
    losing the entire catalogue -- and an empty catalogue would silently render
    every finding as "not known-exploited", which is exactly the false negative
    this feed exists to prevent.

    Entries without a CVE identifier are dropped: the id is the join key, so an
    entry lacking one can never match a finding.

    Args:
        payload: The decoded JSON document, expected to carry a
            ``vulnerabilities`` list. A bare list is also accepted.

    Returns:
        One record per usable entry, de-duplicated by CVE id (last wins).
    """
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = payload.get("vulnerabilities") or []
    else:
        return []

    if not isinstance(entries, list):
        return []

    by_cve: dict[str, KevRecord] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve_id = _clean(entry.get("cveID") or entry.get("cve_id"))
        if not cve_id:
            continue
        ransomware = str(
            entry.get("knownRansomwareCampaignUse") or ""
        ).strip().lower()
        by_cve[cve_id.upper()] = KevRecord(
            cve_id=cve_id.upper(),
            vendor_project=_clean(entry.get("vendorProject")),
            product=_clean(entry.get("product")),
            vulnerability_name=_clean(entry.get("vulnerabilityName")),
            date_added=_clean(entry.get("dateAdded")),
            due_date=_clean(entry.get("dueDate")),
            known_ransomware_use=ransomware == _RANSOMWARE_AFFIRMATIVE,
            notes=_clean(entry.get("shortDescription") or entry.get("notes")),
        )

    return list(by_cve.values())


class KevHttpClient:
    """Downloads and parses the live CISA KEV catalogue."""

    def __init__(
        self,
        url: str = _DEFAULT_KEV_URL,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._http_client = http_client

    def fetch(self) -> list[KevRecord]:
        """Download the catalogue and return its normalized entries.

        Raises:
            Exception: Any transport or decode failure is propagated, so the
                caller records a failed refresh rather than overwriting a good
                cache with an empty one. Returning ``[]`` on error here would
                erase a working catalogue on a transient network blip.
        """
        should_close = False
        if self._http_client is not None:
            client = self._http_client
        else:
            client = httpx.Client(timeout=self._timeout)
            should_close = True

        try:
            response = client.get(self._url)
            response.raise_for_status()
            records = parse_kev_catalog(response.json())
        finally:
            if should_close:
                client.close()

        _LOGGER.info("KEV catalogue fetched: %d entries", len(records))
        return records
