"""Vulnerability matching logic and severity derivation.

This module houses the pure logic that turns collected inventory and raw
vulnerability data into findings. It provides:

- ``derive_severity``: maps a CVSS base score to a ``Severity`` band.
- ``resolve_severity``: decides a finding's band from the score and the
  qualitative severity the advisory published, either of which may be
  absent.
- ``NvdClient`` / ``OsvClient`` protocols: the data-source client contracts the
  Matcher depends on (OS-level CVEs from NVD, package-level advisories from OSV).
- ``RawCve`` / ``RawAdvisory``: normalized raw records returned by the clients.
- ``Finding`` / ``MatchResult``: the Matcher's output (findings plus per-source
  reachability status).
- ``Matcher``: correlates an ``Inventory`` with reachable data sources, deriving
  severity and recording ``DATA_SOURCE_UNAVAILABLE`` for unreachable sources.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from app.enums import Severity, SourceStatus
from app.models import Inventory, OsInfo, Package

# CVSS v3.x qualitative severity band lower bounds (inclusive), highest first.
# A score at or above a threshold takes that band. Using thresholds (rather
# than the documented 0.0-3.9 / 4.0-6.9 / ... closed intervals) makes the
# function total over the entire continuous [0.0, 10.0] range, including the
# fractional gaps between the one-decimal band edges (e.g. 3.95).
#
# Severity.UNSCORED is deliberately absent: these are bands *of the CVSS
# range*, and an advisory with no score is not somewhere in that range. See
# resolve_severity, which is the entry point that handles its absence.
_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)

_MIN_CVSS = 0.0
_MAX_CVSS = 10.0

_LOGGER = logging.getLogger(__name__)

# Exceptions that mean "this code is broken", not "this data source is down".
# Laundering these into DATA_SOURCE_UNAVAILABLE hides the defect behind a
# plausible-looking empty result, so they are re-raised. Per-target fault
# isolation in ScannerEngine still keeps one bad target from aborting a batch.
_PROGRAMMING_ERRORS = (NameError, TypeError, AttributeError, ImportError)


def derive_severity(cvss_score: float) -> Severity:
    """Map a CVSS base score to its ``Severity`` band.

    Total over the valid CVSS range 0.0-10.0 using the documented CVSS v3.x
    bands: 0.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical.

    Args:
        cvss_score: The CVSS base score, expected in the range 0.0 to 10.0.

    Returns:
        The single ``Severity`` level for the given score.

    Raises:
        ValueError: If ``cvss_score`` is outside the range 0.0 to 10.0.
    """
    if not _MIN_CVSS <= cvss_score <= _MAX_CVSS:
        raise ValueError(
            f"cvss_score must be within {_MIN_CVSS}-{_MAX_CVSS}, got {cvss_score!r}"
        )

    for lower_bound, severity in _SEVERITY_BANDS:
        if cvss_score >= lower_bound:
            return severity

    # Unreachable: the final band has a lower bound of 0.0 and the range is
    # validated above, so some band always matches.
    return Severity.LOW


def resolve_severity(
    cvss_score: float | None, band: Severity | None = None
) -> Severity:
    """Decide a finding's Severity_Level from what the advisory actually said.

    Total over every combination, and the only place the three cases are
    resolved:

    - a qualitative band, with or without a score: the band the feed published
      wins. It is a statement by the advisory's author, and deriving a band
      from a score we then had to invent is how the invented score got in
      (Req 2.6).
    - a score and no band: the band is derived from the score, as always.
    - neither: ``UNSCORED``. Not ``MEDIUM``, and not the lowest band (Req 2.7).

    Args:
        cvss_score: The published CVSS base score, or ``None`` if the advisory
            carries none that could be parsed.
        band: The qualitative severity the feed named, if it named one.

    Returns:
        The Severity_Level to record.
    """
    if band is not None:
        return band
    if cvss_score is None:
        return Severity.UNSCORED
    return derive_severity(cvss_score)


# --- Raw records returned by the data-source clients -----------------------


class RawCve(BaseModel):
    """A raw OS-level CVE record as returned by an ``NvdClient``.

    This is the normalized shape the Matcher consumes from NVD. It carries the
    CVE identifier and its CVSS base score, either of which the source may
    leave unstated; the Matcher resolves the ``Severity`` band from both
    (Req 2.3, 2.4, 2.6, 2.7).
    """

    model_config = ConfigDict(frozen=True)

    cve_id: str
    cvss_score: float | None
    #: The qualitative band the source published, when it published one
    #: instead of (or alongside) a score. Carried here rather than resolved at
    #: the client, so the Matcher stays the single place severity is decided.
    severity: Severity | None = None


class RawAdvisory(BaseModel):
    """A raw package-level advisory as returned by an ``OsvClient``.

    Carries the CVE identifier, its CVSS base score (absent when the advisory
    publishes none), the qualitative band it named if any, and the package
    identifier the advisory applies to. The package identifier is preserved on the
    resulting finding so package-level findings remain traceable to the
    affected software (Req 7.1).
    """

    model_config = ConfigDict(frozen=True)

    cve_id: str
    cvss_score: float | None
    #: See :attr:`RawCve.severity`.
    severity: Severity | None = None
    package_identifier: str


# --- Data-source client protocols ------------------------------------------


@runtime_checkable
class NvdClient(Protocol):
    """Contract for a client that matches OS inventory against NVD.

    Implementations connect to the National Vulnerability Database and return
    the OS-level CVEs applicable to the given operating-system details.
    """

    def match_os(self, os_info: OsInfo) -> list[RawCve]:
        """Return the OS-level CVEs applicable to ``os_info``."""
        ...


@runtime_checkable
class OsvClient(Protocol):
    """Contract for a client that matches software inventory against OSV.dev.

    Implementations connect to the OSV database and return the package-level
    advisories applicable to the given installed packages.
    """

    def match_packages(self, packages: list[Package]) -> list[RawAdvisory]:
        """Return the package-level advisories applicable to ``packages``."""
        ...


# --- Matcher output --------------------------------------------------------


class Finding(BaseModel):
    """A single CVE finding produced by the Matcher for a machine.

    Every finding carries the CVE identifier, its CVSS score, the derived
    severity, the affected machine reference, and the originating source
    ("nvd" or "osv"). ``package_identifier`` is populated only for OSV-sourced
    (package-level) findings (Req 2.3, 7.1).
    """

    model_config = ConfigDict(frozen=True)

    machine_id: str
    cve_id: str
    #: ``None`` when the advisory publishes no score; see ``severity``, which
    #: is always set (Req 2.7).
    cvss_score: float | None
    severity: Severity
    source: str
    package_identifier: str | None = None


class MatchResult(BaseModel):
    """The outcome of matching one inventory against the data sources.

    Holds the produced findings plus the per-source reachability status. An
    unreachable (``None``) source is recorded as ``DATA_SOURCE_UNAVAILABLE``
    and contributes no findings, while matching still completes against the
    reachable source (Req 2.5).
    """

    model_config = ConfigDict(frozen=True)

    machine_id: str
    findings: list[Finding]
    nvd_status: SourceStatus
    osv_status: SourceStatus


_SOURCE_NVD = "nvd"
_SOURCE_OSV = "osv"


class Matcher:
    """Correlates collected inventory with public vulnerability data sources.

    OS inventory is matched against NVD and installed software against OSV.
    Each identified CVE becomes a ``Finding`` carrying its CVE id, CVSS score,
    derived severity, and the affected machine reference; OSV findings also
    carry the package identifier. A ``None`` (unreachable) client is skipped
    and recorded as ``DATA_SOURCE_UNAVAILABLE`` while matching continues
    against the reachable source (Req 2.1, 2.2, 2.3, 2.5, 7.1).
    """

    def match(
        self,
        inventory: Inventory,
        nvd: NvdClient | None,
        osv: OsvClient | None,
    ) -> MatchResult:
        """Produce findings for ``inventory`` from the reachable sources.

        Args:
            inventory: The normalized inventory for a single Target_Machine.
            nvd: The NVD client, or ``None`` if the source is unreachable.
            osv: The OSV client, or ``None`` if the source is unreachable.

        Returns:
            A ``MatchResult`` with the produced findings and the per-source
            reachability status.
        """
        machine_id = inventory.machine_id
        findings: list[Finding] = []

        if nvd is None:
            nvd_status = SourceStatus.DATA_SOURCE_UNAVAILABLE
        else:
            try:
                raw_cves = nvd.match_os(inventory.os_info)
                nvd_status = SourceStatus.OK
                for raw in raw_cves:
                    findings.append(
                        Finding(
                            machine_id=machine_id,
                            cve_id=raw.cve_id,
                            cvss_score=raw.cvss_score,
                            severity=resolve_severity(raw.cvss_score, raw.severity),
                            source=_SOURCE_NVD,
                            package_identifier=None,
                        )
                    )
            except _PROGRAMMING_ERRORS:
                _LOGGER.exception(
                    "NVD matching failed for %s due to a defect, not an outage",
                    machine_id,
                )
                raise
            except Exception:
                _LOGGER.exception(
                    "NVD unreachable for %s; recording DATA_SOURCE_UNAVAILABLE",
                    machine_id,
                )
                nvd_status = SourceStatus.DATA_SOURCE_UNAVAILABLE

        if osv is None:
            osv_status = SourceStatus.DATA_SOURCE_UNAVAILABLE
        else:
            try:
                raw_advisories = osv.match_packages(inventory.packages)
                osv_status = SourceStatus.OK
                for raw in raw_advisories:
                    findings.append(
                        Finding(
                            machine_id=machine_id,
                            cve_id=raw.cve_id,
                            cvss_score=raw.cvss_score,
                            severity=resolve_severity(raw.cvss_score, raw.severity),
                            source=_SOURCE_OSV,
                            package_identifier=raw.package_identifier,
                        )
                    )
            except _PROGRAMMING_ERRORS:
                _LOGGER.exception(
                    "OSV matching failed for %s due to a defect, not an outage",
                    machine_id,
                )
                raise
            except Exception:
                _LOGGER.exception(
                    "OSV unreachable for %s; recording DATA_SOURCE_UNAVAILABLE",
                    machine_id,
                )
                osv_status = SourceStatus.DATA_SOURCE_UNAVAILABLE

        return MatchResult(
            machine_id=machine_id,
            findings=findings,
            nvd_status=nvd_status,
            osv_status=osv_status,
        )
