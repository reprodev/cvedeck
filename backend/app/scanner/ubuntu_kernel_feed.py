"""Canonical's OVAL CVE feed, for the one package OSV cannot answer: Ubuntu's kernel.

OSV's answer for an Ubuntu kernel is gigabytes -- every Ubuntu kernel advisory
lists every Ubuntu kernel flavour -- so 0.9.0 left it unchecked. Canonical
publishes the same tracker as OVAL, one file per release, regenerated daily:
``com.ubuntu.<codename>.cve.oval.xml.bz2``, about 12 MB for 22.04. It states,
per kernel flavour, either the version that fixed a CVE or that no fix exists
(Req 12.11).

Three things this module does differently from evaluating OVAL as written:

- **The flavour comes from the installed package, not from ``uname -r``.**
  Canonical identifies a flavour by a pattern on the release string, and the
  patterns overlap: ``linux`` and ``linux-riscv`` both match
  ``5.15.0-NN-generic``. Evaluated naively, every 22.04 host would carry the
  RISC-V kernel's CVEs as well as its own. The running image's source package
  (collected since 0.8.15) names the flavour exactly.
- **The installed package version is compared, not the uname fragment.** OVAL
  compares ``5.15.0-101`` (from ``uname -r``) with the fixed package version
  ``5.15.0-101.111``, so a host running exactly the fixed kernel reads as
  vulnerable. The running image's own package version is compared instead.
- **Only the shapes seen in the real feeds are accepted.** Surveyed over every
  flavour of 22.04 and 24.04: a flavour listed alone is vulnerable with no fix;
  a flavour beside "was vulnerable but has been fixed (note: 'V')" is fixed in
  V. Anything else fails the whole refresh, so a format change reads as "not
  checked", never as a clean kernel.

Downloaded whole on a cadence, like the KEV and EPSS feeds, and joined locally;
nothing about a host is sent. The request names the release, which is the one
thing it reveals.
"""

from __future__ import annotations

import bz2
import io
import logging
import re
from dataclasses import dataclass, field
from typing import BinaryIO
from xml.etree import ElementTree as ET

import httpx

from app.enums import Severity
from app.scanner.debian_version import compare
from app.scanner.http_bounds import MIB, request_limited

_LOGGER = logging.getLogger(__name__)

#: Measured 11.9 MB for 22.04, the largest; a ceiling, not a budget.
_MAX_DOWNLOAD = 64 * MIB
#: Measured 290 MB decompressed for 22.04. Guards against a decompression bomb.
_MAX_DECOMPRESSED = 1024 * MIB

#: Ubuntu releases by version, as a host's /etc/os-release reports them.
UBUNTU_CODENAMES: dict[str, str] = {
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
    "25.10": "questing",
    "26.04": "resolute",
}

_PRIORITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    # Canonical's lowest priority; there is no lower band to put it in.
    "negligible": Severity.LOW,
}

_O = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
_TITLE = re.compile(r"(CVE-\d{4}-\d+) on Ubuntu .+ - (\w+)$")
_RUNNING = re.compile(r"Is kernel '([^']+)' running\?$")
_FIXED = re.compile(r"kernel in \w+ was vulnerable but has been fixed \(note: '([^']+)'\)\.$")


class UbuntuFeedFormatError(ValueError):
    """The feed did not look like the feed CveDeck was built against."""


@dataclass(frozen=True)
class KernelAdvisory:
    """One CVE as it applies to one kernel flavour of one release."""

    cve_id: str
    severity: Severity
    #: The kernel version that fixed it, or ``None`` when no fix is released.
    fixed: str | None


@dataclass
class UbuntuKernelTable:
    """A release's kernel advisories, by flavour."""

    codename: str
    by_flavour: dict[str, list[KernelAdvisory]] = field(default_factory=dict)

    @property
    def entries(self) -> int:
        return sum(len(rows) for rows in self.by_flavour.values())


def codename_for(ecosystem: str | None) -> str | None:
    """``Ubuntu:22.04:LTS`` -> ``jammy``; ``None`` for anything else."""
    m = re.fullmatch(r"Ubuntu:(\d\d\.\d\d)(?::LTS)?", (ecosystem or "").strip())
    return UBUNTU_CODENAMES.get(m.group(1)) if m else None


class _CappedReader(io.RawIOBase):
    """Decompress lazily, refusing to produce more than ``limit`` bytes."""

    def __init__(self, raw: bytes, limit: int) -> None:
        self._source = bz2.BZ2File(io.BytesIO(raw))
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self._source.read(len(buffer))
        self._read += len(data)
        if self._read > self._limit:
            raise UbuntuFeedFormatError(
                f"feed decompressed past {self._limit // MIB} MiB; refusing it"
            )
        buffer[: len(data)] = data
        return len(data)


def parse_ubuntu_kernel_oval(stream: BinaryIO, codename: str) -> UbuntuKernelTable:
    """Stream an OVAL CVE feed into a table of kernel advisories (Req 12.11).

    Streamed and cleared as it goes: parsed whole, 22.04's file took 2 GB.
    Raises :class:`UbuntuFeedFormatError` on any shape it does not know, and on
    a feed with no kernel advisories at all -- an empty table would read as
    every kernel clean.
    """
    table = UbuntuKernelTable(codename=codename)
    seen: dict[str, dict[str, KernelAdvisory]] = {}
    vulnerability_definitions = 0
    for _event, el in ET.iterparse(stream):
        if el.tag != _O + "definition":
            continue
        if el.get("class") != "vulnerability":
            el.clear()
            continue
        vulnerability_definitions += 1
        title = el.findtext(f"{_O}metadata/{_O}title") or ""
        m = _TITLE.match(title)
        criteria = el.find(_O + "criteria")
        if not m or criteria is None:
            raise UbuntuFeedFormatError(f"unrecognised definition title: {title[:80]!r}")
        cve_id, priority = m.group(1), m.group(2).lower()
        severity = _PRIORITY.get(priority)
        if severity is None:
            raise UbuntuFeedFormatError(f"unrecognised priority {priority!r} for {cve_id}")
        for node in criteria.iter(_O + "criteria"):
            kids = [k for k in node if k.tag == _O + "criterion"]
            for kid in kids:
                running = _RUNNING.match(kid.get("comment") or "")
                if not running:
                    continue
                flavour = running.group(1)
                fixed: str | None = None
                if node.get("operator", "AND") == "AND":
                    others = [k for k in kids if k is not kid]
                    for other in others:
                        note = _FIXED.search(other.get("comment") or "")
                        if not note:
                            raise UbuntuFeedFormatError(
                                f"{cve_id}: unrecognised criterion beside kernel "
                                f"{flavour!r}: {(other.get('comment') or '')[:80]!r}"
                            )
                        fixed = note.group(1)
                advisory = KernelAdvisory(cve_id, severity, fixed)
                rows = seen.setdefault(flavour, {})
                # One answer per CVE and flavour; a stated fix outranks none.
                if cve_id not in rows or (rows[cve_id].fixed is None and fixed is not None):
                    rows[cve_id] = advisory
        el.clear()
    if vulnerability_definitions == 0 or not seen:
        raise UbuntuFeedFormatError(f"{codename}: no kernel advisories in the feed")
    table.by_flavour = {flavour: list(rows.values()) for flavour, rows in seen.items()}
    return table


@dataclass(frozen=True)
class FetchResult:
    """What one release's download produced."""

    #: ``None`` when the server said the file had not changed.
    table: UbuntuKernelTable | None
    etag: str | None


class UbuntuKernelFeedClient:
    """Downloads one release's OVAL CVE feed at a time."""

    def __init__(
        self,
        url_template: str,
        *,
        timeout: float = 120.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url_template = url_template
        self._timeout = timeout
        self._http_client = http_client

    def url_for(self, codename: str) -> str:
        return self._url_template.format(codename=codename)

    def fetch(self, codename: str, etag: str | None = None) -> FetchResult:
        """Download and parse, or report the file unchanged since ``etag``.

        Raises on any transport, size or format failure, so the caller keeps
        the previous table rather than replacing it with nothing.
        """
        url = self.url_for(codename)
        headers = {"If-None-Match": etag} if etag else None
        client = self._http_client or httpx.Client(timeout=self._timeout)
        try:
            response = request_limited(
                client, "GET", url, limit=_MAX_DOWNLOAD, headers=headers
            )
            if response.status_code == 304:
                return FetchResult(table=None, etag=etag)
            response.raise_for_status()
            table = parse_ubuntu_kernel_oval(
                io.BufferedReader(_CappedReader(response.content, _MAX_DECOMPRESSED)),
                codename,
            )
        finally:
            if self._http_client is None:
                client.close()
        _LOGGER.info(
            "Ubuntu %s kernel feed: %d flavours, %d entries",
            codename, len(table.by_flavour), table.entries,
        )
        return FetchResult(table=table, etag=response.headers.get("etag"))


def affecting(installed_version: str, advisories: list[KernelAdvisory]) -> list[KernelAdvisory]:
    """The advisories that apply to the running kernel image (Req 12.11).

    ``installed_version`` is the running image package's own version
    (``5.15.0-101.111``), not the fragment OVAL reads out of ``uname -r``
    (``5.15.0-101``). OVAL compares that fragment with the fixed package
    version, and ``5.15.0-101`` sorts before ``5.15.0-101.111``: a host running
    exactly the fixed kernel would be reported vulnerable. The package version
    is what the fix is stated in, so it is compared like with like.

    No fix released: it applies. A fix: it applies while the installed version
    is older, compared as dpkg does.
    """
    return [a for a in advisories if a.fixed is None or compare(installed_version, a.fixed) < 0]


def encode_flavours(table: UbuntuKernelTable) -> dict[str, tuple[int, bytes]]:
    """The stored form: per flavour, (entry count, zlib-compressed JSON rows)."""
    import json
    import zlib

    return {
        flavour: (
            len(rows),
            zlib.compress(
                json.dumps(
                    [[a.cve_id, a.severity.value, a.fixed] for a in rows],
                    separators=(",", ":"),
                ).encode(),
                6,
            ),
        )
        for flavour, rows in table.by_flavour.items()
    }


def decode_flavour(payload: bytes) -> list[KernelAdvisory]:
    """Read one flavour's stored rows back."""
    import json
    import zlib

    return [
        KernelAdvisory(cve_id=cve, severity=Severity(severity), fixed=fixed)
        for cve, severity, fixed in json.loads(zlib.decompress(payload))
    ]
