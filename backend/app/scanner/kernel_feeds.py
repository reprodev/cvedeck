"""Kernel advisories for the distributions OSV's per-package lookup cannot answer.

Since 0.9.0 the kernel of Debian, RHEL and its rebuilds, SUSE and Alpine is
looked up in OSV with the rest of a host's packages, and since 0.10.0 Ubuntu's
in Canonical's own feed. Four distributions were left saying their kernel was
not checked; 0.15.0 checks three of them, each from the source that describes
the kernel they actually ship (researched and measured 2026-10-31):

- **Fedora and Arch (Req 12.12)** ship near-unmodified upstream stable kernels,
  so the upstream kernel CNA's own CVE records apply, keyed by upstream
  version. OSV carries them as the ``Linux`` ecosystem -- but its query
  returns nothing when asked for a version (asked for 5.4.268, which
  CVE-2024-26581 explicitly covers, it paged five times and answered zero), so
  the whole set is fetched, about 31,000 records in some 14 pages, and
  compared here. No new host: OSV is already the scanner's main source.
- **Oracle Linux (Req 12.13)** mostly runs the Unbreakable Enterprise Kernel,
  which keeps one version (5.15.0, 6.12.0) and backports fixes into it, so no
  upstream version describes it. Oracle's ELSA OVAL does, one file per
  release, for UEK and the Red Hat compatible kernel alike.
- **Amazon Linux 2023 (Req 12.14)** publishes its advisories as the
  ``updateinfo`` its own repositories carry -- what ``dnf updateinfo`` reads --
  naming the fixed build of each kernel series (``kernel``, ``kernel6.12``...).

Each is downloaded whole on the feed cadence and joined locally, like KEV,
EPSS and the Ubuntu feed; nothing about a host is sent. Oracle's and Amazon's
requests name the release, the one thing they reveal. Each parser accepts only
the shapes seen in the real data and raises :class:`KernelFeedFormatError` on
anything else, including a feed with no kernel advisories: a format change
must read as "not checked", never as a clean kernel.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import logging
import re
import zlib
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterable
from xml.etree import ElementTree as ET

import httpx

from app.enums import Severity
from app.scanner.http_bounds import MIB, request_limited
from app.scanner.rpm_version import compare as rpm_compare

_LOGGER = logging.getLogger(__name__)

#: OSV pages measured 9-13 MB each; a ceiling, not a budget.
_MAX_PAGE = 64 * MIB
#: The whole Linux set measured 14 pages; far past it means something changed.
_MAX_PAGES = 60
#: Oracle OL8 measured 5.8 MB compressed and 115 MB as XML; Amazon's updateinfo
#: 2 MB compressed. Ceilings against a broken or hostile response.
_MAX_DOWNLOAD = 64 * MIB
_MAX_DECOMPRESSED = 1024 * MIB

UPSTREAM = "upstream"
ORACLE = "oracle"
AMAZON = "amazon"


class KernelFeedFormatError(ValueError):
    """The feed did not look like the feed CveDeck was built against."""


@dataclass(frozen=True)
class KernelFeedEntry:
    """One CVE as one feed states it for one kernel stream.

    ``fixed`` is the build that fixed it (Oracle, Amazon). An upstream entry
    keeps the CNA's ranges instead, since which fix applies depends on the
    stable series of the kernel asked about.
    """

    cve_id: str
    severity: Severity
    score: float | None = None
    fixed: str | None = None
    #: Upstream only: ``(introduced, fixed, last_affected)`` per range.
    ranges: tuple[tuple[str | None, str | None, str | None], ...] = ()


@dataclass
class KernelFeedTable:
    """A feed's kernel advisories, by stream (``all``; ``kernel-uek:5.15.0``; ``kernel6.12``)."""

    feed: str
    streams: dict[str, list[KernelFeedEntry]] = field(default_factory=dict)

    @property
    def entries(self) -> int:
        return sum(len(rows) for rows in self.streams.values())


@dataclass(frozen=True)
class FetchResult:
    """What one feed's download produced."""

    #: ``None`` when nothing changed since ``digest`` was last stored.
    table: KernelFeedTable | None
    digest: str | None


def oracle_feed(release: str) -> str:
    return f"{ORACLE}:ol{release}"


def amazon_feed(release: str) -> str:
    return f"{AMAZON}:al{release}"


def feed_key(source: str, ecosystem: str | None) -> str | None:
    """The stored feed a host's kernel is checked against, or ``None`` if unknown.

    ``Fedora`` and ``Arch Linux`` share the one upstream table;
    ``Oracle Linux:9`` reads ``oracle:ol9``; ``Amazon Linux:2023`` reads
    ``amazon:al2023``.
    """
    eco = (ecosystem or "").strip()
    if source == UPSTREAM:
        return UPSTREAM
    if source == ORACLE:
        m = re.fullmatch(r"Oracle Linux:(\d+)", eco)
        return oracle_feed(m.group(1)) if m else None
    if source == AMAZON:
        m = re.fullmatch(r"Amazon Linux:(2023)(\.[\d.]+)?", eco)
        return amazon_feed(m.group(1)) if m else None
    return None


class _CappedReader(io.RawIOBase):
    """Decompress lazily, refusing to produce more than ``limit`` bytes."""

    def __init__(self, source: BinaryIO, limit: int) -> None:
        self._source = source
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self._source.read(len(buffer))
        self._read += len(data)
        if self._read > self._limit:
            raise KernelFeedFormatError(f"feed decompressed past {self._limit // MIB} MiB; refusing it")
        buffer[: len(data)] = data
        return len(data)


def _decompressed(raw: bytes, opener) -> io.BufferedReader:
    return io.BufferedReader(_CappedReader(opener(io.BytesIO(raw)), _MAX_DECOMPRESSED))


def _digest(table: KernelFeedTable) -> str:
    hasher = hashlib.sha256()
    for stream in sorted(table.streams):
        for row in sorted(table.streams[stream], key=lambda e: e.cve_id):
            hasher.update(repr((stream, row)).encode())
    return hasher.hexdigest()


# --- Upstream: the kernel CNA's records, through OSV (Req 12.12) -------------


_UPSTREAM_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _vkey(version: str) -> tuple[int, int, int]:
    m = _UPSTREAM_VERSION.match(version.strip())
    if not m:
        raise ValueError(f"not an upstream kernel version: {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def upstream_version(version: str) -> str | None:
    """The upstream kernel version a package version carries, or ``None``.

    ``6.19.10-300.fc44`` -> ``6.19.10``; ``7.2.11.arch1-1`` -> ``7.2.11``;
    ``6.18.60-1`` -> ``6.18.60``. An epoch is dropped.
    """
    bare = version.split(":", 1)[-1].strip()
    m = _UPSTREAM_VERSION.match(bare)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}.{m.group(3) or 0}"


def parse_upstream_records(records: Iterable[dict[str, Any]]) -> list[KernelFeedEntry]:
    """The CNA's kernel records as entries, ranges intact (Req 12.12).

    Only the ``Linux``/``Kernel`` package's ``ECOSYSTEM`` ranges are read; the
    ``GIT`` ranges beside them name commits, which no installed package can be
    compared with. A record with neither is skipped, as is one OSV withdrew.
    """
    from app.scanner.osv_client import parse_cvss
    from app.scanner.matcher import derive_severity

    entries: list[KernelFeedEntry] = []
    for record in records:
        cve_id = record.get("id")
        if not isinstance(cve_id, str) or record.get("withdrawn"):
            continue
        ranges: list[tuple[str | None, str | None, str | None]] = []
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            if package.get("ecosystem") != "Linux" or package.get("name") != "Kernel":
                continue
            for rng in affected.get("ranges") or []:
                if rng.get("type") != "ECOSYSTEM":
                    continue
                introduced: str | None = None
                for event in rng.get("events") or []:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    elif "fixed" in event:
                        ranges.append((introduced, event["fixed"], None))
                        introduced = None
                    elif "last_affected" in event:
                        ranges.append((introduced, None, event["last_affected"]))
                        introduced = None
                    else:
                        raise KernelFeedFormatError(f"{cve_id}: unrecognised range event {event!r}")
                if introduced is not None:
                    ranges.append((introduced, None, None))
        if not ranges:
            continue
        for bound in (b for r in ranges for b in r if b and b != "0"):
            try:
                _vkey(bound)
            except ValueError as exc:
                raise KernelFeedFormatError(f"{cve_id}: {exc}") from exc
        score, band = parse_cvss(record)
        severity = band or (derive_severity(score) if score is not None else Severity.UNSCORED)
        entries.append(KernelFeedEntry(cve_id, severity, score, None, tuple(ranges)))
    return entries


@dataclass(frozen=True)
class UpstreamVerdict:
    """How one upstream CVE stands for one kernel version."""

    entry: KernelFeedEntry
    #: The fix in the kernel's own stable series, when it has one.
    fixed: str | None
    #: Otherwise the earliest fix in a newer series, e.g. ``7.2.6``.
    fixed_elsewhere: str | None


def upstream_affecting(version: str, entries: Iterable[KernelFeedEntry]) -> list[UpstreamVerdict]:
    """The CVEs affecting upstream kernel ``version`` (Req 12.12, Property 21).

    The CNA's ranges overlap across stable series: "introduced 6.13, fixed
    6.19.6" also spans 6.18.x, whose own fix is 6.18.16. Read naively, a
    current 6.18 kernel carried 589 CVEs; it has 126. So when the kernel's own
    series (major.minor) lists a fix, that fix alone decides. Only otherwise --
    an end-of-life series, or a fix not backported -- do the ranges decide,
    and then the earliest fix in a newer series is what can be offered.
    """
    v = _vkey(version)
    out: list[UpstreamVerdict] = []
    for entry in entries:
        fixes = [f for _i, f, _l in entry.ranges if f]
        own = [f for f in fixes if _vkey(f)[:2] == v[:2]]
        if own:
            first = min(own, key=_vkey)
            if v < _vkey(first):
                out.append(UpstreamVerdict(entry, first, None))
            continue
        hit = False
        for introduced, fixed, last in entry.ranges:
            low = _vkey(introduced) if introduced and introduced != "0" else (0, 0, 0)
            if v < low:
                continue
            if fixed and v >= _vkey(fixed):
                continue
            if last and v > _vkey(last):
                continue
            hit = True
            break
        if hit:
            newer = [f for f in fixes if _vkey(f)[:2] > v[:2]]
            out.append(UpstreamVerdict(entry, None, min(newer, key=_vkey) if newer else None))
    return out


class UpstreamKernelFeedClient:
    """Fetches the kernel CNA's records from OSV, every page (Req 12.12)."""

    def __init__(
        self,
        api_url: str,
        *,
        timeout: float = 120.0,
        http_client: httpx.Client | None = None,
        max_pages: int = _MAX_PAGES,
    ) -> None:
        self._url = api_url.rstrip("/") + "/query"
        self._timeout = timeout
        self._http_client = http_client
        self._max_pages = max_pages

    def fetch(self, digest: str | None = None) -> FetchResult:
        """Download the whole set; ``table`` is ``None`` when it equals ``digest``.

        OSV's paging offers no conditional request, so the set is always
        downloaded; only an unchanged one is not rewritten. Raises on any
        transport or format failure, and on running past ``max_pages``.
        """
        client = self._http_client or httpx.Client(timeout=self._timeout)
        entries: list[KernelFeedEntry] = []
        token: str | None = None
        try:
            for _page in range(self._max_pages):
                body: dict[str, Any] = {"package": {"name": "Kernel", "ecosystem": "Linux"}}
                if token:
                    body["page_token"] = token
                response = request_limited(client, "POST", self._url, limit=_MAX_PAGE, json=body)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise KernelFeedFormatError("OSV answered with something other than an object")
                entries.extend(parse_upstream_records(data.get("vulns") or []))
                token = data.get("next_page_token")
                if not token:
                    break
            else:
                raise KernelFeedFormatError(f"still paging after {self._max_pages} pages; refusing it")
        finally:
            if self._http_client is None:
                client.close()
        if not entries:
            raise KernelFeedFormatError("no kernel advisories in OSV's Linux records")
        table = KernelFeedTable(UPSTREAM, {"all": entries})
        new = _digest(table)
        _LOGGER.info("Upstream kernel feed: %d entries", table.entries)
        return FetchResult(table=None if new == digest else table, digest=new)


# --- Oracle Linux: ELSA OVAL (Req 12.13) -------------------------------------


_O = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
_L = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}"
_ORACLE_KERNELS = {"kernel": "kernel", "kernel-core": "kernel", "kernel-uek": "kernel-uek", "kernel-uek-core": "kernel-uek"}
_ADVISORY_SEVERITY = {
    "critical": Severity.CRITICAL,
    "important": Severity.HIGH,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def advisory_severity(text: str | None) -> Severity:
    """An advisory's own rating; "N/A" or nothing is unscored, never guessed (Req 2.7)."""
    return _ADVISORY_SEVERITY.get((text or "").strip().lower(), Severity.UNSCORED)


def oracle_stream(name: str, evr: str) -> str | None:
    """``kernel-uek-core`` at ``0:5.15.0-325...el9uek`` -> ``kernel-uek:5.15.0``."""
    family = _ORACLE_KERNELS.get(name)
    if family is None:
        return None
    return f"{family}:{evr.split(':', 1)[-1].split('-', 1)[0]}"


def _keep_highest(rows: dict[str, KernelFeedEntry], entry: KernelFeedEntry) -> None:
    """One answer per CVE and stream: the highest fix any advisory names.

    A later advisory naming a CVE again means the earlier fix was not the
    whole fix; holding a host to the earlier one would read it cleaner than
    it is.
    """
    current = rows.get(entry.cve_id)
    if current is None or rpm_compare(_bare(entry.fixed or ""), _bare(current.fixed or "")) > 0:
        rows[entry.cve_id] = entry


def _bare(evr: str) -> str:
    return evr.split(":", 1)[-1]


def parse_oracle_oval(stream: BinaryIO, release: str) -> KernelFeedTable:
    """Stream Oracle's OVAL for one release into kernel entries by stream (Req 12.13).

    Only "less than" EVR tests on the kernel packages count, and only builds
    for this release: the OL9 file also carries EL10 builds (``.el10uek``),
    which would hold an OL9 host to fixes it cannot install.
    """
    objects: dict[str, str] = {}
    states: dict[str, str] = {}
    tests: dict[str, tuple[str | None, str | None]] = {}
    definitions: list[tuple[list[str], Severity, list[str]]] = []
    for _event, el in ET.iterparse(stream):
        tag = el.tag
        if tag == _L + "rpminfo_object":
            name = el.findtext(_L + "name")
            if name:
                objects[el.get("id", "")] = name
            el.clear()
        elif tag == _L + "rpminfo_state":
            evr = el.find(_L + "evr")
            if evr is not None and evr.get("operation") == "less than" and evr.text:
                states[el.get("id", "")] = evr.text.strip()
            el.clear()
        elif tag == _L + "rpminfo_test":
            obj = el.find(_L + "object")
            state = el.find(_L + "state")
            tests[el.get("id", "")] = (
                obj.get("object_ref") if obj is not None else None,
                state.get("state_ref") if state is not None else None,
            )
            el.clear()
        elif tag == _O + "definition":
            if el.get("class") == "patch":
                cves = [
                    r.get("ref_id", "")
                    for r in el.iter(_O + "reference")
                    if (r.get("source") or "").upper() == "CVE"
                ]
                severity = advisory_severity(el.findtext(f"{_O}metadata/{_O}advisory/{_O}severity"))
                refs = [c.get("test_ref", "") for c in el.iter(_O + "criterion")]
                definitions.append((cves, severity, refs))
            el.clear()
    if not definitions:
        raise KernelFeedFormatError(f"ol{release}: no advisories in the feed")
    dist = re.compile(rf"\.el{re.escape(release)}(?:_\d+)?(?:uek)?$")
    streams: dict[str, dict[str, KernelFeedEntry]] = {}
    for cves, severity, refs in definitions:
        for ref in refs:
            obj, state = tests.get(ref, (None, None))
            name = objects.get(obj or "")
            evr = states.get(state or "")
            if not name or not evr or name not in _ORACLE_KERNELS or not dist.search(evr):
                continue
            key = oracle_stream(name, evr)
            for cve in cves:
                _keep_highest(streams.setdefault(key, {}), KernelFeedEntry(cve, severity, None, evr))
    if not streams:
        raise KernelFeedFormatError(f"ol{release}: no kernel advisories in the feed")
    return KernelFeedTable(oracle_feed(release), {k: list(v.values()) for k, v in streams.items()})


class OracleKernelFeedClient:
    """Downloads one Oracle Linux release's ELSA OVAL (Req 12.13)."""

    def __init__(self, url_template: str, *, timeout: float = 120.0, http_client: httpx.Client | None = None) -> None:
        self._url_template = url_template
        self._timeout = timeout
        self._http_client = http_client

    def url_for(self, release: str) -> str:
        return self._url_template.format(release=release)

    def fetch(self, release: str, digest: str | None = None) -> FetchResult:
        """Download and parse, or report the file unchanged since ``digest`` (its ETag)."""
        client = self._http_client or httpx.Client(timeout=self._timeout)
        try:
            response = request_limited(
                client, "GET", self.url_for(release), limit=_MAX_DOWNLOAD,
                headers={"If-None-Match": digest} if digest else None,
            )
            if response.status_code == 304:
                return FetchResult(table=None, digest=digest)
            response.raise_for_status()
            table = parse_oracle_oval(_decompressed(response.content, bz2.BZ2File), release)
        finally:
            if self._http_client is None:
                client.close()
        _LOGGER.info("Oracle Linux %s kernel feed: %d streams, %d entries", release, len(table.streams), table.entries)
        return FetchResult(table=table, digest=response.headers.get("etag"))


# --- Amazon Linux 2023: repository updateinfo (Req 12.14) --------------------


_AMAZON_KERNEL = re.compile(r"kernel(\d+\.\d+)?")


def parse_amazon_updateinfo(stream: BinaryIO, release: str) -> KernelFeedTable:
    """Amazon's advisories, as the repository carries them, into kernel entries (Req 12.14).

    Each ``<update>`` is one ALAS advisory: a severity, its CVEs, and the fixed
    build of each package. A kernel series is its package name: ``kernel``
    (6.1), ``kernel6.12``, ``kernel6.18``.
    """
    streams: dict[str, dict[str, KernelFeedEntry]] = {}
    updates = 0
    for _event, el in ET.iterparse(stream):
        if el.tag != "update":
            continue
        updates += 1
        cves = [r.get("id", "") for r in el.iter("reference") if r.get("type") == "cve" and r.get("id")]
        severity = advisory_severity(el.findtext("severity"))
        for pkg in el.iter("package"):
            name = pkg.get("name") or ""
            if not _AMAZON_KERNEL.fullmatch(name) or pkg.get("arch") not in ("x86_64", "aarch64"):
                continue
            version, rel = pkg.get("version"), pkg.get("release")
            if not version or not rel:
                raise KernelFeedFormatError(f"{el.findtext('id')}: kernel package without a version")
            epoch = pkg.get("epoch")
            fixed = f"{epoch}:{version}-{rel}" if epoch and epoch != "0" else f"{version}-{rel}"
            for cve in cves:
                _keep_highest(streams.setdefault(name, {}), KernelFeedEntry(cve, severity, None, fixed))
        el.clear()
    if updates == 0 or not streams:
        raise KernelFeedFormatError(f"al{release}: no kernel advisories in updateinfo")
    return KernelFeedTable(amazon_feed(release), {k: list(v.values()) for k, v in streams.items()})


class AmazonKernelFeedClient:
    """Downloads Amazon Linux 2023's updateinfo through its mirror list (Req 12.14).

    The repository lives under a per-snapshot path, so the mirror list is read
    first, then ``repomd.xml``, which names the updateinfo file and its
    checksum -- kept as the digest, so an unchanged file is not fetched again.
    """

    def __init__(self, mirror_list_template: str, *, timeout: float = 120.0, http_client: httpx.Client | None = None) -> None:
        self._template = mirror_list_template
        self._timeout = timeout
        self._http_client = http_client

    def fetch(self, release: str, digest: str | None = None) -> FetchResult:
        client = self._http_client or httpx.Client(timeout=self._timeout)
        try:
            listing = request_limited(client, "GET", self._template.format(release=release), limit=MIB)
            listing.raise_for_status()
            base = next((line.strip() for line in listing.text.splitlines() if line.strip()), "")
            if not base.startswith("https://"):
                raise KernelFeedFormatError(f"al{release}: mirror list names no https repository")
            base = base if base.endswith("/") else base + "/"
            repomd = request_limited(client, "GET", base + "repodata/repomd.xml", limit=4 * MIB)
            repomd.raise_for_status()
            location, checksum = _updateinfo_location(repomd.content, release)
            if digest and checksum == digest:
                return FetchResult(table=None, digest=digest)
            data = request_limited(client, "GET", base + location, limit=_MAX_DOWNLOAD)
            data.raise_for_status()
            gunzip = location.endswith(".gz")
            table = parse_amazon_updateinfo(
                _decompressed(data.content, (lambda f: gzip.GzipFile(fileobj=f)) if gunzip else (lambda f: f)),
                release,
            )
        finally:
            if self._http_client is None:
                client.close()
        _LOGGER.info("Amazon Linux %s kernel feed: %d streams, %d entries", release, len(table.streams), table.entries)
        return FetchResult(table=table, digest=checksum)


def _updateinfo_location(repomd: bytes, release: str) -> tuple[str, str]:
    ns = "{http://linux.duke.edu/metadata/repo}"
    root = ET.fromstring(repomd)
    for data in root.iter(ns + "data"):
        if data.get("type") == "updateinfo":
            location = data.find(ns + "location")
            checksum = data.findtext(ns + "checksum")
            if location is not None and location.get("href") and checksum:
                return location.get("href", ""), checksum.strip()
    raise KernelFeedFormatError(f"al{release}: repomd.xml names no updateinfo")


def build_kernel_feed_sources(timeout: float) -> dict[str, Any]:
    """The clients for every kernel feed switched on, by source (Req 12.12-12.14).

    A feed switched off gets no client at all: nothing can fetch it.
    """
    from app import config

    sources: dict[str, Any] = {}
    if config.upstream_kernel_feed_enabled():
        sources[UPSTREAM] = UpstreamKernelFeedClient(config.osv_api_url(), timeout=timeout)
    if config.oracle_kernel_feed_enabled():
        sources[ORACLE] = OracleKernelFeedClient(config.oracle_kernel_feed_url(), timeout=timeout)
    if config.amazon_kernel_feed_enabled():
        sources[AMAZON] = AmazonKernelFeedClient(config.amazon_kernel_feed_url(), timeout=timeout)
    return sources


def feed_release(feed: str) -> str:
    """``oracle:ol9`` -> ``9``; ``amazon:al2023`` -> ``2023``."""
    return re.sub(r"^[a-z]+:(?:ol|al)", "", feed)


# --- Evaluation and storage ---------------------------------------------------


def rpm_affecting(installed_version: str, entries: Iterable[KernelFeedEntry]) -> list[KernelFeedEntry]:
    """The entries whose fixed build is newer than the installed one, by rpm ordering."""
    bare = _bare(installed_version)
    return [e for e in entries if e.fixed and rpm_compare(bare, _bare(e.fixed)) < 0]


def encode_streams(table: KernelFeedTable) -> dict[str, tuple[int, bytes]]:
    """The stored form: per stream, (entry count, zlib-compressed JSON rows)."""
    return {
        stream: (
            len(rows),
            zlib.compress(
                json.dumps(
                    [[e.cve_id, e.severity.value, e.score, e.fixed, [list(r) for r in e.ranges]] for e in rows],
                    separators=(",", ":"),
                ).encode(),
                6,
            ),
        )
        for stream, rows in table.streams.items()
    }


def decode_stream(payload: bytes) -> list[KernelFeedEntry]:
    """Read one stream's stored rows back."""
    return [
        KernelFeedEntry(cve, Severity(severity), score, fixed, tuple(tuple(r) for r in ranges))
        for cve, severity, score, fixed, ranges in json.loads(zlib.decompress(payload))
    ]
