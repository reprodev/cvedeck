"""Fedora, Arch, Oracle Linux and Amazon Linux 2023 kernels, checked against their feeds.

Req 12.12-12.14. The tables are refreshed from the sources in
app.scanner.kernel_feeds and read here, locally: no network at scan time.

Unlike Ubuntu's feed, which keys on the running kernel, these state fixes by
package version, so **every installed kernel is assessed**, as OSV's lookup
does for Debian or RHEL. Each kernel's findings are reported against one of
its binaries -- the one named like its source when installed (``kernel``,
``kernel-uek``), otherwise the image itself -- and every image of that kernel
is recorded as assessed.

When a kernel cannot be checked the reason is said, never left as silence:
the feed is switched off or has not been fetched, the release is unknown, the
feed has nothing for that kernel, or the kernel is a flavour whose own patch
set no upstream record describes (Arch's ``linux-zen`` and ``linux-hardened``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.data.repository import FindingInput
from app.models import Inventory, Package
from app.package_identifier import is_kernel_image, kernel_feed_for

#: Why a kernel from one of these feeds was not checked; the dashboard words each.
FEED_OFF = "kernel_feed_off"
FEED_UNAVAILABLE = "kernel_feed_unavailable"
RELEASE_UNKNOWN = "kernel_release_unknown"
NOT_IN_FEED = "kernel_not_in_feed"
FLAVOUR_UNSUPPORTED = "kernel_flavour_unsupported"
NOT_YET_SCANNED = "kernel_not_yet_scanned"

#: The feed sources this module checks; Ubuntu has its own (app.services.ubuntu_kernel).
FEED_SOURCES = ("upstream", "oracle", "amazon")
#: Arch flavours carrying large patch sets of their own: an upstream record
#: describes the kernel they were built from, not what they ship.
UNSUPPORTED_FLAVOURS = frozenset({"linux-zen", "linux-hardened"})
_SOURCE_TAG = {"upstream": "kernel-cna", "oracle": "oracle-oval", "amazon": "amazon-alas"}


@dataclass
class KernelFeedCheck:
    """What checking one host's kernels against its feed produced."""

    #: ``None`` when at least one kernel was checked; otherwise why none was.
    reason: str | None
    findings: list[FindingInput] = field(default_factory=list)
    #: ``name@version`` of every kernel image assessed.
    assessed: list[str] = field(default_factory=list)


def feed_kernel_images(inventory: Inventory) -> list[Package]:
    """The host's kernel images, if one of these feeds covers its distribution."""
    return [
        p for p in inventory.packages
        if is_kernel_image(p.name) and kernel_feed_for(p.ecosystem) in FEED_SOURCES
    ]


def _family(name: str) -> str:
    """The binary named like a kernel's source: ``kernel-uek-core`` -> ``kernel-uek``."""
    return name[: -len("-core")] if name.endswith("-core") else name


def _series(version: str) -> str:
    return ".".join(version.split(".")[:2])


def check_feed_kernels(
    inventory: Inventory,
    repository,
    *,
    enabled: Callable[[str], bool],
    feed_usable: Callable[[str], bool],
) -> KernelFeedCheck | None:
    """Check every installed kernel against its distribution's feed, or say why not.

    ``None`` for a host none of these feeds covers. ``enabled(source)`` says
    whether a feed is switched on; ``feed_usable(feed)`` whether its stored
    table is fresh enough to answer from.
    """
    from app.scanner.kernel_feeds import (
        UPSTREAM,
        decode_stream,
        feed_key,
        oracle_stream,
        rpm_affecting,
        upstream_affecting,
        upstream_version,
    )

    images = feed_kernel_images(inventory)
    if not images:
        return None
    source = kernel_feed_for(images[0].ecosystem) or ""
    feed = feed_key(source, images[0].ecosystem)
    if feed is None:
        return KernelFeedCheck(reason=RELEASE_UNKNOWN)
    if not enabled(source):
        return KernelFeedCheck(reason=FEED_OFF)
    if not feed_usable(feed):
        return KernelFeedCheck(reason=FEED_UNAVAILABLE)
    supported = [p for p in images if p.name not in UNSUPPORTED_FLAVOURS]
    if not supported:
        return KernelFeedCheck(reason=FLAVOUR_UNSUPPORTED)

    # One kernel per family and version: RHEL-style hosts install kernel and
    # kernel-core side by side, one kernel between them.
    kernels: dict[tuple[str, str], list[Package]] = {}
    for p in supported:
        kernels.setdefault((_family(p.name), p.version), []).append(p)

    upstream_rows = None
    findings: list[FindingInput] = []
    assessed: list[str] = []
    for (family, version), members in sorted(kernels.items()):
        reported = next((p for p in members if p.name == family), sorted(members, key=lambda p: p.name)[0])
        base = f"{reported.ecosystem}:{reported.name}@{reported.version}"
        if source == UPSTREAM:
            upstream = upstream_version(version)
            if upstream is None:
                continue
            if upstream_rows is None:
                payload = repository.kernel_feed(feed, "all")
                upstream_rows = decode_stream(payload) if payload is not None else []
            for verdict in upstream_affecting(upstream, upstream_rows):
                entry = verdict.entry
                if verdict.fixed:
                    note = f" (fixed in {verdict.fixed})"
                elif verdict.fixed_elsewhere:
                    note = (
                        f" (no fix in Linux {_series(upstream)}; fixed only in "
                        f"Linux {_series(verdict.fixed_elsewhere)}: {verdict.fixed_elsewhere})"
                    )
                else:
                    note = ""
                findings.append(_finding(entry, source, base + note))
        else:
            stream = oracle_stream(reported.name, version) if source == "oracle" else reported.name
            payload = repository.kernel_feed(feed, stream) if stream else None
            if payload is None:
                continue
            for entry in rpm_affecting(version, decode_stream(payload)):
                findings.append(_finding(entry, source, f"{base} (fixed in {entry.fixed})"))
        assessed.extend(f"{p.name}@{p.version}" for p in members)

    if not assessed:
        return KernelFeedCheck(reason=NOT_IN_FEED)
    return KernelFeedCheck(reason=None, findings=findings, assessed=assessed)


def _finding(entry, source: str, package_identifier: str) -> FindingInput:
    return FindingInput(
        cve_id=entry.cve_id,
        # Oracle and Amazon rate advisories, not CVEs; the CNA scores few (Req 2.6).
        cvss_score=entry.score,
        severity=entry.severity,
        source=_SOURCE_TAG[source],
        package_identifier=package_identifier,
    )
