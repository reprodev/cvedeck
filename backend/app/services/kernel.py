"""A host's kernels as the dashboard shows them (Req 12.5, 12.6, 12.8).

The kernel is the one package where *installed* and *in use* part ways: a host
can have the fixed kernel on disk and still be running the vulnerable one it
booted from, and can keep old kernels it never boots again. So each installed
kernel is told apart as running or not, from the ``uname -r`` collected with
the inventory, and the fix for a kernel finding is a reboot, an upgrade and a
reboot, or the removal of a kernel nothing runs.

Derived when read, from the same inventory the findings were matched against,
so it can never disagree with them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.data.repository import FindingInput
from app.models import Inventory
from app.package_identifier import (
    finding_package,
    is_kernel_image,
    is_kernel_metapackage,
    is_kernel_package,
    kernel_image_release,
    kernel_is_matched,
    parse_fix,
    parse_package_name,
)


@dataclass(frozen=True)
class InstalledKernel:
    """One installed kernel image."""

    package: str
    version: str
    #: ``None`` when the host did not report its running kernel release.
    running: bool | None
    #: The highest version installed: what a reboot would most likely boot.
    newest: bool
    #: CVEs in this kernel with no fix in the host's release, counted rather
    #: than listed (Req 12.9). ``None`` when not assessed.
    unfixed: UnfixedCount | None = None


@dataclass(frozen=True)
class KernelView:
    """A host's kernels, and whether the running one is among them."""

    #: What ``uname -r`` printed, or ``None`` when the host did not say.
    release: str | None
    #: Whether this host's kernel was looked up at all (Req 12.5).
    checked: bool
    #: ``None`` when the release is unknown or no kernel is installed;
    #: ``False`` for a container or a hand-built kernel -- the running kernel
    #: then comes from no package, and nothing here was checked for it.
    running_installed: bool | None
    reboot_required: bool | None
    installed: list[InstalledKernel] = field(default_factory=list)
    #: What to upgrade to get a newer kernel. On Debian and Ubuntu that is the
    #: metapackage: a fixed kernel arrives as a new package
    #: (``linux-image-6.1.0-54-amd64``), so upgrading the old one does nothing.
    upgrade_packages: list[str] = field(default_factory=list)

    def running_for(self, packages: Iterable[str], version: str | None = None) -> bool | None:
        """Whether a finding on these binaries is in the running kernel (Req 12.6).

        True if any of them is the running image -- one source can build
        several flavours, and Alpine's ``linux-virt`` is built from
        ``linux-lts``. ``version`` is the one the finding names: on RPM and
        SUSE every installed kernel is called ``kernel-core`` or
        ``kernel-default``, and only the version tells them apart. ``None``
        when none of them is a kernel image, or the running release is
        unknown: the finding may be in the running kernel.
        """
        names = set(packages)
        mine = [k for k in self.installed if k.package in names]
        if version is not None and any(k.version == version for k in mine):
            mine = [k for k in mine if k.version == version]
        if not mine or self.release is None:
            return None
        return any(k.running for k in mine)


def _version_key(version: str) -> tuple:
    """Order kernel versions installed side by side on one host.

    Natural order is enough here: the versions compared are all one
    distribution's builds of one kernel series (6.1.187-1 against 6.1.180-1,
    5.14.0-687.53.1.el9_8 against 5.14.0-687.52.1.el9_8).
    """
    bare = version.split(":", 1)[-1]
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in re.findall(r"\d+|[a-z]+", bare.lower())
    )


def kernel_view(
    inventory: Inventory, unfixed: dict[str, UnfixedCount] | None = None
) -> KernelView:
    """The kernels of the host ``inventory`` was collected from.

    ``unfixed`` is what the scan of that inventory counted rather than listed,
    or ``None`` if it counted nothing because the kernel was not looked up.
    """
    release = (inventory.kernel_version or "").strip() or None
    kernels = [p for p in inventory.packages if is_kernel_package(p.name, p.source_name)]
    images = [p for p in kernels if is_kernel_image(p.name)]

    newest_key = max((_version_key(p.version) for p in images), default=None)
    installed = [
        InstalledKernel(
            package=p.name,
            version=p.version,
            running=None if release is None else kernel_image_release(p.name, p.version, release),
            newest=_version_key(p.version) == newest_key,
            unfixed=(
                None if unfixed is None else unfixed.get(f"{p.name}@{p.version}", UnfixedCount())
            ),
        )
        for p in sorted(images, key=lambda p: (_version_key(p.version), p.name), reverse=True)
    ]

    metapackages = sorted({p.name for p in kernels if is_kernel_metapackage(p.name)})
    debian_family = any(p.name.startswith("linux-image-") for p in images)
    if debian_family:
        upgrade = [m for m in metapackages if m.startswith("linux-image-")]
    else:
        upgrade = sorted({p.name for p in images})

    return KernelView(
        release=release,
        checked=bool(images) and all(kernel_is_matched(p.ecosystem) for p in images),
        running_installed=(
            None if release is None or not installed else any(k.running for k in installed)
        ),
        reboot_required=inventory.reboot_required,
        installed=installed,
        upgrade_packages=upgrade,
    )


@dataclass
class UnfixedCount:
    """Kernel CVEs in one installed kernel with no fix in the host's release."""

    #: No fix published anywhere yet.
    no_fix: int = 0
    #: Fixed only in another release, by release label ("Debian 13").
    elsewhere: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return self.no_fix + sum(self.elsewhere.values())


def split_kernel_findings(
    findings: Sequence[FindingInput],
) -> tuple[list[FindingInput], dict[str, UnfixedCount]]:
    """Which kernel CVEs are listed as findings, and which are counted (Req 12.9).

    Measured on live OSV: an up-to-date Debian 12 kernel matches 2,319 kernel
    CVEs, none fixable in Debian 12 -- 2,187 fixed only in Debian 13, 132 fixed
    nowhere -- and Debian publishes no severity for any of them. As rows they
    are thousands of findings nobody on that host can act on, burying the ones
    they can. So a kernel CVE is a finding when the host's release has a fix
    for it, or when it is known exploited, and is otherwise counted, per
    installed kernel (``name@version``), for the machine page to state.

    Counted only when it was checked against the KEV catalogue and is not in
    it: an unenriched finding might be exploited, and an exploited CVE must
    never be reduced to a number (the enrichment invariant). Userland findings
    are untouched.
    """
    kept: list[FindingInput] = []
    counts: dict[str, UnfixedCount] = {}
    for finding in findings:
        name = parse_package_name(finding.package_identifier)
        if not name or not is_kernel_package(name):
            kept.append(finding)
            continue
        status, release, _version = parse_fix(finding.package_identifier)
        if status == "available" or finding.kev_listed is not False:
            kept.append(finding)
            continue
        key = finding_package(finding.package_identifier) or name
        count = counts.setdefault(key, UnfixedCount())
        if status in ("newer_release", "upstream") and release:
            count.elsewhere[release] = count.elsewhere.get(release, 0) + 1
        else:
            count.no_fix += 1
    return kept, counts


def encode_unfixed(counts: dict[str, UnfixedCount]) -> str:
    """The stored form of :func:`split_kernel_findings`' counts."""
    return json.dumps(
        {key: {"no_fix": c.no_fix, "elsewhere": c.elsewhere} for key, c in sorted(counts.items())},
        sort_keys=True,
    )


def decode_unfixed(text: str | None) -> dict[str, UnfixedCount] | None:
    """``None`` when nothing was stored: not assessed, which is not zero."""
    if text is None:
        return None
    try:
        raw = json.loads(text)
    except ValueError:
        return None
    return {
        key: UnfixedCount(
            no_fix=int(value.get("no_fix", 0)),
            elsewhere={str(k): int(v) for k, v in (value.get("elsewhere") or {}).items()},
        )
        for key, value in raw.items()
        if isinstance(value, dict)
    }
