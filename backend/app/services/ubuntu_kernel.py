"""An Ubuntu host's running kernel, checked against Canonical's feed (Req 12.11).

Every other kernel is looked up in OSV during the scan. Ubuntu's is looked up
in the table refreshed from Canonical's OVAL feed (app.scanner.ubuntu_kernel_feed),
locally: no network at scan time.

Only the *running* kernel is checked. The feed states fixes per flavour, and
the flavour of a kernel nobody booted could be judged, but Canonical's own
evaluation is of the running kernel, and that is the claim this makes. A
kernel installed and not running is said to be not assessed.

When the kernel cannot be checked the reason is said, never left as silence:
the feed is switched off, has not been fetched, is stale, the release is
unknown or out of support, the host did not say which kernel it runs, or the
running kernel comes from no installed package.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.data.repository import FindingInput
from app.models import Inventory, Package
from app.package_identifier import advisory_source, is_kernel_image, kernel_image_release

#: Interim releases whose support has ended. Their feeds are frozen at the end
#: of support, so a CVE published since is absent -- not fixed. Checked against
#: such a feed the kernel would read cleaner than it is, so it is not checked.
UBUNTU_END_OF_LIFE = frozenset({"oracular", "plucky"})

#: Why an Ubuntu kernel was not checked; the dashboard words each one.
FEED_OFF = "ubuntu_feed_off"
FEED_UNAVAILABLE = "ubuntu_feed_unavailable"
RELEASE_UNKNOWN = "ubuntu_release_unknown"
RELEASE_END_OF_LIFE = "ubuntu_release_end_of_life"
RUNNING_UNKNOWN = "ubuntu_running_kernel_unknown"
RUNNING_NOT_INSTALLED = "ubuntu_running_kernel_not_installed"
FLAVOUR_UNKNOWN = "ubuntu_kernel_flavour_unknown"
NOT_YET_SCANNED = "ubuntu_not_yet_scanned"


@dataclass
class UbuntuKernelCheck:
    """What checking one host's Ubuntu kernel produced."""

    #: ``None`` when it was checked; otherwise why not.
    reason: str | None
    findings: list[FindingInput] = field(default_factory=list)
    #: ``name@version`` of the kernel that was checked, when one was.
    assessed: str | None = None


def ubuntu_kernel_images(inventory: Inventory) -> list[Package]:
    """The host's kernel images, if it is an Ubuntu host."""
    return [
        p
        for p in inventory.packages
        if is_kernel_image(p.name) and (p.ecosystem or "").startswith("Ubuntu")
    ]


def check_ubuntu_kernel(
    inventory: Inventory,
    repository,
    *,
    enabled: bool,
    feed_usable,
) -> UbuntuKernelCheck | None:
    """Check the running Ubuntu kernel, or say why it was not (Req 12.11).

    ``None`` for a host with no Ubuntu kernel image, which this has nothing to
    say about. ``feed_usable(codename)`` says whether the stored table for a
    release is fresh enough to answer from.
    """
    from app.scanner.ubuntu_kernel_feed import affecting, codename_for, decode_flavour

    images = ubuntu_kernel_images(inventory)
    if not images:
        return None
    codename = codename_for(images[0].ecosystem)
    if codename is None:
        return UbuntuKernelCheck(reason=RELEASE_UNKNOWN)
    if not enabled:
        return UbuntuKernelCheck(reason=FEED_OFF)
    if codename in UBUNTU_END_OF_LIFE:
        return UbuntuKernelCheck(reason=RELEASE_END_OF_LIFE)
    if not feed_usable(codename):
        return UbuntuKernelCheck(reason=FEED_UNAVAILABLE)
    release = (inventory.kernel_version or "").strip()
    if not release:
        return UbuntuKernelCheck(reason=RUNNING_UNKNOWN)
    running = [p for p in images if kernel_image_release(p.name, p.version, release)]
    if not running:
        return UbuntuKernelCheck(reason=RUNNING_NOT_INSTALLED)
    image = running[0]
    # The flavour from the package, never from uname: linux and linux-riscv
    # share a uname pattern on 22.04.
    flavour = advisory_source(image)[0] if image.source_name else None
    payload = repository.ubuntu_kernel_feed(codename, flavour) if flavour else None
    if payload is None:
        return UbuntuKernelCheck(reason=FLAVOUR_UNKNOWN)

    base = f"{image.ecosystem}:{image.name}@{image.version}"
    findings = [
        FindingInput(
            cve_id=advisory.cve_id,
            # Canonical publishes a priority, not a score (Req 2.6).
            cvss_score=None,
            severity=advisory.severity,
            source="ubuntu-oval",
            package_identifier=base if advisory.fixed is None else f"{base} (fixed in {advisory.fixed})",
        )
        for advisory in affecting(image.version, decode_flavour(payload))
    ]
    return UbuntuKernelCheck(reason=None, findings=findings, assessed=f"{image.name}@{image.version}")
