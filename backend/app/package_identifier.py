"""Parse a finding's ``package_identifier`` back into its package name (Req 14.5).

The matcher writes identifiers as ``<ecosystem>:<name>@<version>``, optionally
followed by `` (fixed in <version>)``. Every one of those parts except the name
can itself contain a colon:

- the ecosystem is often versioned -- ``Debian:13``, ``Ubuntu:22.04:LTS``;
- a Debian or RPM version can carry an epoch -- ``@1:2.38-4``;
- and one ecosystem name contains a space -- ``Red Hat:openssl@...``.

So the name is found from the right, not the left: drop the ``(fixed in ...)``
note, drop everything from the last ``@``, then take what follows the last
``:``. The note is cut at its own marker rather than at the first space, which
would have reduced every Red Hat identifier to ``Red``. Splitting on the first colon,
as this used to, turned ``Debian:13:openssl@3.5.1`` into ``13:openssl``, and the
host's fix plan then asked apt to upgrade forty-two packages that do not exist.

A package name contains no ``@`` except as an npm scope's leading character, and
no ``:`` in the OS ecosystems CveDeck matches, so reading from the right is
unambiguous for every identifier the matcher produces.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import Package


def parse_package_name(package_identifier: str | None) -> str | None:
    """The bare package name, or ``None`` when there is none to extract."""
    if not package_identifier or not package_identifier.strip():
        return None
    token = package_identifier.strip()
    note = token.find(" (")
    if note != -1:
        token = token[:note]
    at = token.rfind("@")
    # An "@" at the start of the name part is an npm scope, not a version.
    if at > 0 and token[at - 1] != ":":
        token = token[:at]
    name = token.rsplit(":", 1)[-1].strip()
    return name or None


def parse_package_version(package_identifier: str | None) -> str | None:
    """The installed version a finding names, or ``None`` when it names none."""
    if not package_identifier or not package_identifier.strip():
        return None
    token = package_identifier.strip()
    note = token.find(" (")
    if note != -1:
        token = token[:note]
    at = token.rfind("@")
    if at <= 0 or token[at - 1] == ":":
        return None
    return token[at + 1 :].strip() or None


def finding_package(package_identifier: str | None) -> str | None:
    """What a finding is *in*: the package name, and for a kernel its version too.

    A finding is the same finding from scan to scan while its CVE and package
    name are (Req 18.2): a package upgraded to a version that is still
    vulnerable is one unresolved problem, not one resolved and one new.

    The kernel is the exception. RPM and SUSE install each kernel beside the
    last under one name -- two ``kernel-core`` packages at two versions -- so
    the name alone would merge a CVE in the running kernel with the same CVE in
    an old one nothing boots, and report it against whichever came first
    (Req 12.6). Each installed kernel is its own package here. dpkg already
    names each kernel by its release, so this changes nothing there.
    """
    name = parse_package_name(package_identifier)
    if name is None or not is_kernel_package(name):
        return name
    version = parse_package_version(package_identifier)
    return name if version is None else f"{name}@{version}"


_ELSEWHERE = re.compile(r"\(no fix in (?P<host>.+?); fixed only in (?P<label>.+): (?P<version>\S+)\)\s*$")
_UPSTREAM = re.compile(r"\(not confirmed for this release; upstream fix in (?P<label>.+): (?P<version>\S+)\)\s*$")
_AVAILABLE = re.compile(r"\(fixed in (?P<version>[^)\s]+)\)\s*$")


def parse_fix(
    package_identifier: str | None,
) -> tuple[str | None, str | None, str | None]:
    """How a finding can be fixed, from the note the matcher wrote (Req 14.7, 14.8).

    Returns ``(status, release, version)``:

    - ``("available", None, V)`` -- the host's own release ships V.
    - ``("newer_release", "Debian 14", V)`` -- only a newer release (or a
      subscription stream such as Ubuntu Pro) ships a fix. Upgrading packages
      cannot clear it.
    - ``("upstream", "RHEL 9", V)`` -- a fix exists, but the host's release could
      not be matched to the advisory, so whether it is available is unconfirmed.
    - ``("none", None, None)`` -- no fix is published.
    - ``(None, None, None)`` -- there is no package identifier to read, which
      is every kernel and OS-level advisory. "No fix is published" would be a
      claim about a vendor nobody asked (Req 14.9).
    """
    text = (package_identifier or "").strip()
    if not text:
        return None, None, None
    if m := _AVAILABLE.search(text):
        return "available", None, m.group("version")
    if m := _ELSEWHERE.search(text):
        return "newer_release", m.group("label"), m.group("version")
    if m := _UPSTREAM.search(text):
        return "upstream", m.group("label"), m.group("version")
    return "none", None, None


# Binary and source names of the kernel, across the package managers CveDeck
# reads. Anything built from the kernel's source counts -- on Debian that
# includes ``linux-libc-dev``, whose advisories are the kernel's -- and nothing
# else: ``linux-base`` is its own small source, matched like any other package.
_KERNEL_BINARY_PREFIXES = (
    "linux-image-",
    "linux-headers-",
    "linux-modules-",
    "linux-kbuild-",
    "kernel-core",
    "kernel-modules",
)
_KERNEL_BINARIES = frozenset({"kernel", "kernel-default", "linux-lts", "linux-virt", "linux"})
_KERNEL_SOURCES = frozenset({"linux", "kernel", "kernel-default", "linux-lts", "linux-virt"})


def is_kernel_package(name: str, source_name: str | None = None) -> bool:
    """Whether a package is the kernel itself (Req 12.5).

    Decides *kernel or userland*: which section a finding is shown in, and
    which lookups are kept apart so the kernel's cannot fail the rest
    (Req 12.7). Whether the kernel is looked up at all is
    :func:`kernel_is_matched`.
    """
    lowered = name.lower()
    source = (source_name or "").lower()
    if lowered in _KERNEL_BINARIES or lowered.startswith(_KERNEL_BINARY_PREFIXES):
        return True
    return source in _KERNEL_SOURCES or source.startswith(("linux-signed", "linux-rpi"))


#: Kernel images that are not ``linux-image-*``: the binaries that *are* a
#: kernel on rpm, apk and pacman systems, by exact name, so that
#: ``kernel-default-devel`` or ``linux-lts-dev`` is not mistaken for one.
_KERNEL_IMAGES = frozenset({
    "kernel", "kernel-core", "kernel-rt-core", "kernel-64k-core",
    "kernel-default", "kernel-preempt", "kernel-rt", "kernel-azure",
    "linux", "linux-lts", "linux-virt", "linux-edge", "linux-rpi",
})


def is_kernel_image(name: str) -> bool:
    """Whether a binary is a kernel itself (Req 12.6).

    As opposed to its headers, build tools, modules or a metapackage that only
    depends on one. Kernel findings are reported against an image, so they
    read as the kernel's and can be matched to the one running.
    """
    for prefix in ("linux-image-unsigned-", "linux-image-"):
        if name.startswith(prefix):
            # A real image names its release (linux-image-6.1.0-53-amd64); a
            # metapackage names a flavour (linux-image-amd64, -686-pae).
            return _NAMES_A_RELEASE.match(name[len(prefix) :]) is not None
    return name in _KERNEL_IMAGES


_NAMES_A_RELEASE = re.compile(r"\d+\.\d+")


def is_kernel_metapackage(name: str) -> bool:
    """``linux-image-amd64``, ``linux-headers-generic``: depends on a kernel, is none."""
    for prefix in ("linux-image-unsigned-", "linux-image-", "linux-headers-"):
        if name.startswith(prefix):
            return _NAMES_A_RELEASE.match(name[len(prefix) :]) is None
    return False


#: Distributions whose kernel is looked up in OSV (Req 12.5). Measured against
#: live OSV for an old kernel on each: Debian 12's ``linux`` is 5 pages and 56
#: MB, Rocky, Alma, RHEL, SUSE and Alpine a page or two. Ubuntu's is not here:
#: its kernel advisories each list every Ubuntu kernel flavour, about 470 KB
#: apiece, and the 22.04 answer was still paging at 3.5 GB. Nor are hosts
#: resolved onto a guessed tracker (Arch, Fedora, Oracle, Amazon, a bare
#: ``deb``): their kernel is built differently from the one advisories describe.
_KERNEL_MATCHED_FAMILIES = (
    "Debian",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
    "SUSE",
    "openSUSE",
    "Alpine",
)


def kernel_is_matched(ecosystem: str | None) -> bool:
    """Whether CveDeck looks up the kernel of a host in ``ecosystem`` (Req 12.5).

    Where it does not, each such host says its kernel was not checked, and why,
    rather than show a kernel with no findings as a clean one.
    """
    eco = (ecosystem or "").strip()
    return any(eco == f or eco.startswith(f + ":") for f in _KERNEL_MATCHED_FAMILIES)


def _without_epoch(version: str) -> str:
    return version.split(":", 1)[1] if ":" in version else version


def kernel_image_release(name: str, version: str, release: str) -> bool:
    """Whether the kernel image ``name`` at ``version`` is the one reporting ``release``.

    ``release`` is what the host's ``uname -r`` printed (Req 12.6). Each
    package manager names a kernel differently, so each is compared in its own
    way, checked against real package lists in tests/fixtures/packages:

    - dpkg: ``linux-image-6.1.0-53-amd64`` reports ``6.1.0-53-amd64``.
    - rpm (RHEL, Rocky, Alma): ``kernel-core`` 5.14.0-687.53.1.el9_8 reports
      ``5.14.0-687.53.1.el9_8.x86_64``.
    - rpm (SUSE): ``kernel-default`` 5.14.21-150500.55.39.1 reports
      ``5.14.21-150500.55.39-default``.
    - apk: ``linux-lts`` 6.1.27-r0 reports ``6.1.27-0-lts``.
    - pacman: ``linux`` 6.9.7.arch1-1 reports ``6.9.7-arch1-1``.

    A metapackage (``linux-image-amd64``) is no kernel and matches nothing.
    """
    release = release.strip()
    if not release:
        return False
    for prefix in ("linux-image-unsigned-", "linux-image-"):
        if name.startswith(prefix):
            return name[len(prefix) :] == release
    bare = _without_epoch(version)
    if name in ("kernel-core", "kernel"):
        return release == bare or release.startswith(bare + ".")
    if name.startswith("kernel-") and release.endswith("-" + name[len("kernel-") :]):
        stem = release[: -len(name[len("kernel-") :]) - 1]
        return bare == stem or bare.startswith(stem + ".")
    if name.startswith("linux-") and "-r" in bare:
        upstream, _, rev = bare.rpartition("-r")
        return release == f"{upstream}-{rev}-{name[len('linux-'):]}"
    if name == "linux":
        return release == bare.replace(".arch", "-arch")
    return False


#: Debian's signed-image sources, one per architecture. Their images are the
#: ``linux`` source's build, signed, and OSV keys their advisories by ``linux``.
_DEBIAN_SIGNED_ARCHES = frozenset({"amd64", "arm64", "i386"})


def _kernel_source(source: str) -> str:
    """The name OSV keys a kernel's advisories by (Req 12.5).

    A signed kernel image is built from a ``linux-signed*`` source that only
    wraps the real one -- Debian's ``linux-signed-amd64``, Ubuntu's
    ``linux-signed-hwe-6.5`` -- and has no advisories of its own. Asking under
    it finds nothing, and would split each CVE between the image and the
    headers built from ``linux`` itself.
    """
    if not source.startswith("linux-signed"):
        return source
    rest = source[len("linux-signed") :].lstrip("-")
    if not rest or rest in _DEBIAN_SIGNED_ARCHES:
        return "linux"
    return f"linux-{rest}"


def advisory_source(pkg: Package) -> tuple[str, str]:
    """The name and version a package's advisories are published under (Req 2.8, 12.5).

    The binary's source at the source's version; the binary itself when no
    source was reported (an inventory from before 0.8.15). A signed kernel
    image is the source it wraps, at the image's own version: Debian's signed
    source is versioned ``6.1.187+1`` for a ``linux`` build at ``6.1.187-1``.

    Binaries with the same answer are one source: the matcher reports their
    findings once, and the dashboard lists them together, by this one rule.
    """
    if not pkg.source_name:
        return pkg.name, pkg.version
    if pkg.source_name.startswith("linux-signed"):
        return _kernel_source(pkg.source_name), pkg.version
    return pkg.source_name, pkg.source_version or pkg.version
