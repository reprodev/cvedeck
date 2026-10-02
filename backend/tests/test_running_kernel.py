"""Which installed kernel is the running one (Req 12.6).

The fixtures are CveDeck's own package command, run in containers with real
kernel packages installed; each release string below is the directory that
kernel installed under ``/lib/modules``, which is what ``uname -r`` prints
once it is booted. A container's own ``uname -r`` is its host's kernel, which
is exactly the case of a running kernel no installed package provides.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.package_identifier import is_kernel_package, kernel_image_release
from app.scanner.collectors import _parse_linux_packages

FIXTURES = Path(__file__).parent / "fixtures" / "packages"


def _kernels(name: str, ecosystem: str):
    text = (FIXTURES / f"{name}.tsv").read_text(encoding="utf-8")
    packages = _parse_linux_packages(text, default_ecosystem=ecosystem)
    return [p for p in packages if is_kernel_package(p.name, p.source_name)]


def _running(name: str, ecosystem: str, release: str) -> list[str]:
    return sorted(
        p.name for p in _kernels(name, ecosystem) if kernel_image_release(p.name, p.version, release)
    )


@pytest.mark.parametrize(
    "fixture, ecosystem, release, expected",
    [
        ("debian_12_kernel", "Debian:12", "6.1.0-53-amd64", ["linux-image-6.1.0-53-amd64"]),
        # Two kernels installed: the old one booted, the new one waiting.
        ("ubuntu_22.04_kernel", "Ubuntu:22.04:LTS", "5.15.0-25-generic", ["linux-image-5.15.0-25-generic"]),
        ("ubuntu_22.04_kernel", "Ubuntu:22.04:LTS", "5.15.0-198-generic", ["linux-image-5.15.0-198-generic"]),
        ("rockylinux_9_kernel", "Rocky Linux:9", "5.14.0-687.53.1.el9_8.x86_64", ["kernel-core"]),
        ("almalinux_9_kernel", "AlmaLinux:9", "5.14.0-687.52.1.el9_8.x86_64", ["kernel-core"]),
        # One source, two flavours: only the flavour booted is running.
        ("alpine_3.18_kernel", "Alpine:v3.18", "6.1.175-0-lts", ["linux-lts"]),
        ("alpine_3.18_kernel", "Alpine:v3.18", "6.1.175-0-virt", ["linux-virt"]),
        ("opensuse_leap_15.5_kernel", "openSUSE:Leap 15.5", "5.14.21-150500.55.88-default", ["kernel-default"]),
        ("archlinux_kernel", "Arch Linux", "7.2.7-arch1-1", ["linux"]),
    ],
)
def test_the_running_kernel_is_the_image_that_reports_its_release(fixture, ecosystem, release, expected):
    assert _running(fixture, ecosystem, release) == expected


@pytest.mark.parametrize(
    "fixture, ecosystem",
    [
        ("debian_12_kernel", "Debian:12"),
        ("ubuntu_22.04_kernel", "Ubuntu:22.04:LTS"),
        ("rockylinux_9_kernel", "Rocky Linux:9"),
        ("alpine_3.18_kernel", "Alpine:v3.18"),
        ("opensuse_leap_15.5_kernel", "openSUSE:Leap 15.5"),
        ("archlinux_kernel", "Arch Linux"),
    ],
)
def test_a_running_kernel_no_package_provides_matches_nothing(fixture, ecosystem):
    """A container, or a hand-built kernel: nothing installed is running (Req 12.6)."""
    assert _running(fixture, ecosystem, "6.6.87.2-microsoft-standard-WSL2") == []
    assert _running(fixture, ecosystem, "") == []


def test_a_metapackage_is_never_the_running_kernel():
    """linux-image-amd64 only depends on a kernel; it names no release."""
    assert not kernel_image_release("linux-image-amd64", "6.1.187-1", "6.1.0-53-amd64")
    assert not kernel_image_release("linux-image-generic", "5.15.0.198.171", "5.15.0-198-generic")


@pytest.mark.parametrize(
    "name, version, release, running",
    [
        # SUSE drops the rpm build counter and appends the flavour.
        ("kernel-default", "5.14.21-150500.55.39.1", "5.14.21-150500.55.39-default", True),
        ("kernel-default", "5.14.21-150500.55.3.1", "5.14.21-150500.55.39-default", False),
        ("kernel-default", "5.14.21-150500.55.39.1", "5.14.21-150500.55.39-azure", False),
        # Arch writes the version with a dot where uname has a dash.
        ("linux", "6.9.7.arch1-1", "6.9.7-arch1-1", True),
        ("linux", "6.9.7.arch1-1", "6.9.8-arch1-1", False),
        # An rpm epoch is not part of the release.
        ("kernel-core", "1:5.14.0-70.13.1.el9_0", "5.14.0-70.13.1.el9_0.x86_64", True),
        # A shared prefix is not the same kernel.
        ("kernel-core", "5.14.0-70.1.1.el9_0", "5.14.0-70.13.1.el9_0.x86_64", False),
    ],
)
def test_release_comparison_per_package_manager(name, version, release, running):
    assert kernel_image_release(name, version, release) is running


def test_firmware_is_not_the_kernel():
    """linux-firmware shares a prefix and nothing else (Req 12.5)."""
    names = {p.name for p in _kernels("alpine_3.18_kernel", "Alpine:v3.18")}
    assert names == {"linux-lts", "linux-virt"}
