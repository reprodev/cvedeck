"""Tests for OSV ecosystem resolution and Linux distribution coverage.

The central constraint here is not obvious from the code: OSV's ``/querybatch``
rejects the **entire batch** with HTTP 400 when a single query names an
ecosystem it does not recognize ("error in query at index N: invalid
ecosystem"). One bad name therefore does not degrade one lookup -- it defeats
batching for every package in that chunk and silently drops the scan to one
HTTP request per package per ecosystem.

``Arch Linux`` and ``Fedora`` were both in ``_ALL_LINUX_ECOSYSTEMS`` and are
both invalid, so the universal fallback never batched successfully.

These tests are offline; the ecosystem names were verified against the live API
and are pinned here so a future edit cannot reintroduce an invalid one.
"""

from __future__ import annotations

import pytest

from app.models import Package
from app.scanner.collectors import _parse_os_release
from app.scanner.osv_client import _ALL_LINUX_ECOSYSTEMS, OsvHttpClient

# Verified accepted by https://api.osv.dev/v1/query. Anything outside this set
# is rejected with HTTP 400 and fails its whole batch.
KNOWN_VALID_OSV_ECOSYSTEMS = {
    "Ubuntu",
    "Debian",
    "Red Hat",
    "Alpine",
    "openSUSE",
    "SUSE",
    "AlmaLinux",
    "Rocky Linux",
    "Wolfi",
    "Chainguard",
    "Mageia",
    "Photon OS",
}

# Confirmed rejected by the live API.
KNOWN_INVALID_OSV_ECOSYSTEMS = {"Arch Linux", "Fedora", "Oracle Linux", "Amazon Linux"}


def _base(ecosystem: str) -> str:
    """Strip a release suffix ("Ubuntu:22.04:LTS" -> "Ubuntu")."""
    return ecosystem.split(":", 1)[0]


def _resolve(ecosystem: str, version: str = "1.0.0") -> list[str]:
    return OsvHttpClient()._resolve_ecosystems(
        Package(name="openssl", version=version, ecosystem=ecosystem)
    )


# ---------------------------------------------------------------------------
# The invariant that matters
# ---------------------------------------------------------------------------


def test_universal_fallback_contains_only_valid_ecosystems():
    """A single invalid name here fails every batch that reaches the fallback."""
    invalid = [e for e in _ALL_LINUX_ECOSYSTEMS if e in KNOWN_INVALID_OSV_ECOSYSTEMS]
    assert not invalid, (
        f"{invalid} are not OSV ecosystems; including them makes /querybatch "
        "return HTTP 400 for the whole chunk"
    )
    assert set(_ALL_LINUX_ECOSYSTEMS) <= KNOWN_VALID_OSV_ECOSYSTEMS


@pytest.mark.parametrize(
    "ecosystem",
    [
        "Ubuntu:22.04:LTS",
        "Debian:12",
        "Red Hat",
        "AlmaLinux:9",
        "Rocky Linux:9",
        "Oracle Linux:9",
        "Amazon Linux:2023",
        "Fedora",
        "Arch Linux",
        "openSUSE",
        "SUSE:15.5",
        "Alpine:v3.20",
        "Wolfi",
        "unknown",
        "",
    ],
)
def test_every_resolution_yields_only_valid_ecosystems(ecosystem):
    """No input may resolve to a name OSV would reject."""
    for resolved in _resolve(ecosystem):
        assert _base(resolved) in KNOWN_VALID_OSV_ECOSYSTEMS, (
            f"{ecosystem!r} resolved to {resolved!r}, which OSV rejects"
        )


def test_resolution_never_returns_an_empty_list():
    """An empty list means the package is silently never checked at all."""
    for ecosystem in ("", "unknown", "generic", "linux", "Arch Linux", "Fedora"):
        assert _resolve(ecosystem), f"{ecosystem!r} resolved to nothing"


# ---------------------------------------------------------------------------
# Distribution mapping
# ---------------------------------------------------------------------------


def test_red_hat_is_queried_unversioned():
    """OSV accepts "Red Hat:9" but returns nothing for it.

    A version suffix here is worse than useless: the query succeeds, so nothing
    looks broken, and every finding is silently lost.
    """
    assert _resolve("Red Hat") == ["Red Hat"]
    assert _resolve("Red Hat:9") == ["Red Hat"]


def test_enterprise_linux_derivatives_reach_red_hat():
    """Oracle and Amazon have no OSV tracker; they inherit Red Hat advisories."""
    for ecosystem in ("Oracle Linux:9", "Amazon Linux:2023"):
        assert "Red Hat" in _resolve(ecosystem)


def test_almalinux_and_rocky_query_their_own_tracker_and_red_hat():
    assert _resolve("AlmaLinux:9") == ["AlmaLinux:9", "Red Hat"]
    assert _resolve("Rocky Linux:9") == ["Rocky Linux:9", "Red Hat"]


def test_arch_falls_back_rather_than_sending_an_invalid_name():
    assert _resolve("Arch Linux") == _ALL_LINUX_ECOSYSTEMS


# ---------------------------------------------------------------------------
# os-release parsing
# ---------------------------------------------------------------------------


def _os_release(**fields: str) -> str:
    return "\n".join(f'{k}="{v}"' for k, v in fields.items())


@pytest.mark.parametrize(
    "fields,expected_eco",
    [
        ({"ID": "ubuntu", "VERSION_ID": "22.04"}, "Ubuntu:22.04:LTS"),
        ({"ID": "debian", "VERSION_ID": "12"}, "Debian:12"),
        ({"ID": "almalinux", "VERSION_ID": "9.3"}, "AlmaLinux:9"),
        ({"ID": "rocky", "VERSION_ID": "9.3"}, "Rocky Linux:9"),
        ({"ID": "alpine", "VERSION_ID": "3.20.1"}, "Alpine:v3.20"),
        ({"ID": "rhel", "VERSION_ID": "9.3"}, "Red Hat"),
        # Newly covered distributions.
        ({"ID": "ol", "VERSION_ID": "9.3"}, "Oracle Linux:9"),
        ({"ID": "amzn", "VERSION_ID": "2023"}, "Amazon Linux:2023"),
        ({"ID": "sles", "VERSION_ID": "15.5"}, "SUSE:15.5"),
        ({"ID": "opensuse-leap", "VERSION_ID": "15.5"}, "openSUSE"),
        ({"ID": "raspbian", "VERSION_ID": "12"}, "Debian:12"),
    ],
)
def test_os_release_maps_distributions_to_ecosystems(fields, expected_eco):
    _os_info, eco = _parse_os_release(_os_release(**fields))
    assert eco == expected_eco


def test_unknown_distribution_does_not_masquerade_as_debian():
    """The old fallback was "deb", which produced confidently wrong matches.

    "unknown" routes to the universal fallback, which queries every canonical
    ecosystem instead of guessing one.
    """
    _os_info, eco = _parse_os_release(_os_release(ID="obscure-distro", VERSION_ID="1"))

    assert eco == "unknown"
    assert _resolve(eco) == _ALL_LINUX_ECOSYSTEMS


def test_id_like_is_used_when_the_id_itself_is_unrecognized():
    """A derivative names its parent in ID_LIKE; that is better than guessing."""
    _os_info, eco = _parse_os_release(
        _os_release(ID="pop", ID_LIKE="ubuntu debian", VERSION_ID="22.04")
    )
    assert eco == "Ubuntu:22.04:LTS"
