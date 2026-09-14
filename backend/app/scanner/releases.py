"""Distribution releases: what a host runs, and which release an advisory fixes.

Req 14.7, 14.8.

OSV describes most Linux vulnerabilities once per distribution *release*: one
advisory carries a separate affected entry for ``Debian:12``, ``Debian:13`` and
``Debian:14``, each with its own fixed version, or none. Two mistakes followed
from treating a distribution as one thing, both found on a Debian 13 host:

- **Asking OSV about ``Debian`` rather than ``Debian:13``** compares the
  installed version against every release's fix. A fully patched Debian 13
  ``curl`` is "vulnerable" to anything Debian 14 fixed at a higher version
  number. OSV returned 49 advisories for that ``curl`` asked one way, and 25 the
  other.
- **Taking the fix from any release** called a finding fixable when only
  Debian 14 had the fix. apt had nothing to install, and every re-scan found it
  again.

This module names releases in the forms OSV uses, verified against the live API
(2026-09-14):

============  ====================================================
Debian        ``Debian:13``
Ubuntu        ``Ubuntu:24.04:LTS``, ``Ubuntu:25.10``;
              ``Ubuntu:Pro:24.04:LTS`` for Ubuntu Pro (ESM) fixes
Alpine        ``Alpine:v3.20``
AlmaLinux     ``AlmaLinux:9``
Rocky Linux   ``Rocky Linux:9``
Red Hat       ``Red Hat:enterprise_linux:9::baseos`` (and ``appstream``, ``crb``)
openSUSE      ``openSUSE:Leap 15.6``; ``openSUSE:Tumbleweed`` is rolling
============  ====================================================

SUSE Linux Enterprise is described per product module rather than per release,
and Wolfi, Chainguard and Tumbleweed have no releases at all. Those, and any host
whose release is unknown, are handled without release logic -- and a fix found
for them is reported as "upstream", not as confirmed for the host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The Red Hat Enterprise Linux repositories queried for a given major version.
#: Packages outside them (SAP, high availability, real-time) are not queried, and
#: are never dropped: a finding is only removed when OSV was asked about the
#: exact repository the advisory names.
RHEL_STREAMS = ("baseos", "appstream", "crb")

# Ubuntu release codenames, for derivatives (Linux Mint, elementary OS) whose own
# VERSION_ID is not an Ubuntu version but which declare UBUNTU_CODENAME.
UBUNTU_CODENAMES = {
    "trusty": "14.04",
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "noble": "24.04",
}


@dataclass(frozen=True)
class Release:
    """One release of one distribution family."""

    family: str
    key: tuple[int, ...]
    label: str
    #: True for a paid extended-support stream (Ubuntu Pro), which is not a
    #: newer release but is also not something ``apt upgrade`` reaches.
    subscription: bool = False


def _key(text: str) -> tuple[int, ...] | None:
    parts = text.split(".")
    if not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def ubuntu_ecosystem(version: str) -> str | None:
    """``24.04`` -> ``Ubuntu:24.04:LTS``; ``25.10`` -> ``Ubuntu:25.10``."""
    match = re.fullmatch(r"(\d\d)\.(04|10)", version)
    if not match:
        return None
    lts = match.group(2) == "04" and int(match.group(1)) % 2 == 0
    return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"


def parse_release(ecosystem: str) -> Release | None:
    """The release an OSV (or host) ecosystem string names, if it names one."""
    eco = (ecosystem or "").strip()

    if m := re.fullmatch(r"Debian:(\d{1,2})", eco):
        return Release("Debian", (int(m.group(1)),), f"Debian {m.group(1)}")

    if m := re.fullmatch(r"Ubuntu:Pro:(?:[A-Za-z-]+:)?(\d\d\.\d\d)(:LTS)?", eco):
        return Release(
            "Ubuntu", _key(m.group(1)) or (), f"Ubuntu Pro ({m.group(1)})", subscription=True
        )
    if m := re.fullmatch(r"Ubuntu:(\d\d\.\d\d)(:LTS)?", eco):
        suffix = " LTS" if m.group(2) else ""
        return Release("Ubuntu", _key(m.group(1)) or (), f"Ubuntu {m.group(1)}{suffix}")

    if m := re.fullmatch(r"Alpine:v(\d+\.\d+)", eco):
        return Release("Alpine", _key(m.group(1)) or (), f"Alpine {m.group(1)}")

    for family in ("AlmaLinux", "Rocky Linux"):
        if m := re.fullmatch(rf"{family}:(\d+)", eco):
            return Release(family, (int(m.group(1)),), f"{family} {m.group(1)}")

    if m := re.fullmatch(r"Red Hat:enterprise_linux:(\d+)::[a-z_]+", eco):
        return Release("Red Hat", (int(m.group(1)),), f"RHEL {m.group(1)}")
    # A host records its RHEL release as "Red Hat:9"; OSV never uses that form.
    if m := re.fullmatch(r"Red Hat:(\d+)", eco):
        return Release("Red Hat", (int(m.group(1)),), f"RHEL {m.group(1)}")

    if m := re.fullmatch(r"openSUSE:Leap (\d+\.\d+)", eco):
        return Release("openSUSE Leap", _key(m.group(1)) or (), f"openSUSE Leap {m.group(1)}")

    return None


def host_releases(host_ecosystem: str) -> list[Release]:
    """Every release whose advisories apply to a host, most specific first.

    An AlmaLinux 9 host takes fixes from AlmaLinux 9 and from RHEL 9, which it
    rebuilds; Oracle Linux 9, which has no OSV data of its own, from all three.
    """
    eco = (host_ecosystem or "").strip()
    if m := re.fullmatch(r"(AlmaLinux|Rocky Linux):(\d+)", eco):
        major = m.group(2)
        return [r for r in (parse_release(eco), parse_release(f"Red Hat:{major}")) if r]
    if m := re.fullmatch(r"Oracle Linux:(\d+)", eco):
        major = m.group(1)
        names = (f"AlmaLinux:{major}", f"Rocky Linux:{major}", f"Red Hat:{major}")
        return [r for r in map(parse_release, names) if r]
    release = parse_release(eco)
    return [release] if release and not release.subscription else []


def release_query_ecosystems(host_ecosystem: str) -> list[str]:
    """The release-specific OSV ecosystems to ask about for a host.

    Asked in addition to the distribution-wide query, never instead of it: a
    release OSV does not track (an end-of-life Ubuntu interim) answers every
    query with nothing, and must not turn a host clean.
    """
    queries: list[str] = []
    for release in host_releases(host_ecosystem):
        if release.family == "Red Hat":
            queries.extend(
                f"Red Hat:enterprise_linux:{release.key[0]}::{stream}" for stream in RHEL_STREAMS
            )
        elif release.family == "Debian":
            queries.append(f"Debian:{release.key[0]}")
        elif release.family == "Ubuntu":
            version = ".".join(f"{p:02d}" for p in release.key)
            queries.append(ubuntu_ecosystem(version) or f"Ubuntu:{version}")
        elif release.family == "Alpine":
            queries.append(f"Alpine:v{release.key[0]}.{release.key[1]}")
        elif release.family in ("AlmaLinux", "Rocky Linux"):
            queries.append(f"{release.family}:{release.key[0]}")
        elif release.family == "openSUSE Leap":
            queries.append(f"openSUSE:Leap {release.key[0]}.{release.key[1]}")
    return list(dict.fromkeys(queries))


# How each family's ecosystem names begin in OSV, including forms parse_release
# does not turn into a release (``Red Hat:hummingbird:1``,
# ``Red Hat:enterprise_linux:10.2``). Used to recognise that an advisory is about
# a distribution even when it names none of the host's releases.
_FAMILY_PREFIXES = {
    "Debian": "debian:",
    "Ubuntu": "ubuntu:",
    "Alpine": "alpine:",
    "AlmaLinux": "almalinux:",
    "Rocky Linux": "rocky linux:",
    "Red Hat": "red hat:",
    "openSUSE Leap": "opensuse:leap ",
}


def in_family(ecosystem: str, family: str) -> bool:
    """Whether an OSV ecosystem string belongs to a distribution family."""
    prefix = _FAMILY_PREFIXES.get(family)
    return bool(prefix and (ecosystem or "").lower().startswith(prefix))
