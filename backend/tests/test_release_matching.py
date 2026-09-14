"""Findings and fixes are judged against the host's own distribution release.

Validates Req 14.7, 14.8.

Found on a Debian 13 host: asking OSV about "Debian" rather than "Debian:13"
reported vulnerabilities Debian 13 had already fixed (49 advisories for one
fully patched ``curl``, against 25), and fixes were taken from any release, so
Debian 14-only fixes went into the host's apt plan and never cleared. The
advisory shapes below are taken from the live OSV entries seen then.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.models import Package
from app.package_identifier import parse_fix
from app.scanner.osv_client import OsvHttpClient, fix_suffix
from app.scanner.releases import (
    host_releases,
    parse_release,
    release_query_ecosystems,
)


def _aff(eco: str, name: str = "curl", fixed: str | None = None) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"package": {"name": name, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}


def _vuln(vid: str, *affected: dict) -> dict:
    return {"id": vid, "affected": list(affected)}


# --------------------------------------------------------------------------- #
# Release names
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "eco, family, key, label, subscription",
    [
        ("Debian:13", "Debian", (13,), "Debian 13", False),
        ("Ubuntu:24.04:LTS", "Ubuntu", (24, 4), "Ubuntu 24.04 LTS", False),
        ("Ubuntu:25.10", "Ubuntu", (25, 10), "Ubuntu 25.10", False),
        ("Ubuntu:Pro:22.04:LTS", "Ubuntu", (22, 4), "Ubuntu Pro (22.04)", True),
        ("Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu", (22, 4), "Ubuntu Pro (22.04)", True),
        ("Alpine:v3.20", "Alpine", (3, 20), "Alpine 3.20", False),
        ("AlmaLinux:9", "AlmaLinux", (9,), "AlmaLinux 9", False),
        ("Rocky Linux:9", "Rocky Linux", (9,), "Rocky Linux 9", False),
        ("Red Hat:enterprise_linux:9::baseos", "Red Hat", (9,), "RHEL 9", False),
        ("Red Hat:9", "Red Hat", (9,), "RHEL 9", False),
        ("openSUSE:Leap 15.6", "openSUSE Leap", (15, 6), "openSUSE Leap 15.6", False),
    ],
)
def test_release_names_parse(eco, family, key, label, subscription):
    release = parse_release(eco)
    assert release is not None
    assert (release.family, release.key, release.label, release.subscription) == (
        family, key, label, subscription
    )


@pytest.mark.parametrize(
    "eco",
    ["Debian", "Ubuntu", "Wolfi", "Chainguard", "openSUSE:Tumbleweed", "Fedora",
     "Red Hat:hummingbird:1", "Red Hat:enterprise_linux:10.2", "SUSE:15.6", "unknown"],
)
def test_names_without_a_trackable_release_parse_to_none(eco):
    assert parse_release(eco) is None


@pytest.mark.parametrize(
    "host, queries",
    [
        ("Debian:13", ["Debian:13"]),
        ("Ubuntu:24.04:LTS", ["Ubuntu:24.04:LTS"]),
        ("Ubuntu:25.10", ["Ubuntu:25.10"]),
        ("Alpine:v3.20", ["Alpine:v3.20"]),
        ("Red Hat:9", [f"Red Hat:enterprise_linux:9::{s}" for s in ("baseos", "appstream", "crb")]),
        ("AlmaLinux:9", ["AlmaLinux:9"] + [f"Red Hat:enterprise_linux:9::{s}" for s in ("baseos", "appstream", "crb")]),
        ("Oracle Linux:9", ["AlmaLinux:9", "Rocky Linux:9"] + [f"Red Hat:enterprise_linux:9::{s}" for s in ("baseos", "appstream", "crb")]),
        ("openSUSE:Leap 15.6", ["openSUSE:Leap 15.6"]),
        ("Debian", []),
        ("Fedora", []),
        ("Wolfi", []),
    ],
)
def test_release_queries_per_host(host, queries):
    assert release_query_ecosystems(host) == queries


def test_an_almalinux_host_takes_fixes_from_its_rebuild_source():
    assert [r.label for r in host_releases("AlmaLinux:9")] == ["AlmaLinux 9", "RHEL 9"]


# --------------------------------------------------------------------------- #
# Which fix applies
# --------------------------------------------------------------------------- #

DEBIAN_13 = Package(name="curl", version="8.14.1-2+deb13u5", ecosystem="Debian:13")


def test_a_fix_only_in_a_newer_release_is_not_offered_as_installable():
    # DEBIAN-CVE-2025-10966: no Debian 13 fix, Debian 14 has one.
    vuln = _vuln("DEBIAN-CVE-2025-10966", _aff("Debian:12"), _aff("Debian:13"), _aff("Debian:14", fixed="8.17.0~rc2-1"))

    suffix = fix_suffix(vuln, DEBIAN_13, "Debian", {"debian:13"})

    assert suffix == " (no fix in Debian 13; fixed only in Debian 14: 8.17.0~rc2-1)"
    assert "fixed in" not in suffix, "older dashboards read 'fixed in' as installable"
    assert parse_fix("Debian:13:curl@8.14.1-2+deb13u5" + suffix) == ("newer_release", "Debian 14", "8.17.0~rc2-1")


def test_the_host_release_fix_wins_even_when_an_older_release_is_listed_first():
    # DEBIAN-CVE-2025-15467 lists Debian 12's fix before Debian 13's.
    pkg = Package(name="openssl", version="3.5.1-1", ecosystem="Debian:13")
    vuln = _vuln(
        "DEBIAN-CVE-2025-15467",
        _aff("Debian:12", "openssl", "3.0.18-1~deb12u2"),
        _aff("Debian:13", "openssl", "3.5.4-1~deb13u2"),
        _aff("Debian:14", "openssl", "3.5.5-1"),
    )

    assert fix_suffix(vuln, pkg, "Debian", {"debian:13"}) == " (fixed in 3.5.4-1~deb13u2)"


def test_the_next_newer_release_is_named_not_the_newest():
    vuln = _vuln("X", _aff("Debian:13"), _aff("Debian:15", fixed="9.0"), _aff("Debian:14", fixed="8.9"))

    assert "fixed only in Debian 14: 8.9" in fix_suffix(vuln, DEBIAN_13, "Debian", {"debian:13"})


def test_an_ubuntu_pro_only_fix_is_named_as_such():
    pkg = Package(name="curl", version="7.81.0-1ubuntu1.20", ecosystem="Ubuntu:22.04:LTS")
    vuln = _vuln("UBUNTU-X", _aff("Ubuntu:22.04:LTS"), _aff("Ubuntu:Pro:22.04:LTS", fixed="7.81.0-1ubuntu1.21+esm1"))

    suffix = fix_suffix(vuln, pkg, "Ubuntu", {"ubuntu:22.04:lts"})

    assert suffix == " (no fix in Ubuntu 22.04 LTS; fixed only in Ubuntu Pro (22.04): 7.81.0-1ubuntu1.21+esm1)"


def test_no_fix_anywhere_says_nothing():
    vuln = _vuln("X", _aff("Debian:13"), _aff("Debian:14"))

    assert fix_suffix(vuln, DEBIAN_13, "Debian", {"debian:13"}) == ""


def test_a_rolling_distribution_takes_its_own_fix():
    pkg = Package(name="curl", version="8.9.0-r0", ecosystem="Wolfi")
    vuln = _vuln("CGA-x", _aff("Chainguard", fixed="8.9.1-r1"), _aff("Wolfi", fixed="8.9.1-r0"))

    assert fix_suffix(vuln, pkg, "Wolfi", set()) == " (fixed in 8.9.1-r0)"


def test_a_host_without_a_matching_release_gets_an_upstream_fix_not_an_installable_one():
    pkg = Package(name="curl", version="8.6.0-10.fc40", ecosystem="Fedora")
    vuln = _vuln("RHSA-x", _aff("Red Hat:enterprise_linux:9::baseos", fixed="7.76.1-29.el9"))

    suffix = fix_suffix(vuln, pkg, "Red Hat", set())

    assert suffix == " (not confirmed for this release; upstream fix in RHEL 9: 7.76.1-29.el9)"
    assert parse_fix("Fedora:curl@8.6.0-10.fc40" + suffix) == ("upstream", "RHEL 9", "7.76.1-29.el9")


# --------------------------------------------------------------------------- #
# End to end through the real client, with OSV mocked at the transport
# --------------------------------------------------------------------------- #


def _osv(batch_ids: dict[str, list[str]], details: dict[str, list[dict]], *, fail_batch=False, paged=()):
    """A mock OSV: querybatch answers ids per ecosystem, query answers details."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/querybatch"):
            if fail_batch:
                return httpx.Response(500)
            results = []
            for q in body["queries"]:
                eco = q["package"]["ecosystem"]
                entry = {"vulns": [{"id": i} for i in batch_ids.get(eco, [])]}
                if eco in paged:
                    entry["next_page_token"] = "more"
                results.append(entry)
            return httpx.Response(200, json={"results": results})
        return httpx.Response(200, json={"vulns": details.get(body["package"]["ecosystem"], [])})

    return OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


ALREADY_FIXED = _vuln("DEBIAN-CVE-2024-2379", _aff("Debian:12"), _aff("Debian:13", fixed="8.7.1-1"), _aff("Debian:14", fixed="8.7.1-1"))
NEWER_ONLY = _vuln("DEBIAN-CVE-2025-10966", _aff("Debian:13"), _aff("Debian:14", fixed="8.17.0~rc2-1"))
NOT_THIS_RELEASE = _vuln("DEBIAN-CVE-2026-8925", _aff("Debian:14", fixed="8.19.0-1"))
FIXABLE_HERE = _vuln("DEBIAN-CVE-2026-0001", _aff("Debian:13", fixed="8.14.1-2+deb13u6"), _aff("Debian:14", fixed="8.19.0-1"))
ALL = [ALREADY_FIXED, NEWER_ONLY, NOT_THIS_RELEASE, FIXABLE_HERE]


def _by_id(advisories):
    return {a.cve_id: a.package_identifier for a in advisories}


def test_a_debian_13_host_keeps_only_what_affects_debian_13():
    client = _osv(
        batch_ids={"Debian": [v["id"] for v in ALL], "Debian:13": [NEWER_ONLY["id"], FIXABLE_HERE["id"]]},
        details={"Debian": ALL},
    )

    found = _by_id(client.match_packages([DEBIAN_13]))

    assert set(found) == {"CVE-2025-10966", "CVE-2026-0001"}, (
        "already fixed in Debian 13, and Debian-14-only advisories, are dropped"
    )
    assert found["CVE-2026-0001"].endswith("(fixed in 8.14.1-2+deb13u6)")
    assert "fixed only in Debian 14" in found["CVE-2025-10966"]


def test_a_release_osv_does_not_track_never_turns_a_host_clean():
    # An end-of-life Ubuntu interim: OSV accepts the name and answers nothing,
    # and no advisory mentions the release. Nothing may be dropped for that.
    pkg = Package(name="curl", version="8.9.1-2ubuntu2", ecosystem="Ubuntu:24.10")
    vuln = _vuln("UBUNTU-CVE-1", _aff("Ubuntu:24.04:LTS", fixed="8.5.0-2ubuntu10.6"))
    client = _osv(batch_ids={"Ubuntu": ["UBUNTU-CVE-1"], "Ubuntu:24.10": []}, details={"Ubuntu": [vuln]})

    found = _by_id(client.match_packages([pkg]))

    assert list(found) == ["CVE-1"] or len(found) == 1
    assert "upstream fix in Ubuntu 24.04 LTS" in next(iter(found.values()))


def test_when_the_batch_fails_no_finding_is_dropped_on_the_strength_of_its_answer():
    # Without the release query's answer, "OSV did not match this version on
    # Debian 13" is unknown, so an advisory Debian 13 already fixed is kept.
    # One naming only Debian 14 is still dropped: that comes from the advisory
    # itself, not from the failed query.
    client = _osv(batch_ids={}, details={"Debian": ALL}, fail_batch=True)

    found = _by_id(client.match_packages([DEBIAN_13]))

    assert {"CVE-2024-2379", "CVE-2025-10966", "CVE-2026-0001"} <= set(found)
    assert "CVE-2026-8925" not in found


def test_a_paged_release_answer_drops_nothing_it_did_not_see():
    client = _osv(
        batch_ids={"Debian": [v["id"] for v in ALL], "Debian:13": [NEWER_ONLY["id"]]},
        details={"Debian": ALL},
        paged=("Debian:13",),
    )

    found = _by_id(client.match_packages([DEBIAN_13]))

    assert "CVE-2024-2379" in found, "an incomplete answer is not evidence of 'not affected'"


def test_red_hat_advisories_for_other_products_do_not_affect_rhel_9():
    pkg = Package(name="curl", version="7.76.1-26.el9", ecosystem="Red Hat:9")
    rhel9 = _vuln("RHSA-2023:6745", _aff("Red Hat:enterprise_linux:9::baseos", fixed="7.76.1-26.el9_3.2"))
    other = _vuln("RHSA-2026:12916", _aff("Red Hat:hummingbird:1", fixed="8.19.0-1.hum1"))
    streams = [f"Red Hat:enterprise_linux:9::{s}" for s in ("baseos", "appstream", "crb")]
    client = _osv(
        batch_ids={"Red Hat": [rhel9["id"], other["id"]], streams[0]: [rhel9["id"]]},
        details={"Red Hat": [rhel9, other]},
    )

    found = _by_id(client.match_packages([pkg]))

    assert list(found.values()) == ["Red Hat:9:curl@7.76.1-26.el9 (fixed in 7.76.1-26.el9_3.2)"]
