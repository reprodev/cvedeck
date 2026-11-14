"""A fix the host already has is disputed, and the fix chosen is the one it needs.

Validates Req 2.11, 2.12, 14.11, 21.18.

Feature: disputed findings, Property 24: a fix the host already has never
pages anyone. The digest half of the property is in
tests/test_notifications_digest.py, inside Property 23's generator.

In 0.17.0's upgrade check OSV once reported 6,835 kernel CVEs against a Debian
12 host, every one "fixed in" a version older than the 6.1.187-1 installed,
13 of them KEV-listed. The identifier below is one of them, verbatim.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app import package_identifier as pid
from app.models import Package
from app.package_identifier import fix_is_disputed, version_order
from app.scanner import debian_version, rpm_version
from app.scanner.osv_client import _fixed_from_ranges, fix_suffix

RUN_1 = "Debian:12:linux-image-6.1.0-53-amd64@6.1.187-1 (fixed in 6.1.177-1)"


# --- The rule ------------------------------------------------------------------


def test_the_run_1_finding_is_disputed():
    assert fix_is_disputed(RUN_1)


def test_a_fix_newer_than_installed_is_not_disputed():
    assert not fix_is_disputed("Debian:12:linux-image-6.1.0-53-amd64@6.1.187-1 (fixed in 6.1.190-1)")


def test_a_fix_equal_to_the_installed_version_is_disputed():
    """Equal means installed: a version is fixed from its fix onwards."""
    assert fix_is_disputed("Debian:12:openssl@3.0.15-1~deb12u1 (fixed in 3.0.15-1~deb12u1)")


@pytest.mark.parametrize(
    "identifier",
    [
        # No apk ordering in CveDeck: not compared, so not disputed.
        "Alpine:v3.20:busybox@1.36.1-r29 (fixed in 1.36.1-r9)",
        "Wolfi:curl@8.9.1-r0 (fixed in 8.0.0-r0)",
        # A guessed tracker names an upstream fix, never "fixed in".
        "Fedora:curl@8.6.0-10.fc40 (not confirmed for this release; upstream fix in RHEL 9: 7.76.1-29.el9)",
        # Fixed only elsewhere, or not at all.
        "Debian:13:curl@8.14.1-2 (no fix in Debian 13; fixed only in Debian 14: 8.0-1)",
        "Debian:12:curl@8.14.1-2",
        # No installed version to compare with.
        "Debian:12:curl (fixed in 1.0-1)",
        None,
        "",
    ],
)
def test_what_cannot_be_decided_is_not_disputed(identifier):
    assert not fix_is_disputed(identifier)


def test_a_comparison_that_fails_is_not_disputed(monkeypatch):
    """Disputing takes a finding out of alerts; only a comparison that worked may."""
    def broken(_a, _b):
        raise ValueError("unparseable")

    monkeypatch.setitem(pid._VERSION_ORDER, "Debian", broken)
    assert not fix_is_disputed(RUN_1)


def test_rpm_epochs_count():
    assert not fix_is_disputed("Rocky Linux:9:nginx@1.20.1-14.el9 (fixed in 1:1.0-1.el9)")
    assert fix_is_disputed("Rocky Linux:9:nginx@1:1.20.1-14.el9 (fixed in 1.21.1-1.el9)")


def test_one_ordering_for_matching_and_disputing():
    assert version_order("Debian:12") is debian_version.compare
    assert version_order("Ubuntu:22.04:LTS:openssl@3.0.2") is debian_version.compare
    assert version_order("Red Hat:openssl@1:3.0.7-27.el9") is rpm_version.compare
    assert version_order("Alpine:v3.20") is None
    assert version_order(None) is None


_DEB = ["0.9-1", "1.0-1", "1.0-1+b1", "1.0-1~deb12u1", "1.0-2", "1:0.5-1", "1.0.1-1", "2.0~rc1-1", "2.0-1"]
_RPM = ["1.0-1.el9", "1.0-1.el9_2", "1.0-10.el9", "1.0-2.el9", "1:0.5-1.el9", "1.10-1.el9", "1.9-1.el9", "2.0-1.el9"]


@given(
    family=st.sampled_from(
        [("Debian:12:pkg", _DEB, debian_version.compare), ("Rocky Linux:9:pkg", _RPM, rpm_version.compare)]
    ),
    data=st.data(),
)
def test_property_24_disputed_exactly_when_the_fix_is_not_newer(family, data):
    """Property 24: disputed if and only if the ordering puts fix <= installed."""
    prefix, versions, compare = family
    installed = data.draw(st.sampled_from(versions))
    fixed = data.draw(st.sampled_from(versions))

    assert fix_is_disputed(f"{prefix}@{installed} (fixed in {fixed})") is (compare(fixed, installed) <= 0)


# --- The fix chosen (Req 2.12) ---------------------------------------------------


def _ranges(*events: dict) -> list[dict]:
    return [{"type": "ECOSYSTEM", "events": list(events)}]


REINTRODUCED = _ranges(
    {"introduced": "0"}, {"fixed": "1.2-1"}, {"introduced": "1.4-1"}, {"fixed": "1.6-1"}
)


def test_a_reintroduced_vulnerability_takes_the_fix_after_the_installed_version():
    assert _fixed_from_ranges(REINTRODUCED, "1.5-1", debian_version.compare) == "1.6-1"


def test_below_the_first_fix_the_first_fix_is_the_one():
    assert _fixed_from_ranges(REINTRODUCED, "1.0-1", debian_version.compare) == "1.2-1"


def test_without_an_ordering_the_first_listed_is_kept():
    assert _fixed_from_ranges(REINTRODUCED, "1.5-1", None) == "1.2-1"
    assert _fixed_from_ranges(REINTRODUCED) == "1.2-1"


def test_when_no_fix_is_newer_the_first_listed_is_kept():
    """And the finding is then disputed, not silently re-dated."""
    assert _fixed_from_ranges(REINTRODUCED, "2.0-1", debian_version.compare) == "1.2-1"


def test_fixes_in_separate_ranges_are_considered_together():
    ranges = _ranges({"introduced": "0"}, {"fixed": "1.2-1"}) + _ranges({"introduced": "1.4-1"}, {"fixed": "1.6-1"})
    assert _fixed_from_ranges(ranges, "1.5-1", debian_version.compare) == "1.6-1"


def _vuln(*affected: dict) -> dict:
    return {"id": "DEBIAN-CVE-2026-1", "affected": list(affected)}


def test_the_host_s_own_release_names_the_fix_it_needs():
    pkg = Package(name="bash", version="5.2.15-2", ecosystem="Debian:12")
    vuln = _vuln(
        {
            "package": {"name": "bash", "ecosystem": "Debian:12"},
            "ranges": _ranges(
                {"introduced": "0"}, {"fixed": "4.3-7"}, {"introduced": "5.0-1"}, {"fixed": "5.2.15-3"}
            ),
        }
    )

    suffix = fix_suffix(vuln, pkg, "Debian", {"debian:12"})

    assert suffix == " (fixed in 5.2.15-3)"
    assert not fix_is_disputed(f"Debian:12:bash@5.2.15-2{suffix}")


def test_another_release_s_fix_is_named_not_compared():
    """Debian 14's versions say nothing about a Debian 13 host's."""
    pkg = Package(name="curl", version="8.14.1-2", ecosystem="Debian:13")
    vuln = _vuln(
        {"package": {"name": "curl", "ecosystem": "Debian:13"}, "ranges": _ranges({"introduced": "0"})},
        {
            "package": {"name": "curl", "ecosystem": "Debian:14"},
            "ranges": _ranges({"introduced": "0"}, {"fixed": "8.0-1"}, {"fixed": "8.17.0-1"}),
        },
    )

    assert fix_suffix(vuln, pkg, "Debian", {"debian:13"}) == (
        " (no fix in Debian 13; fixed only in Debian 14: 8.0-1)"
    )
