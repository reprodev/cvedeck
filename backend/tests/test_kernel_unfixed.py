"""Kernel CVEs a host's release cannot fix are counted, not listed (Req 12.9).

Measured on live OSV: an up-to-date Debian 12 kernel matches 2,319 kernel CVEs,
none of them fixable in Debian 12 and none with a published severity. Listed,
they bury every finding someone can act on. Counted, the machine page can still
say how many there are and where their fixes live -- and a known-exploited one,
or one whose exploitation was never checked, is always listed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import FindingInput, Repository
from app.data.schema import Base
from app.enums import Platform, ScanStatus, Severity
from app.models import Inventory, OsInfo, Package
from app.services.kernel import decode_unfixed, encode_unfixed, split_kernel_findings
from tests.auth_helpers import override_auth

IMAGE = "Debian:12:linux-image-6.1.0-53-amd64@6.1.187-1"


def _f(cve, identifier, kev=False):
    return FindingInput(cve_id=cve, cvss_score=None, severity=Severity.UNSCORED, source="osv",
                        package_identifier=identifier, kev_listed=kev)


def test_only_what_the_release_can_fix_or_what_is_exploited_is_listed():
    kept, counts = split_kernel_findings([
        _f("CVE-1", f"{IMAGE} (fixed in 6.1.188-1)"),
        _f("CVE-2", f"{IMAGE} (no fix in Debian 12; fixed only in Debian 13: 6.12.1-1)"),
        _f("CVE-3", f"{IMAGE} (no fix in Debian 12; fixed only in Debian 13: 6.12.2-1)"),
        _f("CVE-4", IMAGE),
        # Exploited: listed, fix or no fix.
        _f("CVE-5", IMAGE, kev=True),
        # Never checked against KEV: might be exploited, so listed.
        _f("CVE-6", IMAGE, kev=None),
        # Userland is never counted away.
        _f("CVE-7", "Debian:12:libc6@2.36-9"),
    ])

    assert [f.cve_id for f in kept] == ["CVE-1", "CVE-5", "CVE-6", "CVE-7"]
    count = counts["linux-image-6.1.0-53-amd64@6.1.187-1"]
    assert (count.no_fix, count.elsewhere, count.total) == (1, {"Debian 13": 2}, 3)


def test_counts_round_trip_and_unassessed_is_not_zero():
    _kept, counts = split_kernel_findings([_f("CVE-4", IMAGE)])
    decoded = decode_unfixed(encode_unfixed(counts))
    assert decoded["linux-image-6.1.0-53-amd64@6.1.187-1"].no_fix == 1
    assert decode_unfixed(None) is None
    assert decode_unfixed(encode_unfixed({})) == {}


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


def test_the_kernel_route_says_how_many_were_counted(session):
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)
    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(Inventory(
        machine_id="m1", os_info=OsInfo(name="Debian", version="12"), kernel_version="6.1.0-53-amd64",
        packages=[Package(name="linux-image-6.1.0-53-amd64", version="6.1.187-1", ecosystem="Debian:12",
                          source_name="linux-signed-amd64", source_version="6.1.187+1")],
    ))
    session.commit()

    [before] = client.get("/api/machines/m1/kernel").json()["installed"]
    assert (before["no_fix"], before["fixed_elsewhere"]) == (None, None), "not assessed is not zero"

    _kept, counts = split_kernel_findings([
        _f("CVE-2", f"{IMAGE} (no fix in Debian 12; fixed only in Debian 13: 6.12.1-1)"),
        _f("CVE-4", IMAGE),
    ])
    repo.record_kernel_unfixed("m1", encode_unfixed(counts))
    session.commit()

    [after] = client.get("/api/machines/m1/kernel").json()["installed"]
    assert (after["no_fix"], after["fixed_elsewhere"]) == (1, {"Debian 13": 1})


class _Collector:
    def __init__(self, inventory):
        self._inventory = inventory

    def collect(self, target, credentials):
        return self._inventory


class _Osv:
    def __init__(self, advisories=(), fail=False):
        self._advisories = list(advisories)
        self._fail = fail

    def match_packages(self, packages):
        if self._fail:
            raise RuntimeError("OSV unreachable")
        return self._advisories


class _CheckedEnricher:
    """Every finding checked against KEV and absent from it."""

    def enrich(self, findings):
        from dataclasses import replace
        return [replace(f, kev_listed=False) for f in findings]


def _scan(session, ecosystem, osv):
    from pydantic import SecretStr
    from app.models import Credentials, TargetMachine
    from app.scanner.engine import ScannerEngine

    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.NEVER_SCANNED)
    inventory = Inventory(
        machine_id="m1", os_info=OsInfo(name="Debian", version="12"), kernel_version="6.1.0-53-amd64",
        packages=[Package(name="linux-image-6.1.0-53-amd64", version="6.1.187-1", ecosystem=ecosystem,
                          source_name="linux-signed-amd64", source_version="6.1.187+1")],
    )
    ScannerEngine(
        repo,
        lambda target: Credentials(username="u", password=SecretStr("p")),
        osv=osv,
        collector_factory=lambda platform: _Collector(inventory),
        enricher=_CheckedEnricher(),
    ).scan([TargetMachine(id="m1", hostname="m1", platform=Platform.LINUX)])
    session.commit()
    return repo


def test_a_scan_counts_what_it_does_not_list(session):
    from app.scanner.matcher import RawAdvisory
    from app.data.schema import CveFinding

    repo = _scan(session, "Debian:12", _Osv([
        RawAdvisory(cve_id="CVE-1", cvss_score=None, package_identifier=f"{IMAGE} (fixed in 6.1.188-1)"),
        RawAdvisory(cve_id="CVE-2", cvss_score=None,
                    package_identifier=f"{IMAGE} (no fix in Debian 12; fixed only in Debian 13: 6.12.1-1)"),
    ]))

    assert [f.cve_id for f in session.query(CveFinding).all()] == ["CVE-1"]
    counted = decode_unfixed(repo.latest_kernel_unfixed("m1"))
    assert counted["linux-image-6.1.0-53-amd64@6.1.187-1"].elsewhere == {"Debian 13": 1}


@pytest.mark.parametrize(
    "ecosystem, osv",
    [
        ("Ubuntu:22.04:LTS", _Osv()),  # the kernel was never asked about
        ("Debian:12", _Osv(fail=True)),  # it was asked, and nobody answered
    ],
    ids=["not-looked-up", "osv-down"],
)
def test_counts_are_left_unset_when_the_kernel_was_not_answered(session, ecosystem, osv):
    """Unset reads as not assessed; an empty count would read as zero (Req 12.9)."""
    repo = _scan(session, ecosystem, osv)
    assert repo.latest_kernel_unfixed("m1") is None
