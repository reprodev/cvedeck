"""An Ubuntu kernel, checked against Canonical's feed (Req 12.11).

Driven through the real repository and the real-data fixture (three
definitions cut from the 22.04 feed). The host is a 22.04 machine running
5.15.0-25-generic, older than CVE-2024-1086's fix at 5.15.0-101.111.
"""

from __future__ import annotations

import bz2
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import Repository
from app.data.schema import Base, CveFinding
from app.enums import FeedStatus, Platform, ScanStatus
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.engine import ScannerEngine
from app.scanner.ubuntu_kernel_feed import FetchResult, parse_ubuntu_kernel_oval
from app.services import ubuntu_kernel
from app.services.enrichment import FeedRefreshService, ubuntu_kernel_feed_name
from app.services.kernel import decode_unfixed
from tests.auth_helpers import override_auth

FIXTURE = Path(__file__).parent / "fixtures" / "ubuntu_oval" / "jammy-excerpt.cve.oval.xml.bz2"
ECO = "Ubuntu:22.04:LTS"
IMAGE = "linux-image-5.15.0-25-generic"


def _pkg(name, version, source):
    return Package(name=name, version=version, ecosystem=ECO, source_name=source, source_version=version)


def _inventory(release="5.15.0-25-generic", source="linux-signed"):
    return Inventory(
        machine_id="m1", os_info=OsInfo(name="Ubuntu", version="22.04"), kernel_version=release,
        packages=[
            _pkg(IMAGE, "5.15.0-25.25", source),
            _pkg("linux-image-generic", "5.15.0.25.25", "linux-meta"),
            _pkg("libc6", "2.35-0ubuntu3", "glibc"),
        ],
    )


class _Feed:
    """The client, answering from the fixture; or failing; or 'unchanged'."""

    def __init__(self, fail=False):
        self.fail = fail
        self.asked: list[tuple[str, str | None]] = []

    def fetch(self, codename, etag=None):
        self.asked.append((codename, etag))
        if self.fail:
            raise ConnectionError("security-metadata.canonical.com unreachable")
        if etag == '"same"':
            return FetchResult(table=None, etag=etag)
        return FetchResult(table=parse_ubuntu_kernel_oval(bz2.open(FIXTURE), codename), etag='"same"')


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture(autouse=True)
def feed_on(monkeypatch):
    monkeypatch.delenv("CVEDECK_UBUNTU_KERNEL_FEED", raising=False)


def _host(session, inventory=None):
    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(inventory or _inventory())
    session.commit()
    return repo


def _refresh(repo, feed=None):
    feed = feed or _Feed()
    outcomes = FeedRefreshService(repo, ubuntu_kernel_source=feed).refresh_all()
    repo._session.commit()
    return outcomes, feed


# --- Refreshing ----------------------------------------------------------- #


def test_the_feed_is_fetched_for_the_fleets_releases_only(session):
    repo = _host(session)
    outcomes, feed = _refresh(repo)
    assert feed.asked == [("jammy", None)]
    assert [(o.feed_name, o.status) for o in outcomes] == [("ubuntu-kernel:jammy", FeedStatus.OK)]
    assert repo.ubuntu_kernel_feed("jammy", "linux") is not None


def test_a_fleet_with_no_ubuntu_host_fetches_nothing(session):
    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(Inventory(machine_id="m1", os_info=OsInfo(name="Debian", version="12"),
                                  packages=[Package(name="libc6", version="2.36-9", ecosystem="Debian:12")]))
    outcomes, feed = _refresh(repo)
    assert feed.asked == [] and outcomes == []


def test_an_unchanged_feed_is_not_downloaded_again(session):
    repo = _host(session)
    _refresh(repo)
    outcomes, feed = _refresh(repo)
    assert feed.asked == [("jammy", '"same"')]
    assert outcomes[0].unchanged


def test_a_failed_refresh_keeps_the_table_it_had(session):
    repo = _host(session)
    _refresh(repo)
    outcomes, _ = _refresh(repo, _Feed(fail=True))
    assert outcomes[0].status is FeedStatus.FAILED
    assert repo.ubuntu_kernel_feed("jammy", "linux") is not None


def test_switched_off_the_client_is_never_built(monkeypatch, session):
    from app.services.enrichment import build_feed_refresh_service

    monkeypatch.setenv("CVEDECK_UBUNTU_KERNEL_FEED", "off")
    assert build_feed_refresh_service(Repository(session))._ubuntu_kernel_source is None


# --- Checking ------------------------------------------------------------- #


def _check(repo, inventory=None, *, enabled=True, usable=True):
    return ubuntu_kernel.check_ubuntu_kernel(
        inventory or _inventory(), repo, enabled=enabled, feed_usable=lambda c: usable
    )


def test_the_running_kernel_is_checked_against_its_own_flavour(session):
    repo = _host(session)
    _refresh(repo)
    check = _check(repo)
    assert check.reason is None
    assert check.assessed == f"{IMAGE}@5.15.0-25.25"
    by_cve = {f.cve_id: f.package_identifier for f in check.findings}
    assert by_cve["CVE-2024-1086"] == f"{ECO}:{IMAGE}@5.15.0-25.25 (fixed in 5.15.0-101.111)"
    assert by_cve["CVE-2012-4542"] == f"{ECO}:{IMAGE}@5.15.0-25.25"


def test_a_riscv_kernel_gets_the_riscv_advisories_not_the_generic_ones(session):
    """linux and linux-riscv share a uname pattern; the package's source decides.

    In the real feed CVE-2024-1086 is fixed for the generic kernel at
    5.15.0-101.111 and has no fix for linux-riscv. Read by uname alone, a RISC-V
    host would be told to upgrade to a fix that does not exist for it.
    """
    repo = _host(session)
    _refresh(repo)
    generic = {f.cve_id: f.package_identifier for f in _check(repo).findings}
    riscv = {f.cve_id: f.package_identifier for f in _check(repo, _inventory(source="linux-riscv")).findings}

    assert generic["CVE-2024-1086"].endswith("(fixed in 5.15.0-101.111)")
    assert "fixed in" not in riscv["CVE-2024-1086"]


@pytest.mark.parametrize(
    "inventory, enabled, usable, reason",
    [
        (_inventory(), False, True, ubuntu_kernel.FEED_OFF),
        (_inventory(), True, False, ubuntu_kernel.FEED_UNAVAILABLE),
        (_inventory(release=""), True, True, ubuntu_kernel.RUNNING_UNKNOWN),
        (_inventory(release="6.6.87.2-microsoft-standard-WSL2"), True, True, ubuntu_kernel.RUNNING_NOT_INSTALLED),
        (_inventory(source="linux-something-new"), True, True, ubuntu_kernel.FLAVOUR_UNKNOWN),
    ],
    ids=["off", "unavailable", "release-unknown", "container", "flavour-unknown"],
)
def test_why_a_kernel_was_not_checked(session, inventory, enabled, usable, reason):
    repo = _host(session)
    _refresh(repo)
    assert _check(repo, inventory, enabled=enabled, usable=usable).reason == reason


@pytest.mark.parametrize(
    "ecosystem, reason",
    [("Ubuntu:12.04:LTS", ubuntu_kernel.RELEASE_UNKNOWN), ("Ubuntu:25.04", ubuntu_kernel.RELEASE_END_OF_LIFE)],
)
def test_unknown_and_unsupported_releases_are_not_checked(session, ecosystem, reason):
    """An end-of-life feed is frozen: CVEs since are absent, not fixed."""
    inv = _inventory()
    inv = inv.model_copy(update={"packages": [p.model_copy(update={"ecosystem": ecosystem}) for p in inv.packages]})
    assert _check(_host(session), inv).reason == reason


# --- Scanning, end to end ------------------------------------------------- #


class _Collector:
    def __init__(self, inventory):
        self._inventory = inventory

    def collect(self, target, credentials):
        return self._inventory


class _NoOsv:
    def match_packages(self, packages):
        return []


class _Checked:
    def enrich(self, findings):
        return [replace(f, kev_listed=False) for f in findings]


def _scan(session, inventory):
    repo = Repository(session)
    ScannerEngine(
        repo, lambda t: Credentials(username="u", password=SecretStr("p")),
        osv=_NoOsv(), collector_factory=lambda platform: _Collector(inventory), enricher=_Checked(),
    ).scan([TargetMachine(id="m1", hostname="m1", platform=Platform.LINUX)])
    session.commit()
    return repo


def test_a_scan_lists_the_fixable_and_counts_the_rest(session):
    repo = _host(session)
    _refresh(repo)
    _scan(session, _inventory())

    listed = {f.cve_id for f in session.query(CveFinding).all()}
    assert "CVE-2024-1086" in listed and "CVE-2012-4542" not in listed
    counted = decode_unfixed(repo.latest_kernel_unfixed("m1"))
    assert counted[f"{IMAGE}@5.15.0-25.25"].no_fix >= 1


def test_without_the_feed_a_scan_records_nothing_as_assessed(session):
    repo = _host(session)
    _scan(session, _inventory())
    assert repo.latest_kernel_unfixed("m1") is None
    assert not session.query(CveFinding).filter(CveFinding.package_identifier.like("%linux-image%")).count()


# --- What the dashboard is told ------------------------------------------- #


def _client(session):
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def test_the_kernel_route_says_why_and_that_only_the_running_kernel_is_checked(session):
    repo = _host(session)
    client = _client(session)

    before = client.get("/api/machines/m1/kernel").json()
    assert (before["checked"], before["unchecked_reason"]) == (False, ubuntu_kernel.FEED_UNAVAILABLE)
    assert before["running_only"] is True

    _refresh(repo)
    assert client.get("/api/machines/m1/kernel").json()["unchecked_reason"] == ubuntu_kernel.NOT_YET_SCANNED

    _scan(session, _inventory())
    after = client.get("/api/machines/m1/kernel").json()
    assert (after["checked"], after["unchecked_reason"]) == (True, None)
    [image] = [k for k in after["installed"] if k["package"] == IMAGE]
    assert image["running"] is True and image["no_fix"] >= 1


def test_feed_health_lists_each_ubuntu_release_in_the_fleet(session):
    repo = _host(session)
    names = [f["feed_name"] for f in _client(session).get("/api/feeds").json()]
    assert names == ["kev", "epss", ubuntu_kernel_feed_name("jammy")]
