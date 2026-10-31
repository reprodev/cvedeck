"""Fedora, Arch, Oracle Linux and Amazon Linux 2023 kernels, checked against their feeds.

Req 12.12-12.14. Driven through the real repository with real package lists
(tests/fixtures/packages, captured with the collector's own command) and the
recorded feeds in tests/fixtures/kernel_feeds. Nothing reaches the network.
"""

from __future__ import annotations

import bz2
import gzip
import json
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
from app.enums import Platform, ScanStatus, Severity
from app.models import Credentials, Inventory, OsInfo, TargetMachine
from app.scanner.collectors import _parse_linux_packages
from app.scanner.engine import ScannerEngine
from app.scanner.kernel_feeds import (
    FetchResult,
    KernelFeedTable,
    parse_amazon_updateinfo,
    parse_oracle_oval,
    parse_upstream_records,
)
from app.services import kernel_feeds
from app.services.enrichment import FeedRefreshService, kernel_feed_name
from app.services.kernel import decode_unfixed
from tests.auth_helpers import override_auth

PACKAGES = Path(__file__).parent / "fixtures" / "packages"
FEEDS = Path(__file__).parent / "fixtures" / "kernel_feeds"


def _inventory(fixture: str, ecosystem: str, *, machine_id="m1", replace_versions=None) -> Inventory:
    packages = _parse_linux_packages((PACKAGES / f"{fixture}.tsv").read_text(encoding="utf-8"), default_ecosystem=ecosystem)
    for name, version in (replace_versions or {}).items():
        packages = [p.model_copy(update={"version": version}) if p.name == name else p for p in packages]
    return Inventory(machine_id=machine_id, os_info=OsInfo(name="Linux", version="x"), kernel_version="", packages=packages)


def _upstream() -> KernelFeedTable:
    pages = [json.loads((FEEDS / f"osv_linux_page{n}.json").read_text(encoding="utf-8")) for n in (1, 2)]
    return KernelFeedTable("upstream", {"all": parse_upstream_records(v for p in pages for v in p["vulns"])})


def _oracle() -> KernelFeedTable:
    return parse_oracle_oval(bz2.open(FEEDS / "elsa-ol9-sample.xml.bz2"), "9")


def _amazon() -> KernelFeedTable:
    return parse_amazon_updateinfo(gzip.open(FEEDS / "al2023-updateinfo-sample.xml.gz"), "2023")


class _Client:
    """A feed client answering from the recordings; or failing."""

    def __init__(self, table: KernelFeedTable, fail=False):
        self.table, self.fail = table, fail
        self.asked: list[tuple] = []

    def fetch(self, *args, digest=None):
        self.asked.append((*args, digest))
        if self.fail:
            raise ConnectionError("feed unreachable")
        if digest == "same":
            return FetchResult(table=None, digest=digest)
        return FetchResult(table=self.table, digest="same")


def _sources(**overrides):
    sources = {"upstream": _Client(_upstream()), "oracle": _Client(_oracle()), "amazon": _Client(_amazon())}
    sources.update(overrides)
    return sources


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture(autouse=True)
def feeds_on(monkeypatch):
    for name in ("CVEDECK_UPSTREAM_KERNEL_FEED", "CVEDECK_ORACLE_KERNEL_FEED", "CVEDECK_AMAZON_KERNEL_FEED", "CVEDECK_DEMO_MODE"):
        monkeypatch.delenv(name, raising=False)


def _host(session, inventory: Inventory):
    repo = Repository(session)
    repo.upsert_target_machine(inventory.machine_id, inventory.machine_id, Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(inventory)
    session.commit()
    return repo


def _refresh(repo, sources=None):
    sources = sources or _sources()
    outcomes = FeedRefreshService(repo, kernel_feed_sources=sources).refresh_all()
    repo._session.commit()
    return outcomes, sources


def _check(repo, inventory, *, enabled=True, usable=True):
    return kernel_feeds.check_feed_kernels(
        inventory, repo, enabled=lambda source: enabled, feed_usable=lambda feed: usable
    )


FEDORA_OLD = {"kernel-core": "6.18.10-100.fc43", "kernel-modules-core": "6.18.10-100.fc43"}


# --- Checking ---------------------------------------------------------------


def test_a_fedora_kernel_lists_its_series_fix_and_counts_a_fix_only_newer_series_have(session):
    inventory = _inventory("fedora_44_kernel", "Fedora", replace_versions=FEDORA_OLD)
    repo = _host(session, inventory)
    _refresh(repo)

    check = _check(repo, inventory)

    assert check.reason is None
    assert check.assessed == ["kernel-core@6.18.10-100.fc43"]
    by_cve = {f.cve_id: f for f in check.findings}
    assert by_cve["CVE-2025-71295"].package_identifier.endswith("(fixed in 6.18.16)")
    assert by_cve["CVE-2026-100072"].package_identifier.endswith(
        "(no fix in Linux 6.18; fixed only in Linux 7.2: 7.2.6)"
    )
    assert {f.source for f in check.findings} == {"kernel-cna"}


def test_a_current_fedora_kernel_is_checked_and_clean(session):
    inventory = _inventory("fedora_44_kernel", "Fedora")
    repo = _host(session, inventory)
    _refresh(repo)

    check = _check(repo, inventory)

    assert (check.reason, check.findings) == (None, [])
    assert check.assessed == ["kernel-core@7.2.13-200.fc44"]


def test_arch_checks_linux_lts_and_leaves_linux_zen_unchecked(session):
    inventory = _inventory("archlinux_lts_zen_kernel", "Arch Linux")
    repo = _host(session, inventory)
    _refresh(repo)

    check = _check(repo, inventory)

    assert check.assessed == ["linux-lts@6.18.60-1"]
    assert all("linux-lts@" in f.package_identifier for f in check.findings)
    assert "CVE-2026-100072" in {f.cve_id for f in check.findings}


def test_an_oracle_kernel_is_held_to_its_own_stream_by_rpm_order(session):
    inventory = _inventory("oraclelinux_9_kernel", "Oracle Linux:9", replace_versions={"kernel-core": "5.14.0-611.27.1.el9_7"})
    repo = _host(session, inventory)
    _refresh(repo)

    check = _check(repo, inventory)

    assert check.reason is None
    # UEK7 5.15.0 has no stream in the recording: it is not claimed as assessed.
    assert check.assessed == ["kernel-core@5.14.0-611.27.1.el9_7"]
    assert check.findings and all(f.source == "oracle-oval" for f in check.findings)
    assert all(f.package_identifier.endswith("(fixed in 0:5.14.0-687.61.1.el9_8)") for f in check.findings)
    assert all(f.severity is Severity.HIGH and f.cvss_score is None for f in check.findings)


def test_amazon_checks_each_installed_kernel_series(session):
    inventory = _inventory("amazonlinux_2023_kernel", "Amazon Linux:2023")
    repo = _host(session, inventory)
    _refresh(repo)

    check = _check(repo, inventory)

    assert sorted(check.assessed) == ["kernel6.12@1:6.12.111-136.204.amzn2023", "kernel@1:6.1.188-233.393.amzn2023"]
    assert {f.package_identifier.split("@")[0].rsplit(":", 1)[-1] for f in check.findings} <= {"kernel", "kernel6.12"}
    assert {f.source for f in check.findings} <= {"amazon-alas"}


@pytest.mark.parametrize(
    "fixture, ecosystem, enabled, usable, reason",
    [
        ("fedora_44_kernel", "Fedora", False, True, kernel_feeds.FEED_OFF),
        ("fedora_44_kernel", "Fedora", True, False, kernel_feeds.FEED_UNAVAILABLE),
        ("oraclelinux_9_kernel", "Oracle Linux", True, True, kernel_feeds.RELEASE_UNKNOWN),
    ],
)
def test_why_a_kernel_was_not_checked(session, fixture, ecosystem, enabled, usable, reason):
    inventory = _inventory(fixture, ecosystem)
    assert _check(Repository(session), inventory, enabled=enabled, usable=usable).reason == reason


def test_a_host_running_only_linux_zen_says_its_flavour_is_unsupported(session):
    inventory = _inventory("archlinux_lts_zen_kernel", "Arch Linux")
    inventory = inventory.model_copy(update={"packages": [p for p in inventory.packages if p.name != "linux-lts"]})
    repo = _host(session, inventory)
    _refresh(repo)
    assert _check(repo, inventory).reason == kernel_feeds.FLAVOUR_UNSUPPORTED


def test_a_kernel_the_feed_has_nothing_for_says_so(session):
    inventory = _inventory("oraclelinux_9_kernel", "Oracle Linux:9")
    inventory = inventory.model_copy(update={"packages": [p for p in inventory.packages if p.name != "kernel-core"]})
    repo = _host(session, inventory)
    _refresh(repo)
    assert _check(repo, inventory).reason == kernel_feeds.NOT_IN_FEED


def test_other_distributions_are_not_this_modules_to_check(session):
    inventory = _inventory("debian_12_kernel", "Debian:12")
    assert _check(Repository(session), inventory) is None


# --- Refreshing ---------------------------------------------------------------


def test_feeds_are_fetched_only_for_the_fleets_distributions(session):
    repo = _host(session, _inventory("fedora_44_kernel", "Fedora"))
    _host(session, _inventory("oraclelinux_9_kernel", "Oracle Linux:9", machine_id="m2"))

    outcomes, sources = _refresh(repo)

    assert sorted(o.feed_name for o in outcomes) == [kernel_feed_name("oracle:ol9"), kernel_feed_name("upstream")]
    assert sources["upstream"].asked == [(None,)]
    assert sources["oracle"].asked == [("9", None)]
    assert sources["amazon"].asked == []
    # Fedora and Arch share one upstream table: one fetch for both.
    _host(session, _inventory("archlinux_lts_zen_kernel", "Arch Linux", machine_id="m3"))
    _outcomes, again = _refresh(repo)
    assert again["upstream"].asked == [("same",)]


def test_an_unchanged_feed_is_not_rewritten_and_a_failed_one_keeps_its_table(session):
    repo = _host(session, _inventory("fedora_44_kernel", "Fedora"))
    _refresh(repo)
    stored = repo.count_kernel_feed_entries("upstream")

    outcomes, sources = _refresh(repo)
    assert sources["upstream"].asked == [("same",)] and outcomes[0].unchanged

    failing = _sources(upstream=_Client(_upstream(), fail=True))
    outcomes, _ = _refresh(repo, failing)
    assert not outcomes[0].ok
    assert repo.count_kernel_feed_entries("upstream") == stored


@pytest.mark.parametrize("variable", ["CVEDECK_UPSTREAM_KERNEL_FEED", "CVEDECK_ORACLE_KERNEL_FEED", "CVEDECK_AMAZON_KERNEL_FEED"])
def test_switched_off_a_feed_has_no_client(monkeypatch, variable):
    from app.scanner.kernel_feeds import build_kernel_feed_sources

    monkeypatch.setenv(variable, "off")
    off = variable.split("_")[1].lower()
    assert off not in build_kernel_feed_sources(5.0)
    assert len(build_kernel_feed_sources(5.0)) == 2


def test_in_demo_mode_a_scan_gets_no_feed_client(monkeypatch):
    from app.api.wiring import _kernel_feed_sources

    monkeypatch.setenv("CVEDECK_DEMO_MODE", "1")
    assert _kernel_feed_sources() == {}


# --- Scanning -------------------------------------------------------------------


class _NoOsv:
    def match_packages(self, packages):
        return []


class _Checked:
    def enrich(self, findings):
        return [replace(f, kev_listed=False) for f in findings]


class _ByTarget:
    def __init__(self, by_id):
        self._by_id = by_id

    def collect(self, target, credentials):
        return self._by_id[target.id]


def _scan(session, inventories, sources=None):
    repo = Repository(session)
    by_id = {inv.machine_id: inv for inv in inventories}
    for machine_id in by_id:
        repo.upsert_target_machine(machine_id, machine_id, Platform.LINUX, ScanStatus.NEVER_SCANNED)
    result = ScannerEngine(
        repo, lambda t: Credentials(username="u", password=SecretStr("p")),
        osv=_NoOsv(), enricher=_Checked(), kernel_feed_sources=sources,
        collector_factory=lambda platform: _ByTarget(by_id),
    ).scan([TargetMachine(id=m, hostname=m, platform=Platform.LINUX) for m in by_id])
    session.commit()
    return repo, result


def test_the_first_scan_fetches_the_feed_lists_the_fixable_and_counts_the_rest(session):
    sources = _sources()
    old = _inventory("fedora_44_kernel", "Fedora", replace_versions=FEDORA_OLD)
    repo, result = _scan(session, [old, old.model_copy(update={"machine_id": "m2"})], sources)

    assert [s.status for s in result.machine_scans] == [ScanStatus.SUCCESS] * 2
    assert sources["upstream"].asked == [(None,)], "one fetch for the batch"
    listed = {f.cve_id for f in session.query(CveFinding).filter_by(machine_id="m1")}
    assert "CVE-2025-71295" in listed and "CVE-2026-100072" not in listed
    counted = decode_unfixed(repo.latest_kernel_unfixed("m1"))
    assert counted["kernel-core@6.18.10-100.fc43"].elsewhere.get("Linux 7.2", 0) >= 1


def test_a_failed_fetch_leaves_the_scan_whole_and_the_kernel_unchecked(session):
    sources = _sources(upstream=_Client(_upstream(), fail=True))
    repo, result = _scan(session, [_inventory("fedora_44_kernel", "Fedora")], sources)
    assert result.machine_scans[0].status is ScanStatus.SUCCESS
    assert repo.latest_kernel_unfixed("m1") is None


def _client(session):
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def test_the_kernel_route_says_why_then_that_it_was_checked(session):
    inventory = _inventory("fedora_44_kernel", "Fedora")
    repo = _host(session, inventory)
    client = _client(session)

    before = client.get("/api/machines/m1/kernel").json()
    assert (before["checked"], before["unchecked_reason"], before["running_only"]) == (
        False, kernel_feeds.FEED_UNAVAILABLE, False,
    )
    assert client.get("/api/machines").json()[0]["kernel_packages_unchecked"] == 2

    _refresh(repo)
    assert client.get("/api/machines/m1/kernel").json()["unchecked_reason"] == kernel_feeds.NOT_YET_SCANNED

    _scan(session, [inventory])
    after = client.get("/api/machines/m1/kernel").json()
    assert (after["checked"], after["unchecked_reason"]) == (True, None)
    assert client.get("/api/machines").json()[0]["kernel_packages_unchecked"] == 0


def test_amazon_linux_2_says_it_is_past_its_end_of_support(session):
    inventory = _inventory("amazonlinux_2023_kernel", "Amazon Linux:2")
    _host(session, inventory)
    assert _client(session).get("/api/machines/m1/kernel").json()["unchecked_reason"] == "kernel_release_end_of_support"


def test_feed_health_lists_each_kernel_feed_the_fleet_needs(session):
    _host(session, _inventory("fedora_44_kernel", "Fedora"))
    _host(session, _inventory("amazonlinux_2023_kernel", "Amazon Linux:2023", machine_id="m2"))
    names = [f["feed_name"] for f in _client(session).get("/api/feeds").json()]
    assert names == ["kev", "epss", kernel_feed_name("amazon:al2023"), kernel_feed_name("upstream")]


def test_a_scan_reports_the_findings_it_stored_including_the_feeds(session):
    """Found in the 0.15.0 container run: an Oracle host reported 2 findings with
    2,065 stored, because the count was the matcher's answer alone."""
    old = _inventory("oraclelinux_9_kernel", "Oracle Linux:9", replace_versions={"kernel-core": "5.14.0-611.27.1.el9_7"})
    repo, result = _scan(session, [old], _sources())

    stored = session.query(CveFinding).filter_by(machine_id="m1").count()
    assert stored > 0
    assert result.machine_scans[0].stored_findings == stored
    assert len(result.machine_scans[0].findings) == 0  # the matcher found nothing itself
