"""What a finding covers, and what was not checked (Req 2.8, 12.5).

A CVE is reported once per source package, against one representative binary.
The API names every installed binary of that source, because a fix command
that upgraded only the representative would leave the rest vulnerable, and
because what breaks if glibc goes is what depends on any part of it.

Kernel packages are not matched yet, and each machine says how many it has, so
a kernel with no findings does not read as a clean one.
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
from tests.auth_helpers import override_auth

ECO = "Debian:12"


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def client(session):
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _host(session, machine_id: str, packages: list[Package] | None, findings=()):
    repo = Repository(session)
    repo.upsert_target_machine(machine_id, machine_id, Platform.LINUX, ScanStatus.SUCCESS)
    if packages is not None:
        repo.save_inventory(Inventory(machine_id=machine_id, os_info=OsInfo(name="Debian", version="12"),
                                      packages=packages))
    if findings:
        repo.save_findings(machine_id, list(findings))
    session.commit()


def _pkg(name, source=None, deps=()):
    return Package(name=name, version="2.36-9", ecosystem=ECO, source_name=source,
                   source_version="2.36-9" if source else None, dependencies=list(deps))


def _finding(binary: str) -> FindingInput:
    return FindingInput(
        cve_id="CVE-2024-2961", cvss_score=8.8, severity=Severity.HIGH, source="osv",
        package_identifier=f"{ECO}:{binary}@2.36-9 (fixed in 2.36-9+deb12u7)",
    )


def test_a_finding_names_every_binary_of_its_source(client, session):
    _host(session, "m1", [
        _pkg("libc6", "glibc"),
        _pkg("libc-bin", "glibc", deps=["libc6"]),
        _pkg("locales", "glibc", deps=["libc-bin"]),
        _pkg("openssh-server", "openssh", deps=["libc6"]),
        _pkg("coreutils", "coreutils", deps=["libc6"]),
    ], [_finding("libc-bin")])

    [finding] = client.get("/api/machines/m1/cves").json()

    assert finding["package_name"] == "libc-bin"
    assert finding["affected_packages"] == ["libc-bin", "libc6", "locales"]
    # Dependents of every part of glibc, not counting glibc's own binaries.
    assert sorted(finding["depended_on_by"]) == ["coreutils", "openssh-server"]


def test_an_inventory_from_before_0_8_15_names_the_binary_alone(client, session):
    _host(session, "m1", [_pkg("libc6"), _pkg("libc-bin")], [_finding("libc-bin")])

    [finding] = client.get("/api/machines/m1/cves").json()

    assert finding["affected_packages"] == ["libc-bin"]


def test_the_fleet_list_names_the_binary_it_has(client, session):
    """GET /api/cves loads no inventories, so it cannot know the siblings."""
    _host(session, "m1", [_pkg("libc6", "glibc"), _pkg("libc-bin", "glibc")],
          [_finding("libc-bin")])

    [finding] = client.get("/api/cves").json()

    assert finding["affected_packages"] == ["libc-bin"]


def test_each_machine_counts_its_unchecked_kernel_packages(client, session):
    _host(session, "with-kernel", [
        _pkg("linux-image-6.1.0-9-amd64", "linux"),
        _pkg("linux-image-6.1.0-18-amd64", "linux"),
        _pkg("linux-libc-dev", "linux"),  # headers for userspace, from the kernel source
        _pkg("linux-base", "linux-base"),  # not a kernel
        _pkg("libc6", "glibc"),
    ])
    _host(session, "no-kernel", [_pkg("libc6", "glibc")])  # a container
    _host(session, "never-scanned", None)

    by_id = {m["machine_id"]: m for m in client.get("/api/machines").json()}

    # linux-libc-dev is built from the linux source, so it is not checked either.
    assert by_id["with-kernel"]["kernel_packages_unchecked"] == 3
    assert by_id["no-kernel"]["kernel_packages_unchecked"] == 0
    assert by_id["never-scanned"]["kernel_packages_unchecked"] is None
    assert client.get("/api/machines/with-kernel").json()["kernel_packages_unchecked"] == 3


def test_only_the_latest_inventory_counts(client, session):
    _host(session, "m1", [_pkg("linux-image-6.1.0-9-amd64", "linux")])
    Repository(session).save_inventory(Inventory(
        machine_id="m1", os_info=OsInfo(name="Debian", version="12"), packages=[_pkg("libc6")]))
    session.commit()

    assert client.get("/api/machines/m1").json()["kernel_packages_unchecked"] == 0
