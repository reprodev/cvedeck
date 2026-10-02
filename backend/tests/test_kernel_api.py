"""A host's kernels, and which of its kernel findings are in the running one (Req 12.6, 12.8).

The packages below are the Debian 12 kernel fixture's own rows
(tests/fixtures/packages/debian_12_kernel.tsv), plus an older ABI kernel
left installed -- the state a host is in after an upgrade, before a reboot.
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
NEW = "linux-image-6.1.0-53-amd64"
OLD = "linux-image-6.1.0-52-amd64"


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


def _pkg(name, version, source, source_version=None):
    return Package(name=name, version=version, ecosystem=ECO, source_name=source,
                   source_version=source_version or version)


PACKAGES = [
    _pkg(NEW, "6.1.187-1", "linux-signed-amd64", "6.1.187+1"),
    _pkg("linux-image-amd64", "6.1.187-1", "linux-signed-amd64", "6.1.187+1"),
    _pkg("linux-headers-6.1.0-53-amd64", "6.1.187-1", "linux"),
    _pkg(OLD, "6.1.180-1", "linux-signed-amd64", "6.1.180+1"),
    _pkg("libc6", "2.36-9+deb12u14", "glibc"),
]


def _finding(cve: str, binary: str, version: str) -> FindingInput:
    return FindingInput(cve_id=cve, cvss_score=7.8, severity=Severity.HIGH, source="osv",
                        package_identifier=f"{ECO}:{binary}@{version}")


def _host(session, release: str | None, packages=PACKAGES, ecosystem=ECO):
    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(Inventory(
        machine_id="m1", os_info=OsInfo(name="Debian", version="12"),
        packages=[p.model_copy(update={"ecosystem": ecosystem}) for p in packages],
        kernel_version=release, reboot_required=release == "6.1.0-52-amd64",
    ))
    repo.save_findings("m1", [
        _finding("CVE-2024-0001", OLD, "6.1.180-1"),
        _finding("CVE-2024-0002", NEW, "6.1.187-1"),
        _finding("CVE-2023-4911", "libc6", "2.36-9+deb12u14"),
    ])
    session.commit()


def _by_cve(client):
    return {f["cve_id"]: f for f in client.get("/api/machines/m1/cves").json()}


def test_a_host_running_its_old_kernel(client, session):
    """Upgraded, not rebooted: the old kernel's CVEs are the live ones (Req 12.6)."""
    _host(session, "6.1.0-52-amd64")

    kernel = client.get("/api/machines/m1/kernel").json()
    assert kernel["release"] == "6.1.0-52-amd64"
    assert kernel["checked"] is True
    assert kernel["running_installed"] is True
    assert kernel["reboot_required"] is True
    assert [(k["package"], k["running"], k["newest"]) for k in kernel["installed"]] == [
        (NEW, False, True),
        (OLD, True, False),
    ]
    # A fixed kernel arrives under a new name; only the metapackage brings it.
    assert kernel["upgrade_packages"] == ["linux-image-amd64"]

    findings = _by_cve(client)
    assert (findings["CVE-2024-0001"]["is_kernel"], findings["CVE-2024-0001"]["kernel_running"]) == (True, True)
    assert (findings["CVE-2024-0002"]["is_kernel"], findings["CVE-2024-0002"]["kernel_running"]) == (True, False)
    assert (findings["CVE-2023-4911"]["is_kernel"], findings["CVE-2023-4911"]["kernel_running"]) == (False, None)


def test_each_installed_kernel_lists_only_its_own_binaries(client, session):
    """Two kernels are two sources at two versions, not one (Req 12.6)."""
    _host(session, "6.1.0-53-amd64")

    findings = _by_cve(client)
    assert findings["CVE-2024-0001"]["affected_packages"] == [OLD]
    assert findings["CVE-2024-0002"]["affected_packages"] == [
        "linux-headers-6.1.0-53-amd64", NEW, "linux-image-amd64",
    ]


def test_an_unknown_running_kernel_is_not_shown_as_idle(client, session):
    """No release reported: every kernel finding may be live (Req 12.6)."""
    _host(session, None)

    assert client.get("/api/machines/m1/kernel").json()["running_installed"] is None
    assert {f["kernel_running"] for f in _by_cve(client).values() if f["is_kernel"]} == {None}


def test_a_container_runs_a_kernel_nothing_installed_provides(client, session):
    """The release matches no package: say so, rather than call any kernel running (Req 12.6)."""
    _host(session, "6.6.87.2-microsoft-standard-WSL2")

    kernel = client.get("/api/machines/m1/kernel").json()
    assert kernel["running_installed"] is False
    assert {k["running"] for k in kernel["installed"]} == {False}


def test_an_ubuntu_kernel_says_it_was_not_checked(client, session):
    """Not looked up, and the API says so rather than show it clean (Req 12.5)."""
    _host(session, "6.1.0-53-amd64", ecosystem="Ubuntu:22.04:LTS")

    assert client.get("/api/machines/m1/kernel").json()["checked"] is False


def test_kernel_route_states(client, session):
    """Unknown machine is 404; a machine with nothing collected has no kernel view."""
    assert client.get("/api/machines/nope/kernel").status_code == 404
    Repository(session).upsert_target_machine("m2", "m2", Platform.LINUX, ScanStatus.SUCCESS)
    session.commit()
    response = client.get("/api/machines/m2/kernel")
    assert response.status_code == 200
    assert response.json() is None


def test_the_fleet_list_marks_kernel_findings_without_loading_inventories(client, session):
    """GET /api/cves knows kernel from userland by name; running is not assessed there."""
    _host(session, "6.1.0-52-amd64")

    by_cve = {f["cve_id"]: f for f in client.get("/api/cves").json()}
    assert by_cve["CVE-2024-0001"]["is_kernel"] is True
    assert by_cve["CVE-2024-0001"]["kernel_running"] is None
    assert by_cve["CVE-2023-4911"]["is_kernel"] is False


def test_two_kernel_core_packages_are_two_kernels(client, session):
    """RPM installs each kernel beside the last under one name (Req 12.6).

    The version is all that tells the running kernel-core from the old one, so
    the same CVE in both is two findings, and only one of them is live.
    """
    rocky = "Rocky Linux:9"
    repo = Repository(session)
    repo.upsert_target_machine("m1", "m1", Platform.LINUX, ScanStatus.SUCCESS)
    repo.save_inventory(Inventory(
        machine_id="m1", os_info=OsInfo(name="Rocky Linux", version="9"),
        packages=[
            Package(name="kernel-core", version="5.14.0-362.8.1.el9_3", ecosystem=rocky,
                    source_name="kernel", source_version="5.14.0-362.8.1.el9_3"),
            Package(name="kernel-core", version="5.14.0-284.11.1.el9_2", ecosystem=rocky,
                    source_name="kernel", source_version="5.14.0-284.11.1.el9_2"),
        ],
        kernel_version="5.14.0-362.8.1.el9_3.x86_64",
    ))
    repo.save_findings("m1", [
        FindingInput(cve_id="CVE-2024-1086", cvss_score=7.8, severity=Severity.HIGH, source="osv",
                     package_identifier=f"{rocky}:kernel-core@5.14.0-362.8.1.el9_3"),
        FindingInput(cve_id="CVE-2024-1086", cvss_score=7.8, severity=Severity.HIGH, source="osv",
                     package_identifier=f"{rocky}:kernel-core@5.14.0-284.11.1.el9_2"),
    ])
    session.commit()

    rows = client.get("/api/machines/m1/cves").json()
    running = {r["package_identifier"].rsplit("@", 1)[1]: r["kernel_running"] for r in rows}
    assert running == {"5.14.0-362.8.1.el9_3": True, "5.14.0-284.11.1.el9_2": False}
