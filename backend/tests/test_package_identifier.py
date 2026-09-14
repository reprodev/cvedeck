"""Package names in fix commands come from the identifier's right-hand side.

Validates Req 14.5.

Found on a real Debian 13 host: splitting the identifier on its first colon
turned ``Debian:13:openssl@...`` into ``13:openssl``, so the host's whole fix
plan -- and every single-package copy -- asked apt for packages that do not
exist. The same cases are pinned in frontend/src/lib/remediation.test.ts, so the
two parsers cannot drift apart again.
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
from app.data.schema import Base, TargetMachine
from app.enums import Platform, ScanStatus, Severity, SyncStatus
from app.package_identifier import parse_package_name
from tests.auth_helpers import override_auth

CASES = [
    # A versioned ecosystem: the Debian 13 case that broke.
    ("Debian:13:7zip@25.01+dfsg-1 (fixed in 25.01+dfsg-2)", "7zip"),
    ("Debian:13:python3.13@3.13.5-2", "python3.13"),
    ("Debian:13:netplan.io@1.1.2-2", "netplan.io"),
    ("Ubuntu:22.04:LTS:openssl@3.0.2-0ubuntu1.10", "openssl"),
    ("Alpine:v3.20:busybox@1.36.1-r29 (fixed in 1.36.1-r30)", "busybox"),
    # An epoch in the version must not be mistaken for the ecosystem separator.
    ("Debian:13:bash@1:5.2.37-2 (fixed in 1:5.2.37-3)", "bash"),
    ("Red Hat:openssl@1:3.0.7-27.el9", "openssl"),
    # "Red Hat" contains a space; splitting on whitespace used to yield "Red".
    ("Red Hat:openssl@1:3.0.7-27.el9 (fixed in 1:3.0.7-28.el9)", "openssl"),
    # Unversioned ecosystems and bare names still work.
    ("deb:curl@7.81.0", "curl"),
    ("openssl", "openssl"),
    # An npm scope's "@" is part of the name.
    ("npm:@scope/pkg@1.0.0", "@scope/pkg"),
    ("npm:@scope/pkg", "@scope/pkg"),
    (None, None),
    ("   ", None),
]


@pytest.mark.parametrize("identifier, expected", CASES)
def test_the_package_name_is_read_from_the_right(identifier, expected):
    assert parse_package_name(identifier) == expected


def test_the_api_serves_the_real_package_name_for_a_versioned_ecosystem():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            TargetMachine(
                id="m1",
                hostname="host.example.com",
                platform=Platform.LINUX,
                last_scan_status=ScanStatus.SUCCESS,
                sync_status=SyncStatus.SYNCED,
            )
        )
        Repository(session).save_findings(
            "m1",
            [
                FindingInput(
                    cve_id="CVE-2025-0001",
                    cvss_score=9.8,
                    severity=Severity.CRITICAL,
                    source="osv",
                    package_identifier="Debian:13:openssl@3.5.1-1 (fixed in 3.5.1-2)",
                ),
                FindingInput(
                    cve_id="CVE-2025-0002",
                    cvss_score=7.5,
                    severity=Severity.HIGH,
                    source="osv",
                    package_identifier="Debian:13:bash@1:5.2.37-2 (fixed in 1:5.2.37-3)",
                ),
            ],
        )
        session.commit()

        app = override_auth(create_app())
        app.dependency_overrides[get_session] = lambda: session
        body = TestClient(app).get("/api/machines/m1/cves").json()

    by_cve = {f["cve_id"]: f for f in body}
    assert by_cve["CVE-2025-0001"]["package_name"] == "openssl"
    assert by_cve["CVE-2025-0001"]["fixed_version"] == "3.5.1-2"
    assert by_cve["CVE-2025-0002"]["package_name"] == "bash"
    assert by_cve["CVE-2025-0002"]["fixed_version"] == "1:5.2.37-3"
