"""Unit tests for the core domain models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.enums import Platform
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine


def test_os_info_construction():
    os_info = OsInfo(name="Ubuntu", version="22.04")
    assert os_info.name == "Ubuntu"
    assert os_info.version == "22.04"


def test_package_defaults_ecosystem_to_none():
    pkg = Package(name="openssl", version="3.0.2")
    assert pkg.ecosystem is None


def test_package_with_ecosystem():
    pkg = Package(name="requests", version="2.31.0", ecosystem="PyPI")
    assert pkg.ecosystem == "PyPI"


def test_inventory_holds_os_and_packages():
    inv = Inventory(
        machine_id="m1",
        os_info=OsInfo(name="Debian", version="12"),
        packages=[Package(name="curl", version="7.88.1", ecosystem="deb")],
        collected_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    assert inv.machine_id == "m1"
    assert inv.os_info.name == "Debian"
    assert len(inv.packages) == 1
    assert inv.packages[0].name == "curl"


def test_inventory_packages_default_empty():
    inv = Inventory(machine_id="m2", os_info=OsInfo(name="Windows", version="10"))
    assert inv.packages == []
    assert inv.collected_at is None


def test_target_machine_construction():
    target = TargetMachine(id="t1", hostname="host.example.com", platform=Platform.LINUX)
    assert target.platform == Platform.LINUX
    assert target.platform == "linux"


def test_credentials_secret_is_not_exposed_in_repr():
    creds = Credentials(username="admin", password="s3cr3t")
    rendered = repr(creds) + str(creds)
    assert "s3cr3t" not in rendered
    assert creds.password.get_secret_value() == "s3cr3t"


def test_credentials_secret_is_not_exposed_in_serialization():
    creds = Credentials(username="admin", password="s3cr3t")
    dumped = creds.model_dump_json()
    assert "s3cr3t" not in dumped


def test_missing_required_field_raises():
    with pytest.raises(ValidationError):
        OsInfo(name="Ubuntu")  # missing version
