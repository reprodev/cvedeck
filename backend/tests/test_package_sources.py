"""Every package carries the source it was built from (Req 1.12).

Distribution advisories are published under the source package: OSV has 51
advisories for Debian 12's ``openssl`` at 3.0.9-1 and none for ``libssl3``, 46
for ``glibc`` and none for ``libc6``. The fixtures here are the collector's own
command run in real containers, so the parser is checked against what these
package managers actually print -- including the cases that make the source
*version* matter as much as the name: a binary-only rebuild (``bash``
5.2.15-2+b13 from source 5.2.15-2) and an epoch the source does not carry
(``bsdutils`` 1:2.38.1-... from ``util-linux`` 2.38.1-...).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine, inspect, text

from app.scanner.collectors import _parse_linux_packages, _parse_source

FIXTURES = Path(__file__).parent / "fixtures" / "packages"


def _load(name: str, ecosystem: str):
    text = (FIXTURES / f"{name}.tsv").read_text(encoding="utf-8")
    return {p.name: p for p in _parse_linux_packages(text, default_ecosystem=ecosystem)}


@pytest.mark.parametrize(
    "fixture, ecosystem, binary, source, source_version",
    [
        ("debian_12", "Debian:12", "libc6", "glibc", "2.36-9+deb12u14"),
        ("debian_12", "Debian:12", "bsdutils", "util-linux", "2.38.1-5+deb12u3"),
        ("debian_12", "Debian:12", "bash", "bash", "5.2.15-2"),
        ("ubuntu_22.04", "Ubuntu:22.04:LTS", "libssl3", "openssl", "3.0.2-0ubuntu1.29"),
        # The source RPM names no epoch; the binary does, and the source shares it.
        ("rockylinux_9", "Rocky Linux:9", "openssl-libs", "openssl", "1:3.0.7-24.el9"),
        ("almalinux_9", "AlmaLinux:9", "vim-minimal", "vim", "2:8.2.2637-26.el9_8.13"),
        ("almalinux_9", "AlmaLinux:9", "glibc-common", "glibc", "2.34-275.el9_8"),
        ("alpine_3.18", "Alpine:v3.18", "libssl3", "openssl", "3.1.8-r0"),
        ("alpine_3.18", "Alpine:v3.18", "musl-utils", "musl", "1.2.4-r3"),
        ("opensuse_leap_15.5", "openSUSE:Leap 15.5", "libopenssl1_1", "openssl-1_1",
         "1.1.1l-150500.17.34.1"),
        ("archlinux_latest", "Arch Linux", "openssl", "openssl", "3.6.4-1"),
    ],
)
def test_real_package_manager_output_names_each_source(
    fixture, ecosystem, binary, source, source_version
):
    package = _load(fixture, ecosystem)[binary]

    assert package.source_name == source
    assert package.source_version == source_version


@pytest.mark.parametrize(
    "fixture, ecosystem",
    [
        ("debian_12", "Debian:12"),
        ("ubuntu_22.04", "Ubuntu:22.04:LTS"),
        ("rockylinux_9", "Rocky Linux:9"),
        ("alpine_3.18", "Alpine:v3.18"),
        ("archlinux_latest", "Arch Linux"),
    ],
)
def test_every_real_package_has_a_source(fixture, ecosystem):
    packages = _load(fixture, ecosystem)

    assert packages
    assert [n for n, p in packages.items() if not p.source_name] == []


def test_rpm_keys_have_no_source():
    """``gpg-pubkey`` rows hold imported signing keys, built from nothing."""
    packages = (FIXTURES / "almalinux_9.tsv").read_text(encoding="utf-8")
    keys = [p for p in _parse_linux_packages(packages, "AlmaLinux:9") if p.name == "gpg-pubkey"]

    assert keys and all(p.source_name is None for p in keys)


@pytest.mark.parametrize(
    "field, expected",
    [
        ("openssl-3.0.7-24.el9.src.rpm", ("openssl", "3.0.7-24.el9")),
        ("openssl-1_1-1.1.1l-150500.17.34.1.src.rpm", ("openssl-1_1", "1.1.1l-150500.17.34.1")),
        ("kernel-5.14.0-362.el9.nosrc.rpm", ("kernel", "5.14.0-362.el9")),
        ("(none)", (None, None)),
        ("", (None, None)),
        ("broken.src.rpm", (None, None)),
    ],
)
def test_source_rpm_names_are_taken_apart(field, expected):
    assert _parse_source(field, "") == expected


def test_three_field_output_from_before_0_8_15_still_parses():
    """A package with no source field is its own source: matched as before."""
    [package] = _parse_linux_packages("libssl3\t3.0.9-1\tlibc6\n", "Debian:12")

    assert package.name == "libssl3"
    assert package.source_name is None and package.source_version is None


_token = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc", "Zs", "Zl", "Zp")),
    min_size=1,
    max_size=20,
).filter(lambda t: "\t" not in t)


@given(name=_token, version=_token.map(lambda v: v + "1"), deps=st.text(max_size=30).filter(
    lambda d: "\t" not in d and "\n" not in d and "\r" not in d))
def test_the_parser_never_invents_a_source(name, version, deps):
    """With no source field, no source -- whatever the other fields hold."""
    for package in _parse_linux_packages(f"{name}\t{version}\t{deps}\n", "Debian:12"):
        assert package.source_name is None
        assert package.source_version is None


def test_the_source_survives_storage():
    """Round trip through the repository, which lists columns by hand."""
    from sqlalchemy.orm import Session

    from app.data.repository import Repository
    from app.data.schema import Base
    from app.enums import Platform, ScanStatus
    from app.models import Inventory, OsInfo, Package

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        repo = Repository(session)
        repo.upsert_target_machine("m1", "h", Platform.LINUX, ScanStatus.SUCCESS)
        repo.save_inventory(Inventory(
            machine_id="m1",
            os_info=OsInfo(name="Debian", version="12"),
            packages=[Package(name="libc6", version="2.36-9+deb12u14", ecosystem="Debian:12",
                              source_name="glibc", source_version="2.36-9+deb12u14")],
        ))
        session.commit()
        [package] = repo.get_latest_inventory_for_machine("m1").packages

    assert (package.source_name, package.source_version) == ("glibc", "2.36-9+deb12u14")


def test_the_package_source_migration_round_trips(tmp_path):
    from alembic import command

    from app.data.migrations_runtime import alembic_config, upgrade_to_head

    engine = create_engine(f"sqlite:///{(tmp_path / 'src.db').as_posix()}")
    upgrade_to_head(engine)
    columns = {c["name"] for c in inspect(engine).get_columns("packages")}
    assert {"source_name", "source_version"} <= columns

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "d8b31c6fa042")
    columns = {c["name"] for c in inspect(engine).get_columns("packages")}
    assert "source_name" not in columns and "source_version" not in columns

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
    with engine.connect() as connection:
        assert connection.execute(text("SELECT source_name FROM packages")).fetchall() == []


def test_an_rpm_version_carries_its_epoch():
    """Without it, every fix published as ``2:...`` reads as newer than the host's."""
    packages = {p.name: p for p in _parse_linux_packages(
        (FIXTURES / "almalinux_9.tsv").read_text(encoding="utf-8"), "AlmaLinux:9")}

    assert packages["vim-minimal"].version.startswith("2:")
    assert packages["glibc"].version[0].isdigit() and ":" not in packages["glibc"].version
