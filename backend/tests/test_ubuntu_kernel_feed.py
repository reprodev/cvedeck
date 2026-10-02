"""Canonical's OVAL CVE feed, read for the Ubuntu kernel (Req 12.11).

The fixture is three definitions cut verbatim from the real 22.04 feed of
2026-10-02, chosen for the three shapes the feed uses: CVE-2024-1086 (fixed
in a stated version for most flavours), CVE-2012-4542 (no fix released), and
CVE-2020-36313 (a flavour under "release installed AND kernel running" with
no version: no fix either).
"""

from __future__ import annotations

import bz2
import io
from pathlib import Path

import httpx
import pytest

from app.enums import Severity
from app.scanner.ubuntu_kernel_feed import (
    UbuntuFeedFormatError,
    UbuntuKernelFeedClient,
    affecting,
    codename_for,
    parse_ubuntu_kernel_oval,
)

FIXTURE = Path(__file__).parent / "fixtures" / "ubuntu_oval" / "jammy-excerpt.cve.oval.xml.bz2"


def _table():
    return parse_ubuntu_kernel_oval(bz2.open(FIXTURE), "jammy")


def _by_cve(rows):
    return {a.cve_id: a for a in rows}


def test_the_generic_kernel_is_read_with_its_fixes():
    linux = _by_cve(_table().by_flavour["linux"])
    assert linux["CVE-2024-1086"].fixed == "5.15.0-101.111"
    assert linux["CVE-2024-1086"].severity is Severity.HIGH
    assert linux["CVE-2012-4542"].fixed is None


def test_a_flavour_with_only_the_running_test_has_no_fix():
    """'Release installed AND kernel running', with no version: vulnerable, unfixed."""
    rows = _table().by_flavour["linux-azure-fde-5.19"]
    assert _by_cve(rows)["CVE-2020-36313"].fixed is None


def test_flavours_are_kept_apart():
    """linux and linux-riscv share a uname pattern; the table does not merge them."""
    table = _table()
    assert "linux" in table.by_flavour and "linux-riscv" in table.by_flavour
    assert table.by_flavour["linux"] is not table.by_flavour["linux-riscv"]


@pytest.mark.parametrize(
    "installed, affected",
    [
        # Before the fix: the fixed CVE and the unfixed one both apply.
        ("5.15.0-25.25", {"CVE-2024-1086", "CVE-2012-4542"}),
        # Exactly the fixed kernel. OVAL compares the uname fragment 5.15.0-101,
        # which sorts before 5.15.0-101.111 and would call this vulnerable.
        ("5.15.0-101.111", {"CVE-2012-4542"}),
        ("5.15.0-198.208", {"CVE-2012-4542"}),
    ],
)
def test_what_applies_to_the_running_kernel_image(installed, affected):
    rows = _table().by_flavour["linux"]
    assert {a.cve_id for a in affecting(installed, rows)} == affected


@pytest.mark.parametrize(
    "ecosystem, codename",
    [("Ubuntu:22.04:LTS", "jammy"), ("Ubuntu:24.04:LTS", "noble"), ("Ubuntu:25.10", "questing"),
     ("Ubuntu:12.04:LTS", None), ("Debian:12", None), (None, None)],
)
def test_codenames(ecosystem, codename):
    assert codename_for(ecosystem) == codename


def _oval(definition_xml: str) -> io.BytesIO:
    return io.BytesIO(
        b'<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>'
        + definition_xml.encode()
        + b"</definitions></oval_definitions>"
    )


def test_an_unknown_shape_fails_the_whole_feed():
    """A format change must read as 'not checked', never as a clean kernel."""
    bad = (
        '<definition class="vulnerability"><metadata><title>CVE-2099-0001 on Ubuntu 22.04 LTS (jammy) - high</title></metadata>'
        '<criteria operator="OR"><criteria operator="AND">'
        "<criterion comment=\"Is kernel 'linux' running?\"/>"
        "<criterion comment=\"'linux' kernel in jammy is affected by something new\"/>"
        "</criteria></criteria></definition>"
    )
    with pytest.raises(UbuntuFeedFormatError, match="unrecognised criterion"):
        parse_ubuntu_kernel_oval(_oval(bad), "jammy")


def test_an_unknown_priority_fails_the_whole_feed():
    bad = (
        '<definition class="vulnerability"><metadata><title>CVE-2099-0001 on Ubuntu 22.04 LTS (jammy) - urgent</title></metadata>'
        "<criteria operator=\"OR\"><criterion comment=\"Is kernel 'linux' running?\"/></criteria></definition>"
    )
    with pytest.raises(UbuntuFeedFormatError, match="priority"):
        parse_ubuntu_kernel_oval(_oval(bad), "jammy")


def test_a_feed_with_no_kernel_advisories_is_refused():
    with pytest.raises(UbuntuFeedFormatError, match="no kernel advisories"):
        parse_ubuntu_kernel_oval(_oval(""), "jammy")


def _client(handler) -> UbuntuKernelFeedClient:
    return UbuntuKernelFeedClient(
        "https://feed.example/oval/com.ubuntu.{codename}.cve.oval.xml.bz2",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_fetch_downloads_parses_and_keeps_the_etag():
    asked = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((str(request.url), request.headers.get("if-none-match")))
        return httpx.Response(200, content=FIXTURE.read_bytes(), headers={"etag": '"abc"'})

    result = _client(handler).fetch("jammy")
    assert asked == [("https://feed.example/oval/com.ubuntu.jammy.cve.oval.xml.bz2", None)]
    assert result.etag == '"abc"' and "linux" in result.table.by_flavour


def test_an_unchanged_feed_is_not_downloaded_again():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["if-none-match"] == '"abc"'
        return httpx.Response(304)

    result = _client(handler).fetch("jammy", etag='"abc"')
    assert result.table is None and result.etag == '"abc"'


def test_a_failed_download_raises_rather_than_returning_an_empty_table():
    with pytest.raises(httpx.HTTPStatusError):
        _client(lambda request: httpx.Response(503)).fetch("jammy")


def test_a_decompression_bomb_is_refused(monkeypatch):
    from app.scanner import ubuntu_kernel_feed

    monkeypatch.setattr(ubuntu_kernel_feed, "_MAX_DECOMPRESSED", 1024)
    with pytest.raises(UbuntuFeedFormatError, match="decompressed past"):
        _client(lambda request: httpx.Response(200, content=FIXTURE.read_bytes())).fetch("jammy")
