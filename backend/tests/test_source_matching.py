"""Advisories are looked up under the name the distribution publishes them under.

Req 2.8: asked under the source package and under each binary, because Debian,
Ubuntu, Alpine, Rocky and SUSE key their advisories by source (``glibc``, not
``libc6``) while AlmaLinux keys some by binary (``vim-minimal``, not ``vim``).

Property 17: however many binaries a source ships as, and however many of the
names asked found it, each CVE is one finding per source package, reported
against one representative binary.

The fake OSV here answers exactly as the real one was measured to: it knows the
advisory only under the name it is published under, and says nothing when
asked about any other name.
"""

from __future__ import annotations

import json

import httpx
from hypothesis import given, settings
from hypothesis import strategies as st

from app.models import Package
from app.package_identifier import is_kernel_package, parse_package_name
from app.scanner.osv_client import OsvHttpClient

ECO = "Debian:12"


def _advisory(cve: str, published_under: str, fixed: str) -> dict:
    return {
        "id": f"DEBIAN-{cve}",
        "aliases": [cve],
        "affected": [{
            "package": {"name": published_under, "ecosystem": ECO},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    }


def _osv(index: dict[str, list[dict]], asked: list[str]):
    """A fake OSV that knows each advisory only under the name it is published under."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if request.url.path.endswith("/querybatch"):
            results = []
            for query in body["queries"]:
                asked.append(query["package"]["name"])
                vulns = index.get(query["package"]["name"], [])
                results.append({"vulns": [{"id": v["id"]} for v in vulns]})
            return httpx.Response(200, json={"results": results})
        name = body["package"]["name"]
        return httpx.Response(200, json={"vulns": index.get(name, [])})

    return OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def _pkg(name: str, source: str | None, version: str = "1.0-1", source_version: str | None = None):
    return Package(name=name, version=version, ecosystem=ECO, source_name=source,
                   source_version=source_version or (version if source else None))


def _binaries(advisories) -> dict[str, set[str]]:
    by_cve: dict[str, set[str]] = {}
    for a in advisories:
        by_cve.setdefault(a.cve_id, set()).add(parse_package_name(a.package_identifier))
    return by_cve


def test_a_library_is_found_under_its_source():
    """The case that under-reported: only libc6 and libc-bin are installed."""
    index = {"glibc": [_advisory("CVE-2024-2961", "glibc", "2.36-9+deb12u7")]}
    host = [_pkg("libc6", "glibc", "2.36-9"), _pkg("libc-bin", "glibc", "2.36-9")]

    found = _osv(index, []).match_packages(host)

    # One finding, on the first binary by name, since no binary is called glibc.
    assert _binaries(found) == {"CVE-2024-2961": {"libc-bin"}}
    [finding] = found
    assert finding.package_identifier == "Debian:12:libc-bin@2.36-9 (fixed in 2.36-9+deb12u7)"


def test_the_binary_named_like_its_source_keeps_the_finding():
    """So a finding already matched through the openssl CLI keeps its identity."""
    index = {"openssl": [_advisory("CVE-2024-5535", "openssl", "3.0.14-1~deb12u1")]}
    host = [_pkg("libssl3", "openssl"), _pkg("openssl", "openssl"), _pkg("libssl-dev", "openssl")]

    found = _osv(index, []).match_packages(host)

    assert _binaries(found) == {"CVE-2024-5535": {"openssl"}}


def test_an_advisory_published_under_a_binary_is_still_found():
    """AlmaLinux publishes vim's advisories under vim-minimal, not vim."""
    index = {"vim-minimal": [_advisory("CVE-2025-0001", "vim-minimal", "2:8.2-30")]}
    host = [_pkg("vim-minimal", "vim", "2:8.2-26"), _pkg("vim-common", "vim", "2:8.2-26")]

    found = _osv(index, []).match_packages(host)

    assert _binaries(found) == {"CVE-2025-0001": {"vim-common"}}


def test_an_advisory_found_under_two_names_is_one_finding():
    """AlmaLinux answers for both openssl and openssl-libs: still one CVE."""
    index = {
        "openssl": [_advisory("CVE-2024-6119", "openssl", "1:3.0.7-28.el9")],
        "openssl-libs": [_advisory("CVE-2024-6119", "openssl-libs", "1:3.0.7-28.el9")],
    }
    host = [_pkg("openssl-libs", "openssl", "1:3.0.7-24.el9"),
            _pkg("openssl", "openssl", "1:3.0.7-24.el9")]

    found = _osv(index, []).match_packages(host)

    assert [a.cve_id for a in found] == ["CVE-2024-6119"]


def test_the_source_version_is_the_one_asked():
    """bash 5.2.15-2+b13 is a rebuild of source 5.2.15-2; OSV's ranges use the source."""
    asked_versions: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        for q in body.get("queries", []):
            asked_versions.append((q["package"]["name"], q["version"]))
        return httpx.Response(200, json={"results": [{} for _ in body.get("queries", [])]})

    client = OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    client.match_packages([_pkg("bash", "bash", "5.2.15-2+b13", "5.2.15-2")])

    assert ("bash", "5.2.15-2") in asked_versions


def test_the_kernel_is_not_yet_looked_up_by_source():
    """Req 12.5: the kernel waits for its own release; asked as before, by binary."""
    asked: list[str] = []
    host = [_pkg("linux-image-6.1.0-9-amd64", "linux", "6.1.27-1")]

    _osv({}, asked).match_packages(host)

    assert "linux" not in asked
    assert "linux-image-6.1.0-9-amd64" in asked
    assert is_kernel_package("linux-image-6.1.0-9-amd64", "linux")
    assert is_kernel_package("linux-libc-dev", "linux")  # built from the kernel source
    assert not is_kernel_package("linux-base", "linux-base")


def test_an_inventory_from_before_0_8_15_is_matched_as_it_was():
    asked: list[str] = []
    _osv({}, asked).match_packages([_pkg("libssl3", None)])

    assert set(asked) == {"libssl3"}


_names = st.sampled_from(["liba", "libb", "libc", "tool", "srcpkg", "srcpkg-dev"])


@settings(max_examples=60, deadline=None)
@given(
    binaries=st.lists(_names, min_size=1, max_size=5, unique=True),
    published_under=st.sampled_from(["source", "binary", "both"]),
    cves=st.lists(st.sampled_from(["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]),
                  min_size=1, max_size=3, unique=True),
)
def test_each_cve_is_one_finding_per_source(binaries, published_under, cves):
    """Property 17, whichever name -- or names -- the advisories are published under."""
    host = [_pkg(name, "srcpkg") for name in binaries]
    publishers = {"source": ["srcpkg"], "binary": [binaries[0]],
                  "both": ["srcpkg", binaries[0]]}[published_under]
    index = {p: [_advisory(c, p, "9.9-1") for c in cves] for p in publishers}

    found = _osv(index, []).match_packages(host)
    by_cve = _binaries(found)

    assert set(by_cve) == set(cves)
    for cve in cves:
        assert len(by_cve[cve]) == 1
        [reported] = by_cve[cve]
        assert reported in binaries
    assert len(found) == len(cves)
