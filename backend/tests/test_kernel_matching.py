"""The kernel is looked up by source, apart from everything else (Req 12.5, 12.7).

The kernel's ``linux`` source has thousands of advisories per release. It is
asked where that is practical, and asked separately, so that an answer too
large to read -- or an outage part-way through it -- costs a host its kernel
findings and nothing else, and keeps the scan partial rather than reading the
kernel as patched.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.enums import SourceStatus
from app.models import Inventory, OsInfo, Package
from app.package_identifier import kernel_is_matched
from app.scanner.matcher import Matcher
from app.scanner.osv_client import OsvHttpClient, OsvPartialAnswerError

_LIBC = Package(
    name="libc6",
    version="2.36-9+deb12u14",
    ecosystem="Debian:12",
    source_name="glibc",
    source_version="2.36-9+deb12u14",
)
# As dpkg reports it on a real Debian 12 host (tests/fixtures/packages/debian_12_kernel.tsv).
_IMAGE = Package(
    name="linux-image-6.1.0-53-amd64",
    version="6.1.187-1",
    ecosystem="Debian:12",
    source_name="linux-signed-amd64",
    source_version="6.1.187+1",
)
_KBUILD = Package(
    name="linux-kbuild-6.1",
    version="6.1.187-1",
    ecosystem="Debian:12",
    source_name="linux",
    source_version="6.1.187-1",
)


def _vuln(cve: str, name: str) -> dict:
    return {
        "id": f"DEBIAN-{cve}",
        "aliases": [cve],
        "affected": [{"package": {"name": name, "ecosystem": "Debian:12"}}],
    }


def _osv(*, kernel_fails: bool = False, asked: list | None = None) -> OsvHttpClient:
    answers = {"glibc": [_vuln("CVE-2023-4911", "glibc")], "linux": [_vuln("CVE-2024-1086", "linux")]}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        queries = body["queries"] if request.url.path.endswith("/querybatch") else [body]
        if asked is not None:
            asked.extend(q["package"]["name"] for q in queries)
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": v["id"]} for v in answers.get(q["package"]["name"], [])]}
                        for q in queries
                    ]
                },
            )
        name = body["package"]["name"]
        if kernel_fails and name == "linux":
            return httpx.Response(503)
        return httpx.Response(200, json={"vulns": answers.get(name, [])})

    return OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_the_kernel_is_asked_under_its_source_and_reported_against_its_image():
    """A signed image is asked as ``linux`` at the image's own version (Req 12.5)."""
    asked: list[str] = []
    found = {
        a.cve_id: a.package_identifier
        for a in _osv(asked=asked).match_packages([_LIBC, _IMAGE, _KBUILD])
    }

    assert found["CVE-2024-1086"] == "Debian:12:linux-image-6.1.0-53-amd64@6.1.187-1"
    assert found["CVE-2023-4911"] == "Debian:12:libc6@2.36-9+deb12u14"
    assert "linux-signed-amd64" not in asked, "OSV keys Debian's kernel advisories by `linux`"


def test_a_kernel_lookup_that_fails_keeps_the_userland_findings():
    """The kernel's answer failing is partial, never all-or-nothing (Req 12.7)."""
    with pytest.raises(OsvPartialAnswerError) as caught:
        _osv(kernel_fails=True).match_packages([_LIBC, _IMAGE])

    assert [a.cve_id for a in caught.value.advisories] == ["CVE-2023-4911"]


def test_the_matcher_keeps_a_partial_answer_and_marks_the_source_unavailable():
    """Findings that came back are kept; the scan says it is partial (Req 12.7, 10.1)."""
    inventory = Inventory(
        machine_id="host-1",
        os_info=OsInfo(name="Debian", version="12"),
        packages=[_LIBC, _IMAGE],
    )

    result = Matcher().match(inventory, nvd=None, osv=_osv(kernel_fails=True))

    assert result.osv_status is SourceStatus.DATA_SOURCE_UNAVAILABLE
    assert [f.cve_id for f in result.findings] == ["CVE-2023-4911"]


@pytest.mark.parametrize(
    "ecosystem, matched",
    [
        ("Debian:12", True),
        ("Debian", True),
        ("Rocky Linux:9", True),
        ("AlmaLinux:9", True),
        ("Red Hat:9", True),
        ("SUSE:15.6", True),
        ("openSUSE:Leap 15.5", True),
        ("Alpine:v3.18", True),
        # Ubuntu's kernel answer was still paging at 3.5 GB.
        ("Ubuntu:22.04:LTS", False),
        ("Ubuntu", False),
        # Resolved onto a tracker their kernel was not built from.
        ("Arch Linux", False),
        ("Fedora", False),
        ("Oracle Linux:9", False),
        ("deb", False),
        (None, False),
        ("Debianish", False),
    ],
)
def test_which_kernels_are_looked_up(ecosystem, matched):
    assert kernel_is_matched(ecosystem) is matched


def test_an_ubuntu_kernel_is_never_asked_about():
    """Not asked, so it cannot hold up or fail a scan (Req 12.5)."""
    asked: list[str] = []
    image = Package(
        name="linux-image-5.15.0-25-generic",
        version="5.15.0-25.25",
        ecosystem="Ubuntu:22.04:LTS",
        source_name="linux-signed",
        source_version="5.15.0-25.25",
    )

    _osv(asked=asked).match_packages([image])

    assert asked == []


def test_the_same_cve_in_two_installed_kernel_core_packages_is_two_findings():
    """De-duplication keeps a kernel's version: RPM names every kernel kernel-core (Req 12.6)."""
    from app.scanner.matcher import RawAdvisory

    client = OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    rocky = "Rocky Linux:9"
    found = client._deduplicate_findings([
        RawAdvisory(cve_id="CVE-2024-1086", cvss_score=7.8, package_identifier=f"{rocky}:kernel-core@5.14.0-362.8.1.el9_3"),
        RawAdvisory(cve_id="CVE-2024-1086", cvss_score=7.8, package_identifier=f"{rocky}:kernel-core@5.14.0-284.11.1.el9_2"),
        # A userland package is still one finding however its version is written.
        RawAdvisory(cve_id="CVE-2023-4911", cvss_score=7.8, package_identifier="Debian:12:libc6@2.36-9"),
        RawAdvisory(cve_id="CVE-2023-4911", cvss_score=7.8, package_identifier="Debian:12:libc6@2.36-9+deb12u1"),
    ])

    assert sorted(a.package_identifier for a in found if a.cve_id == "CVE-2024-1086") == [
        f"{rocky}:kernel-core@5.14.0-284.11.1.el9_2",
        f"{rocky}:kernel-core@5.14.0-362.8.1.el9_3",
    ]
    assert len([a for a in found if a.cve_id == "CVE-2023-4911"]) == 1


def test_a_patched_kernel_is_not_held_to_another_releases_advisories():
    """The kernel's answer alone does not decide which releases OSV tracks (Req 14.7, 12.7).

    Measured end to end on a current Rocky 9 kernel: OSV returns only RHEL 10
    advisories for it, because every RHEL 9 one is already fixed. Asked apart
    from userland, the kernel's answer never mentioned RHEL 9, so RHEL 9 looked
    untracked and four known-exploited RHEL 10 advisories were kept as "fixed
    upstream". The userland answer shows OSV does track RHEL 9.
    """
    rocky = "Rocky Linux:9"

    def aff(name, eco, fixed):
        return {"package": {"name": name, "ecosystem": eco},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}

    rhel9_openssl = {"id": "RHSA-2025:0001", "aliases": ["CVE-2025-0001"],
                     "affected": [aff("openssl", "Red Hat:enterprise_linux:9::baseos", "1:3.5.1-9.el9")]}
    rhel10_kernel = {"id": "RHSA-2025:0002", "aliases": ["CVE-2024-53104"],
                     "affected": [aff("kernel", "Red Hat:enterprise_linux:10.0", "0:6.12.0-55.13.1.el10_0")]}
    answers = {"openssl": [rhel9_openssl], "kernel": [rhel10_kernel]}

    def matching(name, eco):
        # As OSV answers: the family-wide "Red Hat" matches everything Red Hat
        # publishes for the package; a release ecosystem only what names it.
        return [v for v in answers.get(name, [])
                if eco == "Red Hat" or any(a["package"]["ecosystem"] == eco for a in v["affected"])]

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": v["id"]} for v in matching(q["package"]["name"], q["package"]["ecosystem"])]}
                for q in body["queries"]
            ]})
        return httpx.Response(200, json={"vulns": matching(body["package"]["name"], body["package"]["ecosystem"])})

    client = OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    found = {a.cve_id for a in client.match_packages([
        Package(name="openssl", version="1:3.5.1-7.el9", ecosystem=rocky, source_name="openssl",
                source_version="1:3.5.1-7.el9"),
        Package(name="kernel-core", version="5.14.0-687.53.1.el9_8", ecosystem=rocky, source_name="kernel",
                source_version="5.14.0-687.53.1.el9_8"),
    ])}

    assert "CVE-2025-0001" in found
    assert "CVE-2024-53104" not in found
