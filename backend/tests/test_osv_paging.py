"""A paged OSV answer is read to its last page, or reported unanswered (Req 2.9).

OSV answers a large ``/query`` in pages and says so with ``next_page_token``.
The client used to read the first page and stop, and the first page reads
exactly like a complete answer: every advisory past it was dropped without a
trace. These tests drive the real client through a mocked transport.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.scanner import osv_client
from app.scanner.osv_client import OsvHttpClient, OsvUnavailableError
from app.models import Package

_PKG = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu")


def _vuln(n: int) -> dict:
    return {
        "id": f"UBUNTU-CVE-2024-{n:04d}",
        "aliases": [f"CVE-2024-{n:04d}"],
        "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu"}}],
    }


def _paged(pages: list[list[int]], fail_page: int | None = None, endless: bool = False):
    """A handler serving ``pages`` of advisories, chained by page tokens."""
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "x"}]} for _ in body["queries"]]},
            )
        token = body.get("page_token")
        seen.append(token)
        index = 0 if token is None else int(token)
        if index == fail_page:
            return httpx.Response(503, json={"message": "unavailable"})
        data: dict = {"vulns": [_vuln(n) for n in pages[index % len(pages)]]}
        if endless or index + 1 < len(pages):
            data["next_page_token"] = str(index + 1)
        return httpx.Response(200, json=data)

    return handler, seen


def _client(handler) -> OsvHttpClient:
    return OsvHttpClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_every_page_is_read():
    """Advisories on the second and third pages are findings too (Req 2.9)."""
    handler, seen = _paged([[1, 2], [3], [4, 5]])
    advisories = _client(handler).match_packages([_PKG])
    assert sorted(a.cve_id for a in advisories) == [f"CVE-2024-{n:04d}" for n in range(1, 6)]
    assert seen == [None, "1", "2"]


def test_a_failed_page_fails_the_query_and_is_not_cached():
    """Two pages of three is not an answer (Req 2.9, 10.1)."""
    handler, _ = _paged([[1], [2], [3]], fail_page=1)
    client = _client(handler)
    with pytest.raises(OsvUnavailableError):
        client.match_packages([_PKG])
    assert client._advisory_cache == {}


def test_an_answer_past_the_page_ceiling_is_unanswered():
    """A server that never stops paging cannot hold a scan, or pass for complete (Req 2.9)."""
    handler, seen = _paged([[1]], endless=True)
    with pytest.raises(OsvUnavailableError):
        _client(handler).match_packages([_PKG])
    assert len(seen) == osv_client._MAX_OSV_PAGES


def test_a_paged_release_answer_keeps_the_release_filter():
    """The ids a release matched are read in full, so the filter still applies (Req 2.9, 14.7).

    The host runs Ubuntu 22.04. OSV's distribution-wide answer has an advisory
    fixed for this release long ago; the 22.04 answer is paged and does not
    list it on any page. Leaving a paged batch answer's ids unknown switched
    the release filter off, and that advisory came back as a finding.
    """
    host = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu:22.04:LTS")
    only_elsewhere = {
        "id": "UBUNTU-CVE-2020-0001",
        "aliases": ["CVE-2020-0001"],
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"}},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/querybatch"):
            results = []
            for q in body["queries"]:
                if q["package"]["ecosystem"] == "Ubuntu":
                    results.append({"vulns": [{"id": "UBUNTU-CVE-2020-0001"}]})
                else:
                    results.append({"vulns": [{"id": _vuln(1)["id"]}], "next_page_token": "1"})
            return httpx.Response(200, json={"results": results})
        if body["package"]["ecosystem"] == "Ubuntu":
            return httpx.Response(200, json={"vulns": [only_elsewhere, _vuln(1), _vuln(2)]})
        # The release, in two pages.
        if body.get("page_token") is None:
            return httpx.Response(200, json={"vulns": [_vuln(1)], "next_page_token": "1"})
        return httpx.Response(200, json={"vulns": [_vuln(2)]})

    advisories = _client(handler).match_packages([host])
    assert "CVE-2020-0001" not in {a.cve_id for a in advisories}


def test_trimming_a_record_changes_nothing_matching_reads():
    """Only unread fields go; every reading function answers the same (Req 2.9).

    Trimmed as each page arrives, which took an old Debian kernel's lookup from
    286 MB to 173 MB at peak, measured with the real client -- and the whole
    result set came out identical.
    """
    from app.scanner.osv_client import _resolve_cve_id, _trim, fix_suffix, parse_cvss

    record = {
        "id": "DEBIAN-CVE-2024-0001",
        "aliases": ["CVE-2024-0001"],
        "upstream": ["CVE-2024-0001"],
        "summary": "s", "details": "d" * 5000, "references": [{"url": "u"}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "HIGH", "source": "x"},
        "affected": [{
            "package": {"name": "openssl", "ecosystem": "Debian:12", "purl": "pkg:deb/openssl"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.11-1"}]}],
            "versions": [f"3.0.{n}-1" for n in range(500)],
            "ecosystem_specific": {"urgency": "low", "severity": "MODERATE"},
        }],
    }
    trimmed = _trim(record)

    assert "versions" not in trimmed["affected"][0]
    assert "details" not in trimmed and "references" not in trimmed
    host = Package(name="openssl", version="3.0.2-1", ecosystem="Debian:12")
    for read in (parse_cvss, _resolve_cve_id):
        assert read(trimmed) == read(record)
    assert fix_suffix(trimmed, host, "Debian", {"debian:12"}) == fix_suffix(record, host, "Debian", {"debian:12"})
