"""What the data sources may send, and what a breach turns into (Req 10.18, 8.13).

Each feed client reads a bounded body, the EPSS gunzip is bounded, redirects
stay on the host that was asked, and a breach takes the path every other
unanswered question takes: a failed refresh that keeps the previous cache, or
an OSV lookup reported as unavailable -- never an empty answer (Req 10.1).
"""

from __future__ import annotations

import gzip
import json
import time

import httpx
import pytest

from app.models import Package
from app.scanner import discovery, epss_client, kev_client
from app.scanner.epss_client import EpssHttpClient
from app.scanner.http_bounds import (
    ResponseTooLargeError,
    UnexpectedRedirectError,
    gunzip_limited,
    request_limited,
)
from app.scanner.kev_client import KevHttpClient
from app.scanner.osv_client import OsvHttpClient, OsvUnavailableError

_EPSS = b"#model_version:v2025.03.14,score_date:2026-09-24T00:00:00+0000\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n"
_KEV = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "vendorProject": "v", "product": "p",
                              "vulnerabilityName": "n", "dateAdded": "2024-01-01",
                              "shortDescription": "d", "requiredAction": "a",
                              "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"}]}


def _client(handler, **kwargs) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)


class _Stream(httpx.SyncByteStream):
    """A body that arrives in chunks and never says how long it is."""

    def __init__(self, chunk: bytes, count: int) -> None:
        self.chunk, self.count, self.sent = chunk, count, 0

    def __iter__(self):
        for _ in range(self.count):
            self.sent += 1
            yield self.chunk


# --- the helper ------------------------------------------------------------


def test_a_body_over_the_limit_is_refused_without_reading_it_all():
    stream = _Stream(b"x" * 1024, 10_000)
    client = _client(lambda request: httpx.Response(200, stream=stream))

    with pytest.raises(ResponseTooLargeError):
        request_limited(client, "GET", "https://feed.test/x", limit=64 * 1024)

    assert stream.sent < 100  # stopped at the limit, not at the end


def test_a_declared_length_over_the_limit_is_refused_up_front():
    client = _client(lambda r: httpx.Response(200, headers={"content-length": "999999999"}, content=b"{}"))

    with pytest.raises(ResponseTooLargeError):
        request_limited(client, "GET", "https://feed.test/x", limit=1024)


def test_a_body_that_lies_about_its_length_is_still_counted():
    stream = _Stream(b"x" * 1024, 100)
    client = _client(lambda r: httpx.Response(200, headers={"content-length": "10"}, stream=stream))

    with pytest.raises(ResponseTooLargeError):
        request_limited(client, "GET", "https://feed.test/x", limit=8 * 1024)


def test_a_compressed_transfer_is_bounded_by_what_it_expands_to():
    """Content-Encoding: gzip is decoded by httpx; the limit counts the decoded bytes."""
    bomb = gzip.compress(b"\0" * (4 * 1024 * 1024))  # ~4 KB on the wire
    client = _client(lambda r: httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb))

    with pytest.raises(ResponseTooLargeError):
        request_limited(client, "GET", "https://feed.test/x", limit=1024 * 1024)


def test_a_body_under_the_limit_reads_as_before():
    client = _client(lambda r: httpx.Response(200, json={"ok": True}))

    response = request_limited(client, "GET", "https://feed.test/x", limit=1024)

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_gunzip_refuses_a_bomb():
    bomb = gzip.compress(b"\0" * (8 * 1024 * 1024))

    with pytest.raises(ResponseTooLargeError):
        gunzip_limited(bomb, limit=1024 * 1024)


def test_gunzip_reads_every_member_and_up_to_the_limit():
    payload = gzip.compress(b"a" * 1000) + gzip.compress(b"b" * 1000)

    assert gunzip_limited(payload, limit=2000) == b"a" * 1000 + b"b" * 1000
    with pytest.raises(ResponseTooLargeError):
        gunzip_limited(payload, limit=1999)


# --- the clients -----------------------------------------------------------


def test_epss_refuses_a_gzip_bomb(monkeypatch):
    monkeypatch.setattr(epss_client, "_MAX_DECOMPRESSED", 1024 * 1024)
    bomb = gzip.compress(_EPSS + b"\0" * (8 * 1024 * 1024))
    client = EpssHttpClient(
        "https://feed.test/epss.csv.gz",
        http_client=_client(lambda r: httpx.Response(200, content=bomb)),
    )

    with pytest.raises(ResponseTooLargeError):
        client.fetch()


def test_epss_follows_a_redirect_on_the_same_host():
    """The real "current" URL redirects to a dated file; that must keep working."""
    def handler(request):
        if request.url.path == "/epss_scores-current.csv.gz":
            return httpx.Response(302, headers={"location": "/epss_scores-2026-09-24.csv.gz"})
        return httpx.Response(200, content=gzip.compress(_EPSS))

    client = EpssHttpClient(
        "https://feed.test/epss_scores-current.csv.gz",
        http_client=_client(handler, follow_redirects=True),
    )

    assert [r.cve_id for r in client.fetch()] == ["CVE-2024-0001"]


def test_epss_refuses_a_redirect_to_another_host():
    def handler(request):
        if request.url.host == "feed.test":
            return httpx.Response(302, headers={"location": "https://elsewhere.test/epss.csv.gz"})
        return httpx.Response(200, content=gzip.compress(_EPSS))

    client = EpssHttpClient(
        "https://feed.test/epss.csv.gz",
        http_client=_client(handler, follow_redirects=True),
    )

    with pytest.raises(UnexpectedRedirectError):
        client.fetch()


def test_kev_refuses_an_oversized_catalogue(monkeypatch):
    monkeypatch.setattr(kev_client, "_MAX_CATALOGUE", 1024)
    big = json.dumps({"vulnerabilities": _KEV["vulnerabilities"] * 50}).encode()
    client = KevHttpClient(
        "https://feed.test/kev.json",
        http_client=_client(lambda r: httpx.Response(200, content=big)),
    )

    with pytest.raises(ResponseTooLargeError):
        client.fetch()


def test_an_oversized_osv_answer_is_unavailable_not_clean(monkeypatch):
    from app.scanner import osv_client

    monkeypatch.setattr(osv_client, "_MAX_OSV_RESPONSE", 1024)

    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-1"}]}]})
        return httpx.Response(200, content=b'{"vulns": [' + b'{"id": "x"},' * 500 + b'{"id": "y"}]}')

    client = OsvHttpClient(http_client=_client(handler))

    with pytest.raises(OsvUnavailableError):
        client.match_packages([Package(name="linux", version="6.1.0-1", ecosystem="Debian:12")])


# --- discovery (Req 8.13) --------------------------------------------------


def test_a_resolver_that_never_answers_costs_the_timeout_not_the_sweep(monkeypatch):
    monkeypatch.setattr(discovery, "_DNS_TIMEOUT_S", 0.2)
    monkeypatch.setattr(discovery.socket, "getfqdn", lambda ip: time.sleep(5) or "late.lan")

    started = time.monotonic()
    name = discovery._reverse_dns("192.0.2.10")

    assert name == ""
    assert time.monotonic() - started < 1.5


def test_a_prompt_answer_is_still_used(monkeypatch):
    monkeypatch.setattr(discovery.socket, "getfqdn", lambda ip: "nas.lan")

    assert discovery._reverse_dns("192.0.2.11") == "nas.lan"
