"""Tests for the KEV and EPSS feed parsers and their HTTP clients.

The parsers are pure functions over recorded fixture payloads -- no live HTTP
anywhere in this file. The upstream field naming is the brittle part of these
clients, and fixtures are the only way to pin it without making the suite
depend on CISA and FIRST being reachable.

Property-based tests cover the parsers' central guarantee: a malformed row must
cost only that row, never the whole feed. Losing an entire catalogue to one bad
entry would silently reclassify every known-exploited finding as unremarkable.
"""

from __future__ import annotations

import gzip
import json

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.scanner.epss_client import EpssHttpClient, parse_epss_csv
from app.scanner.kev_client import KevHttpClient, parse_kev_catalog


# --------------------------------------------------------------------------- #
# Fixtures: recorded upstream payload shapes
# --------------------------------------------------------------------------- #

KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.09.01",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a JNDI injection flaw.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2024-3400",
            "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS",
            "vulnerabilityName": "PAN-OS Command Injection",
            "dateAdded": "2024-04-12",
            "shortDescription": "Command injection in the GlobalProtect feature.",
            "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2023-4863",
            "vendorProject": "Google",
            "product": "Chrome",
            "vulnerabilityName": "libwebp Heap Buffer Overflow",
            "dateAdded": "2023-09-13",
            "dueDate": "2023-10-04",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}

EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-09-01T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.944120,0.999510\n"
    "CVE-2024-3400,0.941030,0.999200\n"
    "CVE-2019-0001,0.000430,0.101200\n"
)


# --------------------------------------------------------------------------- #
# KEV parsing
# --------------------------------------------------------------------------- #


def test_kev_parses_every_documented_field():
    records = {r.cve_id: r for r in parse_kev_catalog(KEV_PAYLOAD)}

    assert set(records) == {"CVE-2021-44228", "CVE-2024-3400", "CVE-2023-4863"}
    log4j = records["CVE-2021-44228"]
    assert log4j.vendor_project == "Apache"
    assert log4j.product == "Log4j2"
    assert log4j.vulnerability_name == "Apache Log4j2 Remote Code Execution"
    assert log4j.date_added == "2021-12-10"
    assert log4j.due_date == "2021-12-24"
    assert log4j.notes == "Apache Log4j2 contains a JNDI injection flaw."


def test_kev_ransomware_flag_is_only_set_for_known():
    """"Unknown" must not read as ransomware use.

    This is the signal most likely to trigger an out-of-hours response, so
    overstating it is the more damaging error.
    """
    records = {r.cve_id: r for r in parse_kev_catalog(KEV_PAYLOAD)}
    assert records["CVE-2021-44228"].known_ransomware_use is True
    assert records["CVE-2024-3400"].known_ransomware_use is False
    assert records["CVE-2023-4863"].known_ransomware_use is False


def test_kev_cve_ids_are_upper_cased():
    """The id is the join key against findings, so its case cannot vary."""
    records = parse_kev_catalog(
        {"vulnerabilities": [{"cveID": "cve-2021-44228"}]}
    )
    assert [r.cve_id for r in records] == ["CVE-2021-44228"]


def test_kev_entry_without_a_cve_id_is_dropped():
    """An entry with no id can never match a finding, so it is not stored."""
    records = parse_kev_catalog(
        {
            "vulnerabilities": [
                {"vendorProject": "Nobody", "product": "Nothing"},
                {"cveID": "CVE-2020-1234"},
            ]
        }
    )
    assert [r.cve_id for r in records] == ["CVE-2020-1234"]


def test_kev_malformed_entry_does_not_discard_the_catalogue():
    """One bad entry costs one entry, never the whole feed."""
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228"},
            "not-an-object",
            None,
            42,
            {"cveID": "CVE-2024-3400"},
        ]
    }
    records = parse_kev_catalog(payload)
    assert {r.cve_id for r in records} == {"CVE-2021-44228", "CVE-2024-3400"}


def test_kev_duplicate_cve_ids_collapse_to_one_entry():
    records = parse_kev_catalog(
        {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "product": "old"},
                {"cveID": "CVE-2021-44228", "product": "new"},
            ]
        }
    )
    assert len(records) == 1
    assert records[0].product == "new"


@pytest.mark.parametrize("payload", [None, "string", 42, [], {}, {"vulnerabilities": {}}])
def test_kev_unusable_payload_yields_no_records(payload):
    assert parse_kev_catalog(payload) == []


@given(
    st.lists(
        st.one_of(
            st.none(),
            st.text(max_size=20),
            st.integers(),
            st.dictionaries(st.text(max_size=10), st.text(max_size=10), max_size=4),
        ),
        max_size=30,
    )
)
def test_kev_parser_never_raises_on_arbitrary_entries(entries):
    """Whatever CISA publishes, the parser degrades rather than throwing.

    A raise here would propagate to the refresh service and be recorded as a
    feed outage, which is a misleading diagnosis for a parsing defect.
    """
    records = parse_kev_catalog({"vulnerabilities": entries})
    assert all(r.cve_id for r in records)


# --------------------------------------------------------------------------- #
# EPSS parsing
# --------------------------------------------------------------------------- #


def test_epss_skips_the_model_version_comment_line():
    """The comment line precedes the real header.

    Without skipping it, DictReader takes ``#model_version:...`` as the header
    and every row parses to garbage while still looking like a successful
    import.
    """
    records = {r.cve_id: r for r in parse_epss_csv(EPSS_CSV)}
    assert set(records) == {"CVE-2021-44228", "CVE-2024-3400", "CVE-2019-0001"}
    assert records["CVE-2021-44228"].score == pytest.approx(0.944120)
    assert records["CVE-2021-44228"].percentile == pytest.approx(0.999510)


def test_epss_reads_columns_by_name_not_position():
    """An added upstream column must not shift score into percentile."""
    csv_text = (
        "#model_version:v1\n"
        "cve,model_version,epss,percentile\n"
        "CVE-2021-44228,v1,0.9,0.99\n"
    )
    records = parse_epss_csv(csv_text)
    assert len(records) == 1
    assert records[0].score == pytest.approx(0.9)
    assert records[0].percentile == pytest.approx(0.99)


def test_epss_rejects_out_of_range_probabilities():
    """A value above 1.0 means the layout changed; it is not clamped.

    Clamping would persist a wrong number as though it had been measured.
    """
    csv_text = (
        "cve,epss,percentile\n"
        "CVE-2000-0001,1.5,0.5\n"
        "CVE-2000-0002,-0.2,0.5\n"
        "CVE-2000-0003,0.5,0.5\n"
    )
    records = parse_epss_csv(csv_text)
    assert [r.cve_id for r in records] == ["CVE-2000-0003"]


def test_epss_malformed_row_does_not_discard_the_score_set():
    csv_text = (
        "cve,epss,percentile\n"
        "CVE-2000-0001,0.5,0.5\n"
        ",0.5,0.5\n"
        "CVE-2000-0002,not-a-number,0.5\n"
        "CVE-2000-0003,0.25,0.75\n"
    )
    records = parse_epss_csv(csv_text)
    assert {r.cve_id for r in records} == {"CVE-2000-0001", "CVE-2000-0003"}


def test_epss_unrecognized_header_yields_no_records():
    """Better to import nothing than to import the wrong column as a score."""
    assert parse_epss_csv("alpha,beta,gamma\n1,2,3\n") == []


@pytest.mark.parametrize("text", ["", "\n\n", "#only a comment\n"])
def test_epss_empty_input_yields_no_records(text):
    assert parse_epss_csv(text) == []


@given(st.text(max_size=400))
def test_epss_parser_never_raises_on_arbitrary_text(text):
    records = parse_epss_csv(text)
    assert all(0.0 <= r.score <= 1.0 for r in records)
    assert all(0.0 <= r.percentile <= 1.0 for r in records)


# --------------------------------------------------------------------------- #
# HTTP clients (transport mocked, no network)
# --------------------------------------------------------------------------- #


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_kev_client_fetches_and_parses():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("known_exploited_vulnerabilities.json")
        return httpx.Response(200, json=KEV_PAYLOAD)

    client = KevHttpClient(
        "https://example.test/known_exploited_vulnerabilities.json",
        http_client=_mock_client(handler),
    )
    assert len(client.fetch()) == 3


def test_kev_client_propagates_transport_failure():
    """Errors must not be swallowed into an empty list.

    An empty result here would replace a good catalogue with nothing on a
    transient blip, erasing every KEV flag in the fleet.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = KevHttpClient("https://example.test/kev", http_client=_mock_client(handler))
    with pytest.raises(httpx.HTTPStatusError):
        client.fetch()


def test_epss_client_gunzips_an_opaque_download():
    """The feed is served as a .gz file, not with Content-Encoding: gzip."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=gzip.compress(EPSS_CSV.encode()))

    client = EpssHttpClient(
        "https://example.test/epss.csv.gz", http_client=_mock_client(handler)
    )
    assert len(client.fetch()) == 3


def test_epss_client_handles_a_pre_decompressed_body():
    """Some CDNs decode transparently; sniffing the magic bytes covers both."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=EPSS_CSV.encode())

    client = EpssHttpClient(
        "https://example.test/epss.csv.gz", http_client=_mock_client(handler)
    )
    assert len(client.fetch()) == 3


def test_epss_client_propagates_transport_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = EpssHttpClient(
        "https://example.test/epss.csv.gz", http_client=_mock_client(handler)
    )
    with pytest.raises(httpx.HTTPStatusError):
        client.fetch()


def test_kev_client_accepts_a_bare_list_document():
    """Tolerating a top-level list costs nothing and survives a reshape."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps([{"cveID": "CVE-2021-44228"}]).encode()
        )

    client = KevHttpClient("https://example.test/kev", http_client=_mock_client(handler))
    assert [r.cve_id for r in client.fetch()] == ["CVE-2021-44228"]
