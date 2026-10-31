"""Kernel feeds for Fedora, Arch, Oracle Linux and Amazon Linux 2023 (Req 12.12-12.14).

Feature: cvedeck, Property 21.

Every fixture is real data recorded on 2026-10-31 and trimmed
(tests/fixtures/kernel_feeds): OSV's Linux records, Oracle's OL9 OVAL, Amazon
Linux 2023's repository metadata. Nothing here reaches the network.
"""

from __future__ import annotations

import bz2
import gzip
import json
from pathlib import Path

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.enums import Severity
from app.scanner.kernel_feeds import (
    AmazonKernelFeedClient,
    KernelFeedEntry,
    KernelFeedFormatError,
    KernelFeedTable,
    OracleKernelFeedClient,
    UpstreamKernelFeedClient,
    decode_stream,
    encode_streams,
    feed_key,
    parse_amazon_updateinfo,
    parse_oracle_oval,
    parse_upstream_records,
    rpm_affecting,
    upstream_affecting,
    upstream_version,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel_feeds"


def _pages() -> list[dict]:
    return [json.loads((FIXTURES / f"osv_linux_page{n}.json").read_text(encoding="utf-8")) for n in (1, 2)]


def _upstream_entries() -> list[KernelFeedEntry]:
    return parse_upstream_records(v for page in _pages() for v in page["vulns"])


def _by_cve(verdicts):
    return {v.entry.cve_id: v for v in verdicts}


# --- Upstream: the kernel CNA's records (Req 12.12) ---------------------------


def test_a_kernel_before_its_own_series_fix_is_affected_and_at_it_is_not():
    """CVE-2024-26581 is fixed in 5.4.269 for the 5.4 series."""
    entries = _upstream_entries()
    assert _by_cve(upstream_affecting("5.4.268", entries))["CVE-2024-26581"].fixed == "5.4.269"
    assert "CVE-2024-26581" not in _by_cve(upstream_affecting("5.4.269", entries))


def test_an_overlapping_range_from_another_series_does_not_decide():
    """The case that made a current 6.18 kernel read as 589 CVEs instead of 126.

    CVE-2025-71295 lists "introduced 6.13.0, fixed 6.19.6", which spans 6.18.x
    too -- but 6.18 has its own fix, 6.18.16, and only that one decides.
    """
    entries = _upstream_entries()
    assert "CVE-2025-71295" not in _by_cve(upstream_affecting("6.18.60", entries))
    assert _by_cve(upstream_affecting("6.18.10", entries))["CVE-2025-71295"].fixed == "6.18.16"


def test_with_no_fix_in_its_series_the_earliest_newer_fix_is_offered():
    """CVE-2026-100072 is fixed in 6.6, 6.12 and 7.2, but nothing lists a 6.18 fix."""
    verdict = _by_cve(upstream_affecting("6.18.60", _upstream_entries()))["CVE-2026-100072"]
    assert verdict.fixed is None
    assert verdict.fixed_elsewhere == "7.2.6"


def test_a_kernel_newer_than_every_range_is_not_affected():
    assert upstream_affecting("7.2.13", _upstream_entries()) == []


def test_a_published_score_is_kept_and_a_missing_one_is_unscored():
    entries = {e.cve_id: e for e in _upstream_entries()}
    scored = entries["CVE-2022-48627"]
    assert scored.score is not None and scored.severity is not Severity.UNSCORED
    assert entries["CVE-2026-100072"].score is None
    assert entries["CVE-2026-100072"].severity is Severity.UNSCORED


@pytest.mark.parametrize(
    "version, expected",
    [
        ("6.19.10-300.fc44", "6.19.10"),
        ("7.2.11.arch1-1", "7.2.11"),
        ("6.18.60-1", "6.18.60"),
        ("7.2.11.zen1-1", "7.2.11"),
        ("1:7.3-1", "7.3.0"),
        ("arch", None),
    ],
)
def test_the_upstream_version_a_package_carries(version, expected):
    assert upstream_version(version) == expected


def _osv_transport(pages: list[dict]):
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        assert body["package"] == {"name": "Kernel", "ecosystem": "Linux"}
        assert "version" not in body  # a version query answers nothing for this ecosystem
        index = 1 if body.get("page_token") == "page-2" else 0
        return httpx.Response(200, json=pages[index])

    return httpx.MockTransport(handler), seen


def test_the_client_reads_every_page():
    transport, seen = _osv_transport(_pages())
    client = UpstreamKernelFeedClient("https://osv.test/v1", http_client=httpx.Client(transport=transport))

    result = client.fetch()

    assert len(seen) == 2 and seen[1]["page_token"] == "page-2"
    assert result.table is not None
    assert {e.cve_id for e in result.table.streams["all"]} >= {"CVE-2024-26581", "CVE-2022-48627"}
    # The same set again is not rewritten.
    transport, _ = _osv_transport(_pages())
    again = UpstreamKernelFeedClient("https://osv.test/v1", http_client=httpx.Client(transport=transport))
    assert again.fetch(digest=result.digest).table is None


def test_a_set_with_no_kernel_records_is_refused():
    transport, _ = _osv_transport([{"vulns": []}, {"vulns": []}])
    client = UpstreamKernelFeedClient("https://osv.test/v1", http_client=httpx.Client(transport=transport))
    with pytest.raises(KernelFeedFormatError, match="no kernel advisories"):
        client.fetch()


def test_paging_that_never_ends_is_refused():
    endless = httpx.MockTransport(lambda r: httpx.Response(200, json={"vulns": [], "next_page_token": "again"}))
    client = UpstreamKernelFeedClient("https://osv.test/v1", http_client=httpx.Client(transport=endless), max_pages=3)
    with pytest.raises(KernelFeedFormatError, match="still paging"):
        client.fetch()


def test_an_unknown_range_event_is_refused():
    record = {"id": "CVE-2026-1", "affected": [{"package": {"name": "Kernel", "ecosystem": "Linux"},
              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "6.1"}, {"limit": "6.2"}]}]}]}
    with pytest.raises(KernelFeedFormatError, match="unrecognised range event"):
        parse_upstream_records([record])


# --- Property 21: the kernel's own series decides --------------------------------

series = st.tuples(st.integers(4, 7), st.integers(0, 20))


@st.composite
def kernel_ranges(draw):
    ranges = []
    for major, minor in draw(st.lists(series, min_size=1, max_size=5, unique=True)):
        patch = draw(st.integers(1, 300))
        intro = draw(st.sampled_from(["0", f"{major}.{max(minor - 3, 0)}.0", f"{major}.{minor}.0"]))
        ranges.append((intro, f"{major}.{minor}.{patch}", None))
    return tuple(ranges)


@given(kernel_ranges(), series, st.integers(0, 400))
def test_the_kernels_own_series_fix_alone_decides(ranges, kernel_series, patch):
    """Property 21: at or past its series' fix a kernel is never affected; before it, always."""
    version = f"{kernel_series[0]}.{kernel_series[1]}.{patch}"
    entry = KernelFeedEntry("CVE-2026-0001", Severity.UNSCORED, None, None, ranges)
    verdicts = upstream_affecting(version, [entry])
    own = [int(f.split(".")[2]) for _i, f, _l in ranges if tuple(map(int, f.split(".")[:2])) == kernel_series]
    if own:
        assert bool(verdicts) == (patch < min(own))
        if verdicts:
            assert verdicts[0].fixed is not None and verdicts[0].fixed_elsewhere is None
    for verdict in verdicts:
        # Anything offered from elsewhere is in a newer series than the kernel's.
        if verdict.fixed_elsewhere:
            assert tuple(map(int, verdict.fixed_elsewhere.split(".")[:2])) > kernel_series


# --- Oracle Linux: ELSA OVAL (Req 12.13) ---------------------------------------


def _oracle_table() -> KernelFeedTable:
    return parse_oracle_oval(bz2.open(FIXTURES / "elsa-ol9-sample.xml.bz2"), "9")


def test_oracle_feed_reads_uek_and_the_red_hat_compatible_kernel():
    table = _oracle_table()
    assert table.feed == "oracle:ol9"
    assert set(table.streams) == {"kernel:5.14.0", "kernel-uek:6.12.0"}
    assert all(e.severity is Severity.HIGH for rows in table.streams.values() for e in rows)


def test_oracle_feed_ignores_builds_for_another_release():
    """The OL9 file also carries EL10 UEK builds; an OL9 host cannot install them."""
    raw = bz2.open(FIXTURES / "elsa-ol9-sample.xml.bz2").read().decode("utf-8")
    assert "el10uek" in raw
    assert not any("el10" in (e.fixed or "") for rows in _oracle_table().streams.values() for e in rows)


def test_an_oracle_kernel_older_than_the_fix_is_affected_and_the_fixed_one_is_not():
    rows = _oracle_table().streams["kernel-uek:6.12.0"]
    assert rpm_affecting("6.12.0-202.76.4.4.el9uek", rows)
    assert rpm_affecting("6.12.0-207.111.5.4.el9uek", rows) == []
    assert rpm_affecting("6.12.0-207.111.5.6.el9uek", rows) == []


def test_the_oracle_client_keeps_its_table_when_the_file_is_unchanged():
    payload = (FIXTURES / "elsa-ol9-sample.xml.bz2").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/security/oval/com.oracle.elsa-ol9.xml.bz2"
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=payload, headers={"etag": '"v1"'})

    client = OracleKernelFeedClient(
        "https://oracle.test/security/oval/com.oracle.elsa-ol{release}.xml.bz2",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    first = client.fetch("9")
    assert first.table is not None and first.digest == '"v1"'
    assert client.fetch("9", digest='"v1"').table is None


def test_an_oracle_feed_with_no_kernel_advisories_is_refused():
    oval = (
        b'<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
        b'<definitions><definition class="patch" id="x"><metadata><title>t</title></metadata>'
        b"</definition></definitions></oval_definitions>"
    )
    import io

    with pytest.raises(KernelFeedFormatError, match="no kernel advisories"):
        parse_oracle_oval(io.BytesIO(oval), "9")


# --- Amazon Linux 2023: updateinfo (Req 12.14) ---------------------------------


def _amazon_transport(calls: list[str]):
    files = {
        "/al2023/core/mirrors/latest/x86_64/mirror.list": (FIXTURES / "al2023-mirror.list").read_bytes(),
        "repomd.xml": (FIXTURES / "al2023-repomd.xml").read_bytes(),
        "updateinfo.xml.gz": (FIXTURES / "al2023-updateinfo-sample.xml.gz").read_bytes(),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        for suffix, body in files.items():
            if request.url.path.endswith(suffix):
                return httpx.Response(200, content=body)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _amazon_client(calls):
    return AmazonKernelFeedClient(
        "https://cdn.amazonlinux.com/al{release}/core/mirrors/latest/x86_64/mirror.list",
        http_client=httpx.Client(transport=_amazon_transport(calls)),
    )


def test_amazon_feed_reads_each_kernel_series_through_the_mirror_list():
    calls: list[str] = []
    result = _amazon_client(calls).fetch("2023")

    assert [c.rsplit("/", 1)[-1] for c in calls] == ["mirror.list", "repomd.xml", "updateinfo.xml.gz"]
    assert result.table is not None and result.table.feed == "amazon:al2023"
    assert set(result.table.streams) == {"kernel", "kernel6.12", "kernel6.18"}
    # An unchanged checksum stops before the download.
    calls.clear()
    assert _amazon_client(calls).fetch("2023", digest=result.digest).table is None
    assert not any(c.endswith("updateinfo.xml.gz") for c in calls)


def test_an_amazon_kernel_with_the_epoch_installed_compares_like_the_fix():
    table = parse_amazon_updateinfo(gzip.open(FIXTURES / "al2023-updateinfo-sample.xml.gz"), "2023")
    rows = table.streams["kernel6.12"]
    fixed = rows[0].fixed
    assert rpm_affecting("1:" + fixed.split(":", 1)[-1], rows) == []
    assert rpm_affecting("1:6.12.0-1.amzn2023", rows)


def test_a_mirror_list_without_an_https_repository_is_refused():
    client = AmazonKernelFeedClient(
        "https://cdn.amazonlinux.com/al{release}/mirror.list",
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="http://plain/\n"))),
    )
    with pytest.raises(KernelFeedFormatError, match="https"):
        client.fetch("2023")


# --- Shared ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, ecosystem, expected",
    [
        ("upstream", "Fedora", "upstream"),
        ("upstream", "Arch Linux", "upstream"),
        ("oracle", "Oracle Linux:9", "oracle:ol9"),
        ("oracle", "Oracle Linux", None),
        ("amazon", "Amazon Linux:2023", "amazon:al2023"),
        ("amazon", "Amazon Linux:2", None),
    ],
)
def test_which_stored_feed_a_host_reads(source, ecosystem, expected):
    assert feed_key(source, ecosystem) == expected


def test_stored_rows_read_back_unchanged():
    table = KernelFeedTable("upstream", {"all": _upstream_entries()})
    (count, payload), = encode_streams(table).values()
    assert count == len(table.streams["all"])
    assert decode_stream(payload) == table.streams["all"]
