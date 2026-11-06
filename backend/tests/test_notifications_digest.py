"""What an alert says, and when one is sent (Req 21.2-21.7, 21.11, 21.13, 21.16).

Feature: notifications, Property 23: an alert is sent exactly when there is
something to act on, and says no more than it may.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from app.data.repository import FindingDiff, FindingSnapshot
from app.enums import (
    SEVERITY_RANK,
    NotificationThreshold,
    ScanJobStatus,
    ScanStatus,
    Severity,
)
from app.services import notifications as n
from app.services.notify_destination import Destination

FINISHED_AT = datetime(2026, 11, 7, 3, 4, tzinfo=timezone.utc)


def dest(**overrides) -> Destination:
    base = dict(
        kind="webhook", url="https://alerts.home.example.org/hook", scheme="https",
        host="alerts.home.example.org", port=443, token=None, secret=None,
        detail="summary", allow_public=False, link_url=None,
    )
    base.update(overrides)
    return Destination(**base)


def snap(cve="CVE-2026-0001", severity=Severity.CRITICAL, kev=None, pkg="deb:openssl@3.0.1"):
    return FindingSnapshot(cve_id=cve, package_identifier=pkg, severity=severity,
                           cvss_score=9.8, kev_listed=kev)


def diff(*new, baseline=False):
    return FindingDiff(new=tuple(new), resolved=(), baseline=baseline,
                       resolved_assessed=True, scanned_at=FINISHED_AT)


def host(name="web-01", *new, status=ScanStatus.SUCCESS, sources_ok=True, baseline=False):
    d = None if status is not ScanStatus.SUCCESS else diff(*new, baseline=baseline)
    return n.HostOutcome(hostname=name, status=status, sources_ok=sources_ok, diff=d)


def digest(*outcomes, status=ScanJobStatus.FINISHED, requested_by="schedule",
           threshold=NotificationThreshold.CRITICAL, include_not_checked=True, kev_usable=True):
    return n.build_digest(
        job_status=status, requested_by=requested_by, finished_at=FINISHED_AT,
        outcomes=list(outcomes), threshold=threshold,
        include_not_checked=include_not_checked, kev_feed_usable=kev_usable,
    )


# --- When ------------------------------------------------------------------------


def test_a_job_a_person_started_sends_nothing():
    """Req 21.2."""
    assert digest(host("web-01", snap(kev=True)), requested_by="admin") is None


def test_only_finished_or_cancelled_jobs_send():
    outcome = host("web-01", snap(kev=True))
    assert digest(outcome, status=ScanJobStatus.FINISHED) is not None
    assert digest(outcome, status=ScanJobStatus.CANCELLED).cancelled
    assert digest(outcome, status=ScanJobStatus.INTERRUPTED) is None


def test_a_baseline_contributes_nothing():
    """Req 21.3, even if a caller hands over a baseline with findings in it."""
    assert digest(host("web-01", snap(kev=True), baseline=True)) is None


def test_nothing_qualifying_and_everything_checked_sends_nothing():
    """Req 21.6: no nightly all-clear."""
    assert digest(host("web-01", snap(severity=Severity.MEDIUM, kev=False))) is None
    assert digest(host("web-01")) is None


def test_an_unchecked_host_is_worth_a_message_unless_switched_off():
    """Req 21.5."""
    failed = host("nas-01", status=ScanStatus.CONNECTION_FAILURE)
    partial = host("web-02", sources_ok=False)
    d = digest(failed, partial)
    assert [h.reason for h in d.not_checked] == ["connection_failure", "partial"]
    assert digest(failed, partial, include_not_checked=False) is None


def test_thresholds():
    """Req 21.4. HIGH includes UNSCORED, which ranks above it."""
    findings = [snap(f"CVE-2026-000{i}", s, kev=False) for i, s in enumerate(Severity)]
    by = {t: digest(host("web-01", *findings), threshold=t) for t in NotificationThreshold}
    assert by[NotificationThreshold.KEV] is None
    assert by[NotificationThreshold.CRITICAL].qualifying == 1
    assert by[NotificationThreshold.HIGH].qualifying == 3


def test_kev_listed_findings_always_qualify():
    d = digest(host("web-01", snap(severity=Severity.LOW, kev=True)),
               threshold=NotificationThreshold.KEV)
    assert d.qualifying == d.kev == 1


def test_an_unknown_kev_state_is_counted_as_unknown_never_as_clear():
    """Req 21.4, the enrichment invariant: None is "not checked"."""
    d = digest(host("web-01", snap(kev=None), snap("CVE-2026-0002", kev=False)))
    assert d.kev == 0 and d.kev_unknown == 1 and d.qualifying == 2
    assert any("no exploitation answer" in line for line in n.summary_lines(d))


def test_an_unusable_kev_feed_is_said_out_loud():
    d = digest(host("web-01", snap(kev=None)), kev_usable=False)
    text = "\n".join(n.summary_lines(d))
    assert "exploitation check did not run" in text
    assert "not exploited" not in text


# --- What it may say --------------------------------------------------------


EVIL = "web-01\r\nX-Injected: 1‮<a href=x>"


def test_scan_text_is_cleaned_and_capped():
    """Req 21.11."""
    d = digest(host(EVIL, snap(pkg="deb:" + "p" * 400 + "@1")))
    (alert,) = d.hosts
    assert "\r" not in alert.hostname and "\n" not in alert.hostname
    assert "‮" not in alert.hostname
    assert len(alert.findings[0].package or "") <= n.MAX_FIELD_LENGTH


def test_headers_never_carry_scan_data():
    """Req 21.11: a hostname a compromised host chose cannot reach a header."""
    d = digest(host(EVIL, snap(kev=True)), host("nas-01", status=ScanStatus.AUTH_FAILURE))
    for detail in ("summary", "detailed"):
        headers, _ = n.render_ntfy(d, dest(kind="ntfy", detail=detail))
        for value in headers.values():
            assert "web-01" not in value and "nas-01" not in value and "CVE-" not in value
            assert value.isascii() and "\r" not in value and "\n" not in value
    assert "Markdown" not in headers and "X-Markdown" not in headers


def test_a_summary_names_nothing():
    """Req 21.7, 21.16."""
    d = digest(host("web-01", snap(kev=True)), host("nas-01", status=ScanStatus.AUTH_FAILURE))
    _, ntfy_body = n.render_ntfy(d, dest(kind="ntfy"))
    _, webhook_body = n.render_webhook(d, dest())
    for body in (ntfy_body.decode(), webhook_body.decode()):
        for forbidden in ("web-01", "nas-01", "CVE-2026", "openssl", "cvedeck_version", "dashboard_url", "http"):
            assert forbidden not in body, forbidden


def test_detailed_names_hosts_and_findings():
    d = digest(host("web-01", snap(kev=True)))
    payload = json.loads(n.render_webhook(d, dest(detail="detailed"))[1])
    assert payload["hosts"][0]["hostname"] == "web-01"
    assert payload["hosts"][0]["new"][0] == {
        "cve_id": "CVE-2026-0001", "severity": "critical", "cvss": 9.8,
        "kev_listed": True, "package": "openssl",
    }
    assert "cvedeck_version" in payload


def test_the_link_is_opt_in():
    """Req 21.16."""
    d = digest(host("web-01", snap(kev=True)))
    link = "https://cvedeck.home.example.org"
    headers, _ = n.render_ntfy(d, dest(kind="ntfy", link_url=link))
    assert headers["Click"] == link + "/#/jobs"
    assert json.loads(n.render_webhook(d, dest(link_url=link))[1])["dashboard_url"] == link + "/#/jobs"


def test_kev_null_stays_null_in_detailed_json():
    d = digest(host("web-01", snap(kev=None)))
    payload = json.loads(n.render_webhook(d, dest(detail="detailed"))[1])
    assert payload["hosts"][0]["new"][0]["kev_listed"] is None


def test_a_long_detailed_ntfy_body_is_cut_under_ntfys_limit():
    many = [snap(f"CVE-2026-{i:05d}", kev=True) for i in range(400)]
    d = digest(host("web-01", *many))
    _, body = n.render_ntfy(d, dest(kind="ntfy", detail="detailed"))
    assert len(body) < 4096
    assert body.decode().rstrip().endswith("more lines")


def test_webhook_signature_verifies():
    """Req 21.13: what a receiver would compute."""
    d = digest(host("web-01", snap(kev=True)))
    headers, body = n.render_webhook(d, dest(secret="s3cret"), now=lambda: 1_790_000_000)
    assert headers["X-CveDeck-Timestamp"] == "1790000000"
    expected = hmac.new(b"s3cret", b"1790000000." + body, hashlib.sha256).hexdigest()
    assert headers["X-CveDeck-Signature"] == "sha256=" + expected
    assert "X-CveDeck-Signature" not in n.render_webhook(d, dest())[0]


def test_priority_follows_exploitation():
    exploited = digest(host("web-01", snap(kev=True)))
    critical = digest(host("web-01", snap(kev=False)))
    unchecked = digest(host("nas-01", status=ScanStatus.CONNECTION_FAILURE))
    assert [n.render_ntfy(d, dest(kind="ntfy"))[0]["Priority"] for d in (exploited, critical, unchecked)] == ["5", "4", "3"]


# --- Property 23 -------------------------------------------------------------


# Mostly distinctive names, which a leak check can look for without colliding
# with the message's own words, plus arbitrary text for the cleaning path.
hostnames = st.one_of(st.from_regex(r"host-[a-z0-9]{6}", fullmatch=True), st.text(min_size=1, max_size=40))
snapshots = st.builds(
    FindingSnapshot,
    cve_id=st.from_regex(r"CVE-20[0-9]{2}-[0-9]{4,6}", fullmatch=True),
    package_identifier=st.one_of(st.none(), st.from_regex(r"deb:[a-z][a-z0-9-]{0,20}@1\.[0-9]", fullmatch=True)),
    severity=st.sampled_from(list(Severity)),
    cvss_score=st.one_of(st.none(), st.floats(0, 10)),
    kev_listed=st.sampled_from([True, False, None]),
)
outcomes = st.builds(
    lambda name, status, sources_ok, new, baseline: n.HostOutcome(
        hostname=name, status=status, sources_ok=sources_ok,
        diff=None if status is not ScanStatus.SUCCESS else FindingDiff(
            new=() if baseline else tuple(new), resolved=(), baseline=baseline,
            resolved_assessed=True, scanned_at=FINISHED_AT),
    ),
    hostnames,
    st.sampled_from(list(ScanStatus)),
    st.booleans(),
    st.lists(snapshots, max_size=6),
    st.booleans(),
)


@settings(max_examples=200)
@given(
    hosts=st.lists(outcomes, max_size=6),
    status=st.sampled_from(list(ScanJobStatus)),
    requested_by=st.sampled_from(["schedule", "admin", "token:ci"]),
    threshold=st.sampled_from(list(NotificationThreshold)),
    include_not_checked=st.booleans(),
    kev_usable=st.booleans(),
)
def test_property_23(hosts, status, requested_by, threshold, include_not_checked, kev_usable):
    d = n.build_digest(
        job_status=status, requested_by=requested_by, finished_at=FINISHED_AT,
        outcomes=hosts, threshold=threshold, include_not_checked=include_not_checked,
        kev_feed_usable=kev_usable,
    )

    def qualifying(s):
        return s.kev_listed is True or (
            threshold is not NotificationThreshold.KEV
            and SEVERITY_RANK[s.severity] <= SEVERITY_RANK[Severity(threshold.value)]
        )

    checked = [h for h in hosts if h.status is ScanStatus.SUCCESS and h.diff and not h.diff.baseline]
    expected_qualifying = [s for h in checked for s in h.diff.new if qualifying(s)]
    unchecked = [h for h in hosts if h.status is not ScanStatus.SUCCESS or not h.sources_ok]
    should_send = (
        requested_by == "schedule"
        and status in (ScanJobStatus.FINISHED, ScanJobStatus.CANCELLED)
        and (bool(expected_qualifying) or (include_not_checked and bool(unchecked)))
    )
    assert (d is not None) is should_send
    if d is None:
        return
    assert d.qualifying == len(expected_qualifying)
    assert d.kev == sum(1 for s in expected_qualifying if s.kev_listed is True)
    assert d.kev_unknown == sum(1 for s in expected_qualifying if s.kev_listed is None)

    # A summary names nothing (Req 21.7, 21.16).
    for render in (n.render_ntfy, n.render_webhook):
        headers, body = render(d, dest(kind="ntfy" if render is n.render_ntfy else "webhook"))
        text = body.decode() + json.dumps(headers)
        for s in expected_qualifying:
            assert s.cve_id not in text
        assert "cvedeck_version" not in text and "dashboard_url" not in text
        for h in [*d.hosts, *d.not_checked]:
            if h.hostname.startswith("host-"):
                assert h.hostname not in text
