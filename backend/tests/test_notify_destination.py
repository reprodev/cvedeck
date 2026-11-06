"""Where an alert may go (Req 21.10, 21.12, 21.14, 21.15, 21.17).

No live network: the resolver is a stub, and the only real socket is a TLS
server on 127.0.0.1 that this file starts itself, to prove the pinned connection
still verifies the certificate against the configured name.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from app.enums import NotificationStatus
from app.services import notify_destination as nd


def cfg(**overrides) -> nd.NotifyConfig:
    base = dict(
        url="https://alerts.home.example.org/hook",
        kind="webhook",
        token=None,
        secret=None,
        detail_requested="summary",
        allow_http=False,
        allow_public=False,
        link=False,
        public_url=None,
        problems=(),
    )
    base.update(overrides)
    return nd.NotifyConfig(**base)


def destination(**overrides) -> nd.Destination:
    policy = nd.evaluate(cfg(**overrides))
    assert policy.destination is not None
    return policy.destination


def resolver_for(*answers: str):
    calls: list[str] = []

    def resolve(host: str, port: int):
        calls.append(host)
        return list(answers)

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


# --- Static rules -------------------------------------------------------------


def test_nothing_is_configured_without_a_url():
    policy = nd.evaluate(cfg(url=None))
    assert not policy.configured and policy.destination is None and not policy.usable


@pytest.mark.parametrize(
    "url, problem",
    [
        ("ftp://alerts.home.example.org/x", "http:// or https://"),
        ("https://user:pw@alerts.home.example.org/x", "username or password"),
    ],
)
def test_bad_urls_are_problems(url, problem):
    policy = nd.evaluate(cfg(url=url))
    assert not policy.usable
    assert any(problem in p for p in policy.problems)
    # A refusal never repeats the URL: a password in it would land in the dashboard.
    assert all("pw@" not in p for p in policy.problems)


def test_a_token_is_not_sent_over_plain_http_without_the_opt_in():
    """Req 21.12."""
    refused = nd.evaluate(cfg(url="http://alerts.home.example.org/hook", token="tk_secret"))
    assert not refused.usable and any("plain http" in p for p in refused.problems)
    allowed = nd.evaluate(
        cfg(url="http://alerts.home.example.org/hook", token="tk_secret", allow_http=True)
    )
    assert allowed.usable
    # Without a token there is nothing to protect, so plain http is fine.
    assert nd.evaluate(cfg(url="http://alerts.home.example.org/hook")).usable


def test_detailed_needs_a_token():
    """Req 21.14."""
    policy = nd.evaluate(cfg(detail_requested="detailed"))
    assert policy.detail_in_effect == "summary"
    assert "token" in (policy.detail_reason or "")


@pytest.mark.parametrize("host", ["ntfy.sh", "NTFY.SH", "eu.ntfy.sh", "ntfy.sh."])
def test_detailed_never_goes_to_public_ntfy(host):
    """Req 21.14: a token on ntfy.sh proves the right to publish, not privacy."""
    policy = nd.evaluate(
        cfg(
            url=f"https://{host}/cvd-7k2m9q4x8r1t6w3p0a5s",
            kind="ntfy",
            token="tk_secret",
            detail_requested="detailed",
            allow_public=True,
        )
    )
    assert policy.detail_in_effect == "summary"
    assert "ntfy.sh" in (policy.detail_reason or "")


def test_detailed_with_a_token_to_a_private_server_is_detailed():
    policy = nd.evaluate(cfg(token="tk_secret", detail_requested="detailed"))
    assert policy.detail_in_effect == "detailed" and policy.detail_reason is None


@pytest.mark.parametrize(
    "topic, ok",
    [
        ("alerts", False),
        ("cvedeck-fleet-alerts-home", False),  # long, but no digit
        ("12345678901234567890", False),  # long, but no letter
        ("cvd-7k2m9q4x8r1t6w3p", True),
    ],
)
def test_public_ntfy_topics_must_be_strong(topic, ok):
    """Req 21.17, checked whenever public destinations are allowed."""
    policy = nd.evaluate(cfg(url=f"https://ntfy.sh/{topic}", kind="ntfy", allow_public=True))
    assert policy.usable is ok
    # A weak topic on the LAN is the operator's business.
    assert nd.evaluate(cfg(url=f"https://ntfy.home.example.org/{topic}", kind="ntfy")).usable


def test_an_ntfy_url_must_name_one_topic():
    assert not nd.evaluate(cfg(url="https://ntfy.home.example.org/", kind="ntfy")).usable


def test_the_policy_repr_never_shows_the_url_or_token():
    """Req 21.10: a policy that ends up in a log line must not carry secrets."""
    policy = nd.evaluate(cfg(url="https://alerts.home.example.org/hook/s3cr3t-path", token="tk_secret"))
    text = repr(policy) + repr(policy.destination)
    assert "s3cr3t-path" not in text and "tk_secret" not in text


def test_bad_environment_values_become_problems_not_crashes(monkeypatch):
    monkeypatch.setenv("CVEDECK_NOTIFY_URL", "https://alerts.home.example.org/hook")
    monkeypatch.setenv("CVEDECK_NOTIFY_KIND", "carrier-pigeon")
    monkeypatch.setenv("CVEDECK_NOTIFY_TOKEN_FILE", "/nonexistent/token-file")
    policy = nd.evaluate(nd.read_config())
    assert not policy.usable
    assert any("CVEDECK_NOTIFY_KIND" in p for p in policy.problems)
    assert any("CVEDECK_NOTIFY_TOKEN_FILE could not be read" == p for p in policy.problems)
    assert all("/nonexistent" not in p for p in policy.problems)


def test_secrets_are_read_from_files(monkeypatch, tmp_path):
    secret_file = tmp_path / "token"
    secret_file.write_text("tk_from_file\n", encoding="utf-8")
    monkeypatch.setenv("CVEDECK_NOTIFY_TOKEN", "tk_from_env")
    monkeypatch.setenv("CVEDECK_NOTIFY_TOKEN_FILE", str(secret_file))
    assert nd.read_config().token == "tk_from_file"


# --- Address check (Req 21.15) ------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.20",
     "169.254.1.1", "100.64.0.1", "100.127.255.254", "::1", "fd12:3456::1",
     "fe80::1", "::ffff:10.0.0.1"],
)
def test_lan_addresses_are_allowed(address):
    assert nd.is_allowed_address(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    "address",
    [
        # RFC 5737 documentation ranges: ipaddress.is_private calls these
        # private, which is exactly why the allowlist is explicit.
        "192.0.2.10", "198.51.100.10", "203.0.113.10",
        "0.0.0.0", "8.8.8.8", "100.128.0.1", "172.32.0.1", "224.0.0.1",
        "2001:db8::1", "2606:4700::1111", "::ffff:8.8.8.8",
    ],
)
def test_public_and_special_addresses_are_refused(address):
    assert not nd.is_allowed_address(ipaddress.ip_address(address))


def test_every_answer_must_pass_not_just_the_first():
    dest = destination()
    with pytest.raises(nd.DestinationRefused, match="public address"):
        nd.pinned_address(dest, timeout=1, resolver=resolver_for("10.0.0.5", "203.0.113.7"))


def test_a_refusal_names_the_host_but_never_the_path():
    dest = destination(url="https://alerts.home.example.org/hook/s3cr3t-path")
    result = nd.send(dest, headers={}, body=b"{}", resolver=resolver_for("203.0.113.7"))
    assert result.status is NotificationStatus.REFUSED
    assert "alerts.home.example.org" in (result.error or "")
    assert "s3cr3t-path" not in (result.error or "")


def test_public_destinations_are_not_resolved_or_pinned_when_allowed():
    resolver = resolver_for("203.0.113.7")
    assert nd.pinned_address(destination(allow_public=True), timeout=1, resolver=resolver) is None
    assert resolver.calls == []


class _Recorder:
    """An httpx transport that records requests and answers with one status."""

    def __init__(self, *statuses: int, error: Exception | None = None):
        self.statuses = list(statuses)
        self.error = error
        self.requests: list[httpx.Request] = []

    def factory(self, **kwargs):
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if self.error is not None:
                raise self.error
            return httpx.Response(self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0])

        self.kwargs = kwargs
        return httpx.Client(transport=httpx.MockTransport(handle), **kwargs)


def test_the_connection_goes_to_the_checked_address():
    """A resolver that changes its answer between check and connect cannot redirect."""
    answers = iter([["10.0.0.5"], ["203.0.113.7"]])
    recorder = _Recorder(200)
    result = nd.send(
        destination(),
        headers={"Content-Type": "application/json"},
        body=b"{}",
        resolver=lambda host, port: next(answers),
        client_factory=recorder.factory,
    )
    assert result.status is NotificationStatus.SENT
    (request,) = recorder.requests
    assert request.url.host == "10.0.0.5"
    assert request.headers["host"] == "alerts.home.example.org"
    assert request.extensions.get("sni_hostname") == "alerts.home.example.org"
    assert recorder.kwargs["follow_redirects"] is False
    assert recorder.kwargs["trust_env"] is False


def test_a_port_is_kept_in_the_host_header():
    recorder = _Recorder(204)
    nd.send(
        destination(url="https://alerts.home.example.org:8443/hook"),
        headers={}, body=b"{}", resolver=resolver_for("192.168.1.9"),
        client_factory=recorder.factory,
    )
    (request,) = recorder.requests
    assert str(request.url) == "https://192.168.1.9:8443/hook"
    assert request.headers["host"] == "alerts.home.example.org:8443"


def test_the_token_travels_as_a_bearer_header():
    recorder = _Recorder(200)
    nd.send(destination(token="tk_secret"), headers={}, body=b"{}",
            resolver=resolver_for("10.0.0.5"), client_factory=recorder.factory)
    assert recorder.requests[0].headers["authorization"] == "Bearer tk_secret"


# --- Delivery outcomes (Req 21.8, 21.12) --------------------------------------


def _send(recorder, **dest):
    sleeps: list[float] = []
    result = nd.send(destination(**dest), headers={}, body=b"{}",
                     resolver=resolver_for("10.0.0.5"), client_factory=recorder.factory,
                     sleep=sleeps.append)
    return result, sleeps


def test_a_5xx_is_retried_once():
    recorder = _Recorder(503, 200)
    result, sleeps = _send(recorder)
    assert result.status is NotificationStatus.SENT
    assert len(recorder.requests) == 2 and sleeps == [nd.RETRY_DELAY_SECONDS]


def test_a_4xx_is_not_retried_and_names_only_host_and_status():
    recorder = _Recorder(401)
    result, sleeps = _send(recorder, url="https://alerts.home.example.org/hook/s3cr3t")
    assert result.status is NotificationStatus.FAILED
    assert result.error == "alerts.home.example.org: HTTP 401"
    assert len(recorder.requests) == 1 and sleeps == []


def test_a_redirect_is_not_followed():
    recorder = _Recorder(302)
    result, _ = _send(recorder)
    assert result.status is NotificationStatus.FAILED
    assert "redirects are not followed" in (result.error or "")
    assert len(recorder.requests) == 1


def test_a_connection_error_is_retried_and_reported_by_class():
    recorder = _Recorder(error=httpx.ConnectError("boom https://alerts.home.example.org/hook/s3cr3t"))
    result, sleeps = _send(recorder, url="https://alerts.home.example.org/hook/s3cr3t")
    assert result.status is NotificationStatus.FAILED
    assert result.error == "alerts.home.example.org: ConnectError"
    assert len(recorder.requests) == 2 and len(sleeps) == 1


def test_send_never_raises():
    recorder = _Recorder(error=RuntimeError("a bug, with tk_secret in it"))
    result, _ = _send(recorder, token="tk_secret")
    assert result.status is NotificationStatus.FAILED
    assert "tk_secret" not in (result.error or "")


# --- The pinned TLS connection still verifies the name -----------------------


def _certificate(tmp_path, name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture()
def tls_server(tmp_path):
    """An HTTPS server on 127.0.0.1 presenting a certificate for notify.test."""
    cert_path, key_path = _certificate(tmp_path, "notify.test")
    received: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    trust = ssl.create_default_context(cafile=str(cert_path))
    try:
        yield server.server_address[1], trust, received
    finally:
        server.shutdown()
        server.server_close()


def test_pinned_https_verifies_the_certificate_against_the_name(tls_server):
    port, trust, received = tls_server
    result = nd.send(
        destination(url=f"https://notify.test:{port}/hook"),
        headers={}, body=b"{}", timeout=5,
        resolver=resolver_for("127.0.0.1"),
        client_factory=lambda **kw: httpx.Client(verify=trust, **kw),
    )
    assert result.status is NotificationStatus.SENT, result.error
    assert received[0]["Host"] == f"notify.test:{port}"


def test_pinned_https_refuses_a_certificate_for_another_name(tls_server):
    """The server's certificate is for notify.test; the operator named another host."""
    port, trust, received = tls_server
    result = nd.send(
        destination(url=f"https://other.test:{port}/hook"),
        headers={}, body=b"{}", timeout=5,
        resolver=resolver_for("127.0.0.1"),
        client_factory=lambda **kw: httpx.Client(verify=trust, **kw),
        sleep=lambda s: None,
    )
    assert result.status is NotificationStatus.FAILED
    assert received == []
