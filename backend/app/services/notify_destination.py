"""Where an alert may go, and how it gets there (Req 21.10-21.15, 21.17).

Notifications are the first thing CveDeck sends anywhere on its own initiative,
so the destination is held to rules the dashboard cannot loosen:

* **Environment only.** The URL, token, signing secret and detail level come
  from ``app.config``; no route accepts them (Req 21.10). A stolen API token
  can switch alerts off or on, never point them somewhere else.
* **LAN only by default** (Req 21.15). Every address the destination resolves
  to must sit in :data:`ALLOWED_NETWORKS`, and the request is then sent *to the
  address that was checked* -- with the original ``Host`` header and TLS server
  name, so the certificate is still verified against the name. Resolving once
  to check and letting the HTTP client resolve again to connect would let a DNS
  answer that changes in between redirect the alert.
* **Explicit allowlist, never** ``ipaddress.is_private``. Python answers True
  there for the RFC 5737 documentation ranges, 0.0.0.0/8 and other special-use
  blocks, none of which is "my LAN".
* **Errors name the host, never the URL** (Req 21.10, 21.12). A webhook path
  often embeds its own secret and an ntfy topic *is* a password, so a failure is
  recorded as ``"<host>: HTTP 401"`` or ``"<host>: ConnectError"`` and nothing
  more -- never ``str(exc)``, which for httpx carries the full URL, and never
  the response body, which is not even read.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Sequence

import httpx

from app import config
from app.enums import NotificationStatus

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: The networks an alert may reach without ``CVEDECK_NOTIFY_ALLOW_PUBLIC``.
#: Loopback, RFC 1918, link-local, RFC 6598 shared space (CGNAT; Tailscale
#: addresses live here), and their IPv6 counterparts.
ALLOWED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(net)
    for net in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

#: The public ntfy service. A token there proves the right to publish to a
#: topic, not that the topic is reserved -- anyone who guesses its name may be
#: able to read it -- so detailed alerts never go there (Req 21.14).
PUBLIC_NTFY_HOST = "ntfy.sh"

#: One retry, after this long, for a connection error or a 5xx (Req 21.8).
RETRY_DELAY_SECONDS = 5.0

_MIN_PUBLIC_TOPIC_LENGTH = 20


class DestinationRefused(Exception):
    """The policy declined to send. ``str()`` is safe to store and show."""


@dataclass(frozen=True)
class NotifyConfig:
    """One reading of the environment, so a decision never mixes two."""

    url: str | None
    kind: str
    token: str | None = field(repr=False)
    secret: str | None = field(repr=False)
    detail_requested: str
    allow_http: bool
    allow_public: bool
    link: bool
    public_url: str | None
    #: Values the environment holds but that could not be used.
    problems: tuple[str, ...] = ()


def read_config() -> NotifyConfig:
    """Read every notification setting, turning a bad value into a problem.

    A typo in a notification variable must not stop the app from starting --
    scanning matters more than alerting -- so it is reported in the dashboard
    instead, and nothing is sent until it is fixed.
    """
    problems: list[str] = []

    def attempt(getter: Callable[[], object], fallback: object, label: str) -> object:
        try:
            return getter()
        except ValueError as exc:
            problems.append(str(exc))
        except OSError:
            # Name the variable, not the error: an OSError message can quote a
            # path the operator would rather not see in a browser.
            problems.append(f"{label} could not be read")
        return fallback

    return NotifyConfig(
        url=config.notify_url(),
        kind=str(attempt(config.notify_kind, "webhook", "CVEDECK_NOTIFY_KIND")),
        token=attempt(config.notify_token, None, "CVEDECK_NOTIFY_TOKEN_FILE"),  # type: ignore[arg-type]
        secret=attempt(config.notify_secret, None, "CVEDECK_NOTIFY_SECRET_FILE"),  # type: ignore[arg-type]
        detail_requested=str(attempt(config.notify_detail, "summary", "CVEDECK_NOTIFY_DETAIL")),
        allow_http=config.notify_allow_http(),
        allow_public=config.notify_allow_public(),
        link=config.notify_link(),
        public_url=config.public_url(),
        problems=tuple(problems),
    )


@dataclass(frozen=True)
class Destination:
    """A destination the static rules accept. Never serialise it whole."""

    kind: str
    url: str = field(repr=False)
    scheme: str
    host: str
    port: int
    token: str | None = field(repr=False)
    secret: str | None = field(repr=False)
    detail: str
    allow_public: bool
    link_url: str | None


@dataclass(frozen=True)
class Policy:
    """What the configuration amounts to, as the dashboard shows it."""

    configured: bool
    kind: str
    destination_host: str | None
    #: Why nothing can be sent as configured. Empty when it can.
    problems: tuple[str, ...]
    detail_in_effect: str
    #: Why detailed was asked for and summary is used, else ``None``.
    detail_reason: str | None
    allow_http: bool
    allow_public: bool
    link: bool
    signed: bool
    destination: Destination | None = field(default=None, repr=False)

    @property
    def usable(self) -> bool:
        return self.destination is not None and not self.problems


def is_public_ntfy(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == PUBLIC_NTFY_HOST or host.endswith("." + PUBLIC_NTFY_HOST)


def topic_is_strong(topic: str) -> bool:
    """At least 20 characters, with letters and digits (Req 21.17)."""
    return (
        len(topic) >= _MIN_PUBLIC_TOPIC_LENGTH
        and re.search(r"[A-Za-z]", topic) is not None
        and re.search(r"[0-9]", topic) is not None
    )


def evaluate(cfg: NotifyConfig) -> Policy:
    """Apply every rule that needs no network (Req 21.12, 21.14, 21.17).

    The address check (Req 21.15) needs DNS and happens at send time, in
    :func:`send`.
    """
    problems = list(cfg.problems)
    signed = cfg.secret is not None and cfg.kind == "webhook"

    def policy(host: str | None, destination: Destination | None,
               detail: str, reason: str | None) -> Policy:
        return Policy(
            configured=cfg.url is not None,
            kind=cfg.kind,
            destination_host=host,
            problems=tuple(problems),
            detail_in_effect=detail,
            detail_reason=reason,
            allow_http=cfg.allow_http,
            allow_public=cfg.allow_public,
            link=cfg.link and cfg.public_url is not None,
            signed=signed,
            destination=destination,
        )

    if cfg.url is None:
        return policy(None, None, "summary", None)

    try:
        url = httpx.URL(cfg.url)
    except (httpx.InvalidURL, ValueError):
        problems.append("CVEDECK_NOTIFY_URL is not a valid URL")
        return policy(None, None, "summary", None)

    host = url.host
    scheme = url.scheme.lower()
    if scheme not in {"http", "https"}:
        problems.append("CVEDECK_NOTIFY_URL must start with http:// or https://")
    if not host:
        problems.append("CVEDECK_NOTIFY_URL has no host")
        return policy(None, None, "summary", None)
    if url.userinfo:
        # A password in the URL would travel in every log line that quotes it.
        problems.append(
            "CVEDECK_NOTIFY_URL must not contain a username or password; "
            "use CVEDECK_NOTIFY_TOKEN"
        )
    topic = url.path.strip("/")
    if cfg.kind == "ntfy":
        if not topic or "/" in topic:
            problems.append("an ntfy URL must name one topic, e.g. https://ntfy.example.org/<topic>")
        elif cfg.allow_public and not topic_is_strong(topic):
            # Checked whenever public destinations are allowed, not only once
            # the name is seen to resolve publicly: a name can change its answer.
            problems.append(
                "with public destinations allowed, the ntfy topic must be at least "
                f"{_MIN_PUBLIC_TOPIC_LENGTH} characters with letters and digits"
            )
    if cfg.token is not None and scheme == "http" and not cfg.allow_http:
        problems.append(
            "a token is set but the URL is plain http; use https, or set "
            "CVEDECK_NOTIFY_ALLOW_HTTP=1 to send it unencrypted"
        )

    detail, reason = "summary", None
    if cfg.detail_requested == "detailed":
        if cfg.token is None:
            reason = "Detailed alerts need an access token; sending summaries."
        elif is_public_ntfy(host):
            reason = (
                "Detailed alerts are never sent to ntfy.sh, where a topic may be "
                "readable by anyone who guesses it; sending summaries."
            )
        else:
            detail = "detailed"

    destination = Destination(
        kind=cfg.kind,
        url=str(url),
        scheme=scheme,
        host=host,
        port=url.port or (443 if scheme == "https" else 80),
        token=cfg.token,
        secret=cfg.secret if cfg.kind == "webhook" else None,
        detail=detail,
        allow_public=cfg.allow_public,
        link_url=cfg.public_url if cfg.link else None,
    )
    return policy(host, destination, detail, reason)


# --- Address check (Req 21.15) ----------------------------------------------

Resolver = Callable[[str, int], Sequence[str]]


def _system_resolver(host: str, port: int) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def is_allowed_address(address: IPAddress) -> bool:
    """Whether an address is on the local network (Req 21.15)."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(
        address.version == network.version and address in network
        for network in ALLOWED_NETWORKS
    )


def resolve(host: str, port: int, *, timeout: float,
            resolver: Resolver = _system_resolver) -> list[IPAddress]:
    """Every address ``host`` resolves to, in order, without duplicates.

    ``getaddrinfo`` has no timeout of its own, so it runs on a helper thread
    and is abandoned after ``timeout``.
    """
    try:
        return [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        pass
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        answers = pool.submit(resolver, host, port).result(timeout=timeout)
    except concurrent.futures.TimeoutError as exc:
        raise DestinationRefused(f"{host}: name lookup timed out") from exc
    except OSError as exc:
        raise DestinationRefused(f"{host}: name lookup failed") from exc
    finally:
        pool.shutdown(wait=False)
    seen: list[IPAddress] = []
    for raw in answers:
        address = ipaddress.ip_address(str(raw).split("%", 1)[0])
        if address not in seen:
            seen.append(address)
    if not seen:
        raise DestinationRefused(f"{host}: name lookup returned no address")
    return seen


def pinned_address(destination: Destination, *, timeout: float,
                   resolver: Resolver = _system_resolver) -> IPAddress | None:
    """The checked address to connect to, or ``None`` when public is allowed.

    Every answer must pass, not just the first: a name with one private and one
    public answer could otherwise be steered to the public one by whichever
    order the resolver happens to return.
    """
    if destination.allow_public:
        return None
    addresses = resolve(destination.host, destination.port, timeout=timeout, resolver=resolver)
    if not all(is_allowed_address(a) for a in addresses):
        raise DestinationRefused(
            f"{destination.host} resolves to a public address; alerts stay on the "
            "local network unless CVEDECK_NOTIFY_ALLOW_PUBLIC=1 is set"
        )
    return addresses[0]


# --- Sending -----------------------------------------------------------------


@dataclass(frozen=True)
class SendResult:
    status: NotificationStatus
    #: Host plus status or error class; never the URL, token or body.
    error: str | None = None


ClientFactory = Callable[..., httpx.Client]


def _pinned_request_target(destination: Destination, address: IPAddress | None
                           ) -> tuple[httpx.URL, dict[str, str], dict[str, object]]:
    url = httpx.URL(destination.url)
    if address is None:
        return url, {}, {}
    default_port = 443 if destination.scheme == "https" else 80
    host_header = destination.host if destination.port == default_port else (
        f"{destination.host}:{destination.port}"
    )
    if ":" in destination.host:  # an IPv6 literal keeps its brackets in Host
        host_header = f"[{destination.host}]" if destination.port == default_port else (
            f"[{destination.host}]:{destination.port}"
        )
    extensions: dict[str, object] = {}
    if destination.scheme == "https":
        # TLS is negotiated, and the certificate verified, against the name the
        # operator configured, while the TCP connection goes to the checked IP.
        extensions["sni_hostname"] = destination.host
    return url.copy_with(host=str(address)), {"Host": host_header}, extensions


def send(
    destination: Destination,
    *,
    headers: dict[str, str],
    body: bytes,
    timeout: float | None = None,
    resolver: Resolver = _system_resolver,
    client_factory: ClientFactory = httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> SendResult:
    """POST one alert. Never raises; the result says what happened (Req 21.8).

    Redirects are not followed and the response body is never read (Req 21.12):
    only the status code matters, and a hostile receiver gets nothing to feed a
    parser. Connection errors and 5xx are retried once.
    """
    timeout = config.http_timeout() if timeout is None else timeout
    host = destination.host
    try:
        address = pinned_address(destination, timeout=timeout, resolver=resolver)
    except DestinationRefused as exc:
        return SendResult(NotificationStatus.REFUSED, str(exc))

    url, extra_headers, extensions = _pinned_request_target(destination, address)
    request_headers = {**headers, **extra_headers}
    if destination.token is not None:
        request_headers["Authorization"] = f"Bearer {destination.token}"

    last_error = f"{host}: not attempted"
    for attempt in range(2):
        if attempt:
            sleep(RETRY_DELAY_SECONDS)
        try:
            with client_factory(
                timeout=timeout,
                follow_redirects=False,
                # Proxies from the environment only when the operator allowed
                # public destinations; otherwise the pinned address is the hop.
                trust_env=destination.allow_public,
            ) as client:
                with client.stream(
                    "POST", url, content=body, headers=request_headers, extensions=extensions
                ) as response:
                    code = response.status_code
        except (httpx.TransportError, OSError) as exc:
            last_error = f"{host}: {type(exc).__name__}"
            continue
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            return SendResult(NotificationStatus.FAILED, f"{host}: {type(exc).__name__}")
        if 200 <= code < 300:
            return SendResult(NotificationStatus.SENT)
        last_error = f"{host}: HTTP {code}"
        if 300 <= code < 400:
            return SendResult(NotificationStatus.FAILED, f"{last_error} (redirects are not followed)")
        if code < 500:
            return SendResult(NotificationStatus.FAILED, last_error)
    return SendResult(NotificationStatus.FAILED, last_error)
