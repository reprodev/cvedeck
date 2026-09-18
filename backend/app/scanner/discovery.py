"""Zero-touch network asset discovery (Phase 1).

Implements the probing half of Req 8 (Req 8.1, 8.3).

Discovers active hosts on a network CIDR without requiring credentials or
modifying any target host. The discovery pipeline uses three complementary
techniques:

1. **ICMP ping sweep** -- subprocess ``ping`` against each address to detect
   live hosts regardless of open TCP ports.
2. **Multi-port TCP connect scan** -- probes standard enterprise ports
   (22/SSH, 80/HTTP, 443/HTTPS, 445/SMB, 3389/RDP, 5985/WinRM) to discover
   reachable services.
3. **Unauthenticated banner grabbing** -- reads the first bytes returned by
   SSH, HTTP, and SMB listeners to fingerprint OS, software name, and version
   without logging in.

All techniques are read-only network operations. No agents are installed,
no credentials are sent, and no packets modify target state.

The module exposes :class:`NetworkDiscoveryEngine` which accepts a CIDR
string and returns a list of :class:`DiscoveredHost` results.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Sequence

# Default ports to probe. Every port here is a standard enterprise management
# or service port whose presence reveals the host's role.
DEFAULT_DISCOVERY_PORTS: list[int] = [22, 80, 443, 445, 3389, 5985]

# Maximum concurrent threads for the subnet sweep.
_DEFAULT_MAX_WORKERS = 50

# Socket timeouts (seconds).
_TCP_CONNECT_TIMEOUT = 1.5
_BANNER_READ_TIMEOUT = 2.0
_PING_TIMEOUT_S = 1  # seconds per ICMP echo

# Banner read buffer size.
_BANNER_MAX_BYTES = 1024


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServiceInfo:
    """Information about a single open port on a discovered host."""

    port: int
    protocol: str = ""      # e.g. "ssh", "http", "smb", "rdp", "winrm"
    banner: str = ""         # raw banner string (first line / header value)
    product: str = ""        # parsed product name, e.g. "OpenSSH"
    version: str = ""        # parsed version string, e.g. "8.9p1"
    extra_info: str = ""     # e.g. "Ubuntu-3ubuntu0.6"


@dataclass(frozen=True)
class DiscoveredHost:
    """A host found during network discovery."""

    ip: str
    hostname: str = ""           # reverse-DNS hostname, empty if unresolved
    #: True answered, False did not, None never asked -- no ping binary or no
    #: permission to use it (Req 8.11).
    responds_to_ping: bool | None = None
    open_ports: list[int] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    os_guess: str = ""           # best-effort OS guess from banners


@dataclass
class SweepResult:
    """What one sweep found, and what it was able to ask.

    ``icmp_checked`` is False when this deployment has no usable ``ping``: every
    host's ``responds_to_ping`` is then ``None``, and a host that answers only
    ICMP cannot be discovered at all -- so "no active hosts" is a statement
    about the sweep, not about the subnet (Req 8.11).
    """

    hosts: list[DiscoveredHost] = field(default_factory=list)
    icmp_checked: bool = True
    #: Addresses whose probe raised instead of answering -- a socket the host
    #: ran out of, a DNS resolver that hung, a defect here. They were dropped
    #: silently before, so a sweep that could not look at half the subnet
    #: reported the same shape as one that found nothing there (Req 8.12).
    probe_errors: int = 0


# ---------------------------------------------------------------------------
# Port label mapping
# ---------------------------------------------------------------------------

_PORT_PROTOCOL: dict[int, str] = {
    22: "ssh",
    80: "http",
    443: "https",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
}


# ---------------------------------------------------------------------------
# Low-level probes (each is a pure function, safe for threading)
# ---------------------------------------------------------------------------

def icmp_available() -> bool:
    """Whether this deployment can send an ICMP echo request at all.

    The container shipped without a ``ping`` binary for several releases, so
    every probe failed with ``FileNotFoundError`` and every host was reported
    as not responding -- a statement about the scanner presented as a fact
    about the host (Req 8.11).
    """
    return shutil.which("ping") is not None


def _ping(ip: str, timeout: int = _PING_TIMEOUT_S) -> bool | None:
    """Send a single ICMP echo request via the OS ``ping`` command.

    Returns ``True`` if the host responds within *timeout* seconds, ``False``
    if it does not, and ``None`` if the question could not be asked: no
    ``ping`` binary, or no permission to open the socket. ``False`` there would
    claim the host is filtered on the strength of a missing program.

    Uses ``-n 1`` on Windows and ``-c 1`` on POSIX.
    """
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    # Windows -w is in milliseconds; POSIX -W is in seconds.
    timeout_value = str(timeout * 1000) if platform.system().lower() == "windows" else str(timeout)

    try:
        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_value, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        # The host did not answer in time, which is an answer.
        return False
    except (FileNotFoundError, PermissionError):
        return None
    except OSError:
        # Anything else that stopped the probe from running -- still not
        # evidence about the host.
        return None


def _tcp_connect(ip: str, port: int, timeout: float = _TCP_CONNECT_TIMEOUT) -> bool:
    """Attempt a TCP three-way handshake to *ip*:*port*.

    Returns ``True`` if the connection completes (the port is open).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def _grab_banner(ip: str, port: int, timeout: float = _BANNER_READ_TIMEOUT) -> str:
    """Connect to *ip*:*port* and read the first banner bytes.

    For protocols like SSH the server sends a banner immediately upon
    connection. For HTTP we send a minimal ``HEAD`` request first.
    Returns the decoded banner string, or empty string on failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))

        # HTTP needs a request to get a response.
        if port in (80, 443, 5985, 8080, 8443):
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode("ascii", errors="replace"))

        # SMB: send minimal negotiate protocol request to elicit OS info.
        if port == 445:
            return _smb_negotiate(sock)

        raw = sock.recv(_BANNER_MAX_BYTES)
        return raw.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
        return ""
    finally:
        sock.close()


def _smb_negotiate(sock: socket.socket) -> str:
    """Send a minimal SMB1 negotiate to extract the OS version string.

    This is unauthenticated: SMB reveals the OS string during protocol
    negotiation before any credentials are exchanged.
    """
    # Minimal SMB1 Negotiate Protocol Request (dialect NT LM 0.12).
    negotiate = (
        b"\x00\x00\x00\x55"      # NetBIOS session header (length 85)
        b"\xff\x53\x4d\x42"      # SMB1 magic
        b"\x72"                   # Negotiate command
        b"\x00\x00\x00\x00"      # Status
        b"\x18"                   # Flags
        b"\x53\xc8"              # Flags2
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Extra
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Extra
        b"\x00\x00"              # TID
        b"\xff\xfe"              # PID
        b"\x00\x00"              # UID
        b"\x00\x00"              # MID
        b"\x00"                   # WCT
        b"\x12\x00"              # BCC (byte count = 18)
        b"\x02"                   # Buffer format
        b"NT LM 0.12\x00"        # Dialect string
        b"\x02"                   # Buffer format
        b"SMB 2.002\x00"         # Dialect string (SMB2 for modern systems)
    )
    try:
        sock.sendall(negotiate)
        raw = sock.recv(1024)
        if not raw:
            return ""
        # Try to decode any ASCII-printable substrings as OS hints.
        decoded = raw.decode("utf-8", errors="replace")
        # Look for common Windows version patterns in the response.
        windows_match = re.search(
            r"(Windows\s+(?:Server\s+)?[\d.]+\s*\w*)", decoded
        )
        if windows_match:
            return f"SMB: {windows_match.group(1)}"
        # Return a generic SMB indicator if we got a response.
        if len(raw) > 4:
            return "SMB: host responded to negotiate"
        return ""
    except (socket.timeout, OSError):
        return ""


# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------

def _parse_ssh_banner(banner: str) -> ServiceInfo:
    """Parse an SSH daemon identification string into a ``ServiceInfo``.

    SSH banners follow RFC 4253: ``SSH-protoversion-softwareversion SP comments``.
    Example: ``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``
    """
    product, version, extra = "", "", ""
    # Match: SSH-<proto>-<product>_<version> <comments>
    match = re.match(
        r"SSH-[\d.]+-([A-Za-z]+)[_-]([\w.]+)\s*(.*)", banner
    )
    if match:
        product = match.group(1)     # e.g. "OpenSSH"
        version = match.group(2)     # e.g. "8.9p1"
        extra = match.group(3).strip()  # e.g. "Ubuntu-3ubuntu0.6"

    return ServiceInfo(
        port=22, protocol="ssh", banner=banner,
        product=product, version=version, extra_info=extra,
    )


def _parse_http_banner(banner: str, port: int) -> ServiceInfo:
    """Extract the ``Server`` header from an HTTP response."""
    product, version = "", ""
    server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
    server_val = server_match.group(1).strip() if server_match else ""

    if server_val:
        # e.g. "Apache/2.4.52 (Ubuntu)" or "nginx/1.18.0"
        pv_match = re.match(r"([\w.-]+?)/([\d.]+)", server_val)
        if pv_match:
            product = pv_match.group(1)
            version = pv_match.group(2)
        else:
            product = server_val

    return ServiceInfo(
        port=port, protocol=_PORT_PROTOCOL.get(port, "http"),
        banner=server_val or banner[:120], product=product, version=version,
    )


def _parse_smb_banner(banner: str) -> ServiceInfo:
    """Parse an SMB negotiate response summary."""
    return ServiceInfo(
        port=445, protocol="smb", banner=banner,
        product="SMB", version="",
        extra_info=banner.replace("SMB: ", ""),
    )


def _classify_banner(port: int, banner: str) -> ServiceInfo:
    """Route a raw banner to the appropriate parser."""
    if port == 22 and banner.startswith("SSH-"):
        return _parse_ssh_banner(banner)
    if port in (80, 443, 5985, 8080, 8443):
        return _parse_http_banner(banner, port)
    if port == 445 and banner:
        return _parse_smb_banner(banner)
    # Fallback: generic service info.
    return ServiceInfo(
        port=port,
        protocol=_PORT_PROTOCOL.get(port, f"tcp/{port}"),
        banner=banner[:200],
    )


# ---------------------------------------------------------------------------
# OS guessing heuristic
# ---------------------------------------------------------------------------

def _guess_os(services: list[ServiceInfo], responds_to_ping: bool | None) -> str:
    """Best-effort OS guess from service banners and open ports."""
    if not services:
        return "Unknown"

    # 1. First check explicit Linux distribution or OpenSSH banners
    for svc in services:
        low = (svc.banner + " " + svc.extra_info + " " + svc.product).lower()
        if "ubuntu" in low:
            return "Ubuntu Linux"
        if "debian" in low:
            return "Debian Linux"
        if "centos" in low or "red hat" in low or "rhel" in low or "almalinux" in low or "rocky" in low:
            return "RHEL / Enterprise Linux"
        if "alpine" in low:
            return "Alpine Linux"
        if "arch" in low:
            return "Arch Linux"
        if "fedora" in low:
            return "Fedora Linux"
        if "opensuse" in low or "suse" in low:
            return "openSUSE Linux"
        if "openssh" in low or "linux" in low:
            return "Linux / Unix (OpenSSH)"

    # 2. Check explicit Windows banners
    for svc in services:
        low = (svc.banner + " " + svc.extra_info + " " + svc.product).lower()
        if "windows" in low or "microsoft" in low or "iis" in low or "ms-wbt-server" in low:
            return "Windows"

    # 3. Port-based inference: Port 22 (SSH) takes priority for Linux
    ports = {svc.port for svc in services}
    if 22 in ports:
        return "Linux / Unix (inferred from SSH)"
    if 3389 in ports or 5985 in ports or 445 in ports:
        return "Windows (inferred from ports)"
    if 80 in ports or 443 in ports:
        return "Linux / Unix (Web Server)"
    return "Unknown"


# ---------------------------------------------------------------------------
# Single-host scanner
# ---------------------------------------------------------------------------

def _scan_host(
    ip: str,
    ports: Sequence[int],
    *,
    do_ping: bool = True,
    grab_banners: bool = True,
) -> DiscoveredHost | None:
    """Probe a single IP address. Returns ``None`` if completely unreachable."""
    # Three states: answered, did not answer, and never asked (Req 8.11).
    responds = _ping(ip) if do_ping else None
    open_ports: list[int] = []

    for port in ports:
        if _tcp_connect(ip, port):
            open_ports.append(port)

    if responds is not True and not open_ports:
        return None  # Nothing answered; whether it is down is not known here.

    # Reverse-DNS lookup (best effort).
    hostname = ""
    try:
        hostname = socket.getfqdn(ip)
        if hostname == ip:
            hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass

    # Banner grabbing on open ports.
    services: list[ServiceInfo] = []
    if grab_banners:
        for port in open_ports:
            banner = _grab_banner(ip, port)
            services.append(_classify_banner(port, banner))
    else:
        for port in open_ports:
            services.append(ServiceInfo(
                port=port, protocol=_PORT_PROTOCOL.get(port, f"tcp/{port}"),
            ))

    os_guess = _guess_os(services, responds)

    return DiscoveredHost(
        ip=ip,
        hostname=hostname,
        responds_to_ping=responds,
        open_ports=open_ports,
        services=services,
        os_guess=os_guess,
    )


# ---------------------------------------------------------------------------
# Public engine
# ---------------------------------------------------------------------------

class NetworkDiscoveryEngine:
    """Sweep a network CIDR to discover active hosts (Req 8.1).

    All techniques are read-only and require no credentials. No agent is
    installed and no host configuration is modified.

    Args:
        max_workers: Maximum concurrent threads for the sweep.
        ports: TCP ports to probe on each address.
        do_ping: Whether to send an ICMP ping before port scanning.
        grab_banners: Whether to read service banners from open ports.
    """

    def __init__(
        self,
        *,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        ports: Sequence[int] | None = None,
        do_ping: bool = True,
        grab_banners: bool = True,
    ) -> None:
        self._max_workers = max_workers
        self._ports = list(ports) if ports is not None else list(DEFAULT_DISCOVERY_PORTS)
        self._do_ping = do_ping
        self._grab_banners = grab_banners

    def sweep(self, cidr: str) -> SweepResult:
        """Scan every host address in *cidr* and return discovered hosts.

        Args:
            cidr: An IPv4 network in CIDR notation, e.g. ``"192.168.0.0/24"``.
                A bare IP address (``"192.168.0.1"``) is treated as ``/32``.

        Returns:
            A :class:`SweepResult`: the hosts that answered, each carrying the
            address, reverse-DNS name, reachability, open ports, banners and
            inferred platform required by Req 8.3, plus whether ICMP was asked
            at all. An empty host list means something different where ICMP
            could not be sent, and only the result object can say so
            (Req 8.11).

        Raises:
            ValueError: If *cidr* is not a valid IPv4 network.
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise ValueError(f"Invalid CIDR: {cidr!r}") from exc

        addresses = [str(addr) for addr in network.hosts()]
        if not addresses:
            # /32 has no .hosts(); use the network address itself.
            addresses = [str(network.network_address)]

        discovered: list[DiscoveredHost] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(
                    _scan_host, ip, self._ports,
                    do_ping=self._do_ping, grab_banners=self._grab_banners,
                ): ip
                for ip in addresses
            }
            probe_errors = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result is not None:
                        discovered.append(result)
                except Exception:
                    # One address failing must not abort the sweep, but it is
                    # not a host that answered nothing either: it is counted
                    # and reported (Req 8.12).
                    probe_errors += 1

        # Sort by IP for deterministic output.
        discovered.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return SweepResult(
            hosts=discovered,
            # Asked once for the sweep rather than inferred from the hosts: with
            # no host discovered there is nothing to infer it from, and that is
            # exactly the case where it matters.
            icmp_checked=self._do_ping and icmp_available(),
            probe_errors=probe_errors,
        )
