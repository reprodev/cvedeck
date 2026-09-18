"""Tests for the zero-touch network discovery engine (Phase 1).

Covers the discovery module's core functions: CIDR parsing, banner parsing,
OS guessing, single-host scanning, and the full sweep engine. All tests use
monkeypatching to avoid real network I/O.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.scanner.discovery import (
    DEFAULT_DISCOVERY_PORTS,
    DiscoveredHost,
    NetworkDiscoveryEngine,
    ServiceInfo,
    _classify_banner,
    _guess_os,
    _parse_http_banner,
    _parse_smb_banner,
    _parse_ssh_banner,
    _scan_host,
)


# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------


class TestParseSSHBanner:
    """SSH banner (RFC 4253) parsing."""

    def test_standard_openssh_ubuntu(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        info = _parse_ssh_banner(banner)
        assert info.port == 22
        assert info.protocol == "ssh"
        assert info.product == "OpenSSH"
        assert info.version == "8.9p1"
        assert "Ubuntu" in info.extra_info

    def test_minimal_openssh(self):
        banner = "SSH-2.0-OpenSSH_9.6"
        info = _parse_ssh_banner(banner)
        assert info.product == "OpenSSH"
        assert info.version == "9.6"

    def test_dropbear(self):
        banner = "SSH-2.0-dropbear_2022.83"
        info = _parse_ssh_banner(banner)
        assert info.product == "dropbear"
        assert info.version == "2022.83"

    def test_non_standard_banner(self):
        banner = "SSH-2.0-WeirdServer_1.0"
        info = _parse_ssh_banner(banner)
        assert info.product == "WeirdServer"
        assert info.version == "1.0"


class TestParseHTTPBanner:
    """HTTP Server header parsing."""

    def test_apache_with_os(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
        info = _parse_http_banner(banner, 80)
        assert info.product == "Apache"
        assert info.version == "2.4.52"
        assert info.protocol == "http"

    def test_nginx(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
        info = _parse_http_banner(banner, 443)
        assert info.product == "nginx"
        assert info.version == "1.18.0"
        assert info.protocol == "https"

    def test_no_server_header(self):
        banner = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        info = _parse_http_banner(banner, 80)
        assert info.product == ""

    def test_microsoft_iis(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"
        info = _parse_http_banner(banner, 80)
        assert "Microsoft-IIS" in info.product
        assert info.version == "10.0"


class TestParseSMBBanner:
    """SMB negotiate response parsing."""

    def test_smb_windows(self):
        banner = "SMB: Windows Server 2019"
        info = _parse_smb_banner(banner)
        assert info.protocol == "smb"
        assert info.port == 445
        assert "Windows Server 2019" in info.extra_info

    def test_smb_generic(self):
        banner = "SMB: host responded to negotiate"
        info = _parse_smb_banner(banner)
        assert info.protocol == "smb"


class TestClassifyBanner:
    """Banner routing to the correct parser."""

    def test_ssh_banner(self):
        info = _classify_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        assert info.protocol == "ssh"
        assert info.product == "OpenSSH"

    def test_http_banner(self):
        info = _classify_banner(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n")
        assert info.product == "nginx"

    def test_smb_banner(self):
        info = _classify_banner(445, "SMB: Windows 10 Enterprise")
        assert info.protocol == "smb"

    def test_rdp_unknown(self):
        info = _classify_banner(3389, "some raw bytes")
        assert info.protocol == "rdp"

    def test_empty_banner_fallback(self):
        info = _classify_banner(5985, "")
        assert info.protocol == "winrm"


# ---------------------------------------------------------------------------
# OS guessing
# ---------------------------------------------------------------------------


class TestGuessOS:
    """OS inference from service banners and port combinations."""

    def test_ubuntu_from_ssh(self):
        services = [ServiceInfo(port=22, banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", extra_info="Ubuntu-3ubuntu0.6", product="OpenSSH")]
        assert "Ubuntu" in _guess_os(services, True)

    def test_windows_from_smb(self):
        services = [ServiceInfo(port=445, banner="SMB: Windows Server 2022", extra_info="Windows Server 2022", product="SMB")]
        assert "Windows" in _guess_os(services, True)

    def test_windows_from_ports_only(self):
        services = [ServiceInfo(port=3389), ServiceInfo(port=5985)]
        assert "Windows" in _guess_os(services, True)

    def test_linux_from_ssh_port_only(self):
        services = [ServiceInfo(port=22)]
        assert "Linux" in _guess_os(services, True) or "Unix" in _guess_os(services, True)

    def test_unknown_no_services(self):
        assert _guess_os([], True) == "Unknown"


# ---------------------------------------------------------------------------
# Single-host scanning (monkeypatched)
# ---------------------------------------------------------------------------


class TestScanHost:
    """_scan_host with mocked network I/O."""

    def test_host_with_open_ssh(self):
        """Host responds to ping and has SSH open."""
        with patch("app.scanner.discovery._ping", return_value=True), \
             patch("app.scanner.discovery._tcp_connect", side_effect=lambda ip, port: port == 22), \
             patch("app.scanner.discovery._grab_banner", return_value="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), \
             patch("app.scanner.discovery.socket") as mock_socket:
            mock_socket.getfqdn.return_value = "webserver.local"
            mock_socket.gethostbyaddr.return_value = ("webserver.local", [], [])
            mock_socket.AF_INET = 2
            mock_socket.SOCK_STREAM = 1

            result = _scan_host("192.168.1.10", [22, 80, 445])

        assert result is not None
        assert result.ip == "192.168.1.10"
        assert result.responds_to_ping is True
        assert 22 in result.open_ports
        assert 80 not in result.open_ports
        assert len(result.services) == 1
        assert result.services[0].protocol == "ssh"

    def test_host_completely_unreachable(self):
        """Host does not respond to ping and has no open ports."""
        with patch("app.scanner.discovery._ping", return_value=False), \
             patch("app.scanner.discovery._tcp_connect", return_value=False):
            result = _scan_host("192.168.1.99", [22, 80])

        assert result is None

    def test_host_no_ping_but_ports_open(self):
        """Host does not respond to ping but has open ports (firewall blocks ICMP)."""
        with patch("app.scanner.discovery._ping", return_value=False), \
             patch("app.scanner.discovery._tcp_connect", side_effect=lambda ip, port: port == 445), \
             patch("app.scanner.discovery._grab_banner", return_value="SMB: host responded to negotiate"), \
             patch("app.scanner.discovery.socket") as mock_socket:
            mock_socket.getfqdn.return_value = "192.168.1.50"
            mock_socket.gethostbyaddr.side_effect = OSError("no reverse DNS")
            mock_socket.AF_INET = 2
            mock_socket.SOCK_STREAM = 1

            result = _scan_host("192.168.1.50", [22, 445])

        assert result is not None
        assert result.responds_to_ping is False
        assert 445 in result.open_ports
        assert "Windows" in result.os_guess

    def test_no_banner_grab(self):
        """Banner grabbing disabled still returns port info."""
        with patch("app.scanner.discovery._ping", return_value=True), \
             patch("app.scanner.discovery._tcp_connect", side_effect=lambda ip, port: port == 80), \
             patch("app.scanner.discovery.socket") as mock_socket:
            mock_socket.getfqdn.return_value = "test.local"
            mock_socket.gethostbyaddr.return_value = ("test.local", [], [])
            mock_socket.AF_INET = 2
            mock_socket.SOCK_STREAM = 1

            result = _scan_host("192.168.1.20", [80], grab_banners=False)

        assert result is not None
        assert 80 in result.open_ports
        assert result.services[0].protocol == "http"
        assert result.services[0].banner == ""  # No banner grab


# ---------------------------------------------------------------------------
# NetworkDiscoveryEngine
# ---------------------------------------------------------------------------


class TestNetworkDiscoveryEngine:
    """Engine-level tests with mocked host scanning."""

    def test_sweep_valid_cidr(self):
        """Sweep discovers hosts in a /30 network."""
        def fake_scan_host(ip, ports, *, do_ping=True, grab_banners=True):
            if ip == "10.0.0.1":
                return DiscoveredHost(
                    ip="10.0.0.1", hostname="router.local",
                    responds_to_ping=True, open_ports=[80, 443],
                    services=[
                        ServiceInfo(port=80, protocol="http", product="nginx", version="1.24.0"),
                        ServiceInfo(port=443, protocol="https", product="nginx", version="1.24.0"),
                    ],
                    os_guess="Linux / Unix (inferred from SSH)",
                )
            if ip == "10.0.0.2":
                return DiscoveredHost(
                    ip="10.0.0.2", hostname="desktop.local",
                    responds_to_ping=True, open_ports=[3389, 5985],
                    services=[
                        ServiceInfo(port=3389, protocol="rdp"),
                        ServiceInfo(port=5985, protocol="winrm"),
                    ],
                    os_guess="Windows (inferred from ports)",
                )
            return None

        with patch("app.scanner.discovery._scan_host", side_effect=fake_scan_host):
            engine = NetworkDiscoveryEngine()
            results = engine.sweep("10.0.0.0/30").hosts

        assert len(results) == 2
        assert results[0].ip == "10.0.0.1"
        assert results[1].ip == "10.0.0.2"
        assert "Windows" in results[1].os_guess

    def test_sweep_invalid_cidr_raises(self):
        """Invalid CIDR raises ValueError."""
        engine = NetworkDiscoveryEngine()
        with pytest.raises(ValueError, match="Invalid CIDR"):
            engine.sweep("not-a-cidr")

    def test_sweep_single_ip(self):
        """A /32 address scans just that one host."""
        def fake_scan_host(ip, ports, *, do_ping=True, grab_banners=True):
            return DiscoveredHost(
                ip=ip, responds_to_ping=True, open_ports=[22],
                services=[ServiceInfo(port=22, protocol="ssh")],
                os_guess="Linux / Unix (inferred from SSH)",
            )

        with patch("app.scanner.discovery._scan_host", side_effect=fake_scan_host):
            engine = NetworkDiscoveryEngine()
            results = engine.sweep("192.168.1.1/32").hosts

        assert len(results) == 1
        assert results[0].ip == "192.168.1.1"

    def test_sweep_empty_subnet(self):
        """All hosts unreachable returns empty list."""
        with patch("app.scanner.discovery._scan_host", return_value=None):
            engine = NetworkDiscoveryEngine()
            results = engine.sweep("10.0.0.0/28").hosts

        assert results == []

    def test_custom_ports(self):
        """Engine passes custom ports to host scanner."""
        call_args: list[tuple] = []

        def fake_scan_host(ip, ports, *, do_ping=True, grab_banners=True):
            call_args.append((ip, list(ports)))
            return None

        with patch("app.scanner.discovery._scan_host", side_effect=fake_scan_host):
            engine = NetworkDiscoveryEngine(ports=[8080, 9090])
            engine.sweep("10.0.0.0/30")

        # All calls should have used the custom ports.
        for _, ports in call_args:
            assert ports == [8080, 9090]


# ---------------------------------------------------------------------------
# API endpoint
# ---------------------------------------------------------------------------


class TestDiscoveryAPI:
    """Test the POST /api/discovery/sweep endpoint."""

    def test_sweep_endpoint_valid_cidr(self):
        from fastapi.testclient import TestClient

        from app.api.app import create_app
        from tests.auth_helpers import override_auth

        app = override_auth(create_app())
        client = TestClient(app)

        def fake_scan_host(ip, ports, *, do_ping=True, grab_banners=True):
            if ip == "10.0.0.1":
                return DiscoveredHost(
                    ip="10.0.0.1", hostname="test.local",
                    responds_to_ping=True, open_ports=[22],
                    services=[ServiceInfo(port=22, protocol="ssh", product="OpenSSH", version="8.9p1")],
                    os_guess="Ubuntu Linux",
                )
            return None

        with patch("app.scanner.discovery._scan_host", side_effect=fake_scan_host):
            resp = client.post("/api/discovery/sweep", json={"cidr": "10.0.0.0/30"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["cidr"] == "10.0.0.0/30"
        assert data["total_hosts_discovered"] == 1
        assert data["hosts"][0]["ip"] == "10.0.0.1"
        assert data["hosts"][0]["os_guess"] == "Ubuntu Linux"
        assert data["hosts"][0]["services"][0]["product"] == "OpenSSH"

    def test_sweep_endpoint_invalid_cidr(self):
        from fastapi.testclient import TestClient

        from app.api.app import create_app
        from tests.auth_helpers import override_auth

        app = override_auth(create_app())
        client = TestClient(app)

        resp = client.post("/api/discovery/sweep", json={"cidr": "garbage"})
        assert resp.status_code == 422

    def test_sweep_endpoint_too_large_network(self):
        from fastapi.testclient import TestClient

        from app.api.app import create_app
        from tests.auth_helpers import override_auth

        app = override_auth(create_app())
        client = TestClient(app)

        resp = client.post("/api/discovery/sweep", json={"cidr": "10.0.0.0/16"})
        assert resp.status_code == 422
        assert "4096" in resp.json()["detail"]

    def test_enroll_discovered_hosts_endpoint(self):
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from sqlalchemy.pool import StaticPool

        from app.api.app import create_app
        from tests.auth_helpers import override_auth
        from app.api.dependencies import get_session
        from app.data.schema import Base

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)

        app = override_auth(create_app())

        def override_get_session():
            with Session(engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_get_session
        client = TestClient(app)

        payload = {
            "hosts": [
                {"hostname": "192.168.1.35", "platform": "windows"},
                {"hostname": "192.168.1.50", "platform": "linux"},
            ]
        }
        resp = client.post("/api/discovery/enroll", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["total_enrolled"] == 2
        assert data["enrolled"][0]["hostname"] == "192.168.1.35"
        assert data["enrolled"][0]["platform"] == "windows"
        assert data["enrolled"][1]["hostname"] == "192.168.1.50"
        assert data["enrolled"][1]["platform"] == "linux"

        # Verify enrolled machines appear in GET /api/machines
        get_resp = client.get("/api/machines")
        assert get_resp.status_code == 200
        machines = get_resp.json()
        assert len(machines) == 2
        hostnames = [m["hostname"] for m in machines]
        assert "192.168.1.35" in hostnames
        assert "192.168.1.50" in hostnames


# ---------------------------------------------------------------------------
# Req 8.11: a scanner that cannot ping does not report hosts as filtered
# ---------------------------------------------------------------------------


class TestIcmpAvailability:
    def test_a_missing_ping_binary_is_not_an_answer_about_the_host(self):
        """Validates Req 8.11.

        The shipped image had no ping binary for several releases, so every
        probe raised FileNotFoundError, was caught, and returned False -- and
        the dashboard printed "Filtered" for every host on the network.
        """
        from app.scanner.discovery import _ping

        with patch(
            "app.scanner.discovery.subprocess.run", side_effect=FileNotFoundError
        ):
            assert _ping("192.0.2.10") is None

    def test_no_permission_to_ping_is_not_an_answer_either(self):
        """Validates Req 8.11: an unprivileged container is not a filtered host."""
        from app.scanner.discovery import _ping

        with patch("app.scanner.discovery.subprocess.run", side_effect=PermissionError):
            assert _ping("192.0.2.10") is None

    def test_a_host_that_does_not_answer_in_time_still_answers_no(self):
        """Validates Req 8.11: a timeout is a real answer and stays one."""
        import subprocess

        from app.scanner.discovery import _ping

        with patch(
            "app.scanner.discovery.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=1),
        ):
            assert _ping("192.0.2.10") is False

    def test_a_host_scanned_without_icmp_reports_unchecked_not_false(self):
        """Validates Req 8.11."""
        with patch("app.scanner.discovery._ping", return_value=None),              patch("app.scanner.discovery._tcp_connect", side_effect=lambda ip, port: port == 22),              patch("app.scanner.discovery._grab_banner", return_value=""),              patch("app.scanner.discovery.socket.gethostbyaddr", side_effect=OSError):
            result = _scan_host("192.0.2.10", [22, 80])

        assert result is not None
        assert result.responds_to_ping is None

    def test_a_sweep_says_whether_it_could_ping_at_all(self):
        """Validates Req 8.11: an empty result means less without ICMP."""
        with patch("app.scanner.discovery._scan_host", return_value=None),              patch("app.scanner.discovery.shutil.which", return_value=None):
            result = NetworkDiscoveryEngine().sweep("10.0.0.0/30")

        assert result.hosts == []
        # The caller can tell "nothing is there" from "I could not look".
        assert result.icmp_checked is False

    def test_a_sweep_with_icmp_says_so(self):
        with patch("app.scanner.discovery._scan_host", return_value=None),              patch("app.scanner.discovery.shutil.which", return_value="/bin/ping"):
            result = NetworkDiscoveryEngine().sweep("10.0.0.0/30")

        assert result.icmp_checked is True


class TestProbeErrors:
    def test_an_address_that_could_not_be_probed_is_counted_not_dropped(self):
        """Validates Req 8.12.

        A probe that raises was swallowed by a bare except, so a sweep that
        could not look at half its range reported the same shape as one that
        looked everywhere and found nothing.
        """
        def flaky(ip, ports, *, do_ping=True, grab_banners=True):
            if ip.endswith((".1", ".2")):
                raise OSError("too many open files")
            return None

        with patch("app.scanner.discovery._scan_host", side_effect=flaky):
            result = NetworkDiscoveryEngine().sweep("10.0.0.0/29")

        assert result.hosts == []
        assert result.probe_errors == 2

    def test_a_clean_sweep_reports_no_probe_errors(self):
        """Validates Req 8.12: the count stays zero when nothing failed."""
        with patch("app.scanner.discovery._scan_host", return_value=None):
            result = NetworkDiscoveryEngine().sweep("10.0.0.0/30")

        assert result.probe_errors == 0

    def test_one_failure_does_not_abort_the_sweep(self):
        """Validates Req 8.2, 8.12: the rest of the range is still swept."""
        def flaky(ip, ports, *, do_ping=True, grab_banners=True):
            if ip == "10.0.0.1":
                raise RuntimeError("boom")
            return DiscoveredHost(ip=ip, responds_to_ping=True)

        with patch("app.scanner.discovery._scan_host", side_effect=flaky):
            result = NetworkDiscoveryEngine().sweep("10.0.0.0/29")

        assert [h.ip for h in result.hosts] == ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]
        assert result.probe_errors == 1

