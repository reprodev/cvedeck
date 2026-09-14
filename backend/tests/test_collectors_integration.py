"""Integration tests for the agentless inventory collectors (task 5.2).

Where the unit tests in ``test_collectors.py`` exercise individual behaviours,
these integration tests drive the collectors end-to-end at higher fidelity:
they run fake SSH/WinRM transports that reproduce realistic, multi-distro and
multi-OS command output, and assert that the collectors normalize a *complete*
``Inventory`` (OS details + full package list) for both platforms.

They also perform a read-only command review (Req 1.3): every command actually
issued to the fake transport is inspected and asserted to contain no
install/remove/write verb and no filesystem-write redirect, confirming the
collectors never mutate the target.

No real host is ever contacted. The collectors' injectable
``ssh_client_factory`` / ``winrm_session_factory`` seams are used to substitute
fakes that behave like the real transports:

- Linux SSH (Req 1.1): a fake ``paramiko.SSHClient`` that returns canned
  stdout keyed by the exact command string.
- Windows WinRM (Req 1.2): a fake ``pywinrm`` session that returns canned
  results keyed by a script substring.

These fakes model the transport contract closely enough (byte stdout, exec by
command, connect/auth exceptions) that a passing test reflects the collector's
real end-to-end behaviour against that contract.
"""

from __future__ import annotations

import re

import pytest

from app.enums import Platform
from app.models import Credentials, TargetMachine
from app.scanner import collectors
from app.scanner.collectors import LinuxCollector, WindowsCollector


# ---------------------------------------------------------------------------
# High-fidelity fake transports
# ---------------------------------------------------------------------------


class _StdoutFile:
    """Mimics the file-like object paramiko returns for stdout/stderr."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class RecordingSSHClient:
    """A fake ``paramiko.SSHClient`` that records every issued command.

    Command output is looked up by exact command string, matching how the real
    client dispatches ``exec_command``. All commands are captured so the test
    can perform a read-only review of the full command set.
    """

    def __init__(self, command_output: dict[str, bytes]) -> None:
        self._command_output = command_output
        self.commands: list[str] = []
        self.connected = False
        self.closed = False

    def set_missing_host_key_policy(self, policy) -> None:
        pass

    def connect(self, **kwargs) -> None:
        self.connected = True

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        data = self._command_output.get(command, b"")
        return None, _StdoutFile(data), _StdoutFile(b"")

    def close(self) -> None:
        self.closed = True


class FakeWinRMResult:
    def __init__(self, std_out: bytes = b"", std_err: bytes = b"", status_code: int = 0):
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class RecordingWinRMSession:
    """A fake ``pywinrm`` session that records every PowerShell script run.

    Output is matched by substring against the script, matching how the real
    collector issues distinct OS and package scripts.
    """

    def __init__(self, script_output: dict[str, FakeWinRMResult]) -> None:
        self._script_output = script_output
        self.scripts: list[str] = []

    def run_ps(self, script):
        self.scripts.append(script)
        for key, result in self._script_output.items():
            if key in script:
                return result
        return FakeWinRMResult(std_out=b"", status_code=0)


CREDS = Credentials(username="scanner", password="s3cret")


# ---------------------------------------------------------------------------
# Read-only command review helpers (Req 1.3)
# ---------------------------------------------------------------------------

# Verbs / operators that would write to, install on, or otherwise mutate the
# target. If any of these appear in an issued command, the collector is not
# read-only.
_FORBIDDEN_LINUX = (
    "apt-get install",
    "apt install",
    "yum install",
    "dnf install",
    "apk add",
    "rm ",
    "rmdir",
    "mv ",
    "cp ",
    "dd ",
    "mkdir",
    "touch ",
    "chmod",
    "chown",
    "tee ",
    "useradd",
    "sed -i",
)
_FORBIDDEN_WINDOWS = (
    "install-",
    "uninstall-",
    "set-itemproperty",
    "new-item",
    "remove-item",
    "start-process",
    "out-file",
    "set-content",
    "add-content",
    "invoke-webrequest",
    "stop-service",
    "set-service",
)

# A filesystem-write redirect: `>` or `>>` targeting something other than the
# `2>/dev/null` stderr discard the collectors legitimately use.
_WRITE_REDIRECT = re.compile(r"(?<!2)>>?\s*[^&\s]")


def assert_no_write_redirect(command: str) -> None:
    """Fail if a command contains a filesystem-write redirect.

    ``2>/dev/null`` (discarding stderr) is allowed because it does not write to
    the target; any other ``>``/``>>`` is treated as a write.
    """
    sanitized = command.replace("2>/dev/null", "")
    assert not _WRITE_REDIRECT.search(sanitized), (
        f"command contains a write redirect: {command!r}"
    )


# ===========================================================================
# Linux SSH collection (Req 1.1) — multiple distros end-to-end
# ===========================================================================

# Debian/Ubuntu-family host: os-release + dpkg-query output.
_UBUNTU_OS_RELEASE = (
    b'NAME="Ubuntu"\n'
    b'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
    b'VERSION_ID="22.04"\n'
    b'ID=ubuntu\n'
    b'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
)
_UBUNTU_DPKG = (
    b"openssl\t3.0.2-0ubuntu1.10\n"
    b"bash\t5.1-6ubuntu1\n"
    b"libc6\t2.35-0ubuntu3.4\n"
    b"python3\t3.10.6-1~22.04\n"
)

# RHEL-family host: os-release with quoted VERSION_ID + rpm -qa output.
_RHEL_OS_RELEASE = (
    b'NAME="Red Hat Enterprise Linux"\n'
    b'VERSION="9.3 (Plow)"\n'
    b'VERSION_ID="9.3"\n'
    b'ID="rhel"\n'
    b'PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"\n'
)
# On an RPM host the dpkg part fails (`|| rpm ...`), so the transport returns
# the rpm output for the same combined command string.
_RHEL_RPM = (
    b"openssl\t3.0.7\n"
    b"glibc\t2.34\n"
    b"kernel\t5.14.0\n"
)


def _linux_context(
    os_release: bytes,
    kernel: bytes = b"5.15.0-56-generic",
    reboot: bytes = b"no",
) -> bytes:
    """Build the sectioned output of the batched Linux context command.

    os-release, the running kernel, and the reboot-required probe share one SSH
    round trip because each round trip pays full network latency.
    """
    marker = collectors._SECTION.encode()
    nl = b"\n"
    return os_release + nl + marker + nl + kernel + nl + marker + nl + reboot


def _linux_client(
    os_output: bytes,
    pkg_output: bytes,
    *,
    kernel: bytes = b"5.15.0-56-generic",
    reboot: bytes = b"no",
) -> RecordingSSHClient:
    return RecordingSSHClient(
        {
            collectors._LINUX_CONTEXT_CMD: _linux_context(os_output, kernel, reboot),
            collectors._LINUX_PACKAGES_CMD: pkg_output,
        }
    )


def test_linux_ssh_collection_ubuntu_full_normalization():
    """End-to-end SSH collection for a Debian/Ubuntu host (Req 1.1)."""
    fake = _linux_client(_UBUNTU_OS_RELEASE, _UBUNTU_DPKG)
    collector = LinuxCollector(ssh_client_factory=lambda: fake)
    target = TargetMachine(id="lin-ubuntu", hostname="ubuntu.example", platform=Platform.LINUX)

    inv = collector.collect(target, CREDS)

    # Full OS normalization: NAME + VERSION_ID preferred.
    assert inv.machine_id == "lin-ubuntu"
    assert inv.os_info.name == "Ubuntu"
    assert inv.os_info.version == "22.04"

    # Full package list normalization, preserving order and ecosystem tag.
    assert [(p.name, p.version, p.ecosystem) for p in inv.packages] == [
        ("openssl", "3.0.2-0ubuntu1.10", "Ubuntu:22.04:LTS"),
        ("bash", "5.1-6ubuntu1", "Ubuntu:22.04:LTS"),
        ("libc6", "2.35-0ubuntu3.4", "Ubuntu:22.04:LTS"),
        ("python3", "3.10.6-1~22.04", "Ubuntu:22.04:LTS"),
    ]
    assert inv.collected_at is not None

    # The transport lifecycle was exercised end to end.
    assert fake.connected is True
    assert fake.closed is True


def test_linux_ssh_collection_rhel_full_normalization():
    """End-to-end SSH collection for an RHEL/rpm host (Req 1.1)."""
    fake = _linux_client(_RHEL_OS_RELEASE, _RHEL_RPM)
    collector = LinuxCollector(ssh_client_factory=lambda: fake)
    target = TargetMachine(id="lin-rhel", hostname="rhel.example", platform=Platform.LINUX)

    inv = collector.collect(target, CREDS)

    assert inv.os_info.name == "Red Hat Enterprise Linux"
    assert inv.os_info.version == "9.3"
    assert [(p.name, p.version) for p in inv.packages] == [
        ("openssl", "3.0.7"),
        ("glibc", "2.34"),
        ("kernel", "5.14.0"),
    ]
    # Every package carries the collector's detected ecosystem tag.
    assert all(p.ecosystem == "Red Hat:9" for p in inv.packages)


def test_linux_ssh_issued_commands_are_read_only():
    """Read-only review of every SSH command issued (Req 1.3)."""
    fake = _linux_client(_UBUNTU_OS_RELEASE, _UBUNTU_DPKG)
    collector = LinuxCollector(ssh_client_factory=lambda: fake)
    target = TargetMachine(id="lin-ro", hostname="ro.example", platform=Platform.LINUX)

    collector.collect(target, CREDS)

    # Commands were actually issued.
    assert fake.commands, "expected the collector to issue at least one command"

    for command in fake.commands:
        lowered = command.lower()
        for forbidden in _FORBIDDEN_LINUX:
            assert forbidden not in lowered, (
                f"read-only violation: {forbidden!r} in {command!r}"
            )
        assert_no_write_redirect(command)

    # The issued commands are exactly the expected read-only inventory reads.
    assert any("os-release" in c for c in fake.commands)
    assert any("dpkg-query -W" in c or "rpm -qa" in c for c in fake.commands)


# ===========================================================================
# Windows WinRM collection (Req 1.2) — multiple OS versions end-to-end
# ===========================================================================

_WIN_SERVER_2019_OS = FakeWinRMResult(
    std_out=b"Microsoft Windows Server 2019 Datacenter\n10.0.17763\n"
)
_WIN_SERVER_2019_PKGS = FakeWinRMResult(
    std_out=(
        b"7-Zip 22.01 (x64)\t22.01\n"
        b"Microsoft Edge\t118.0.2088.76\n"
        b"Mozilla Firefox\t118.0\n"
        b"Notepad++\t8.5.8\n"
    )
)

_WIN_11_OS = FakeWinRMResult(
    std_out=b"Microsoft Windows 11 Pro\n10.0.22631\n"
)
_WIN_11_PKGS = FakeWinRMResult(
    std_out=(
        b"Google Chrome\t119.0.6045.106\n"
        b"Python 3.12.0\t3.12.0150.0\n"
        # A product whose DisplayName is present but version missing -> "unknown".
        b"Legacy Tool\t\n"
    )
)


def _windows_session(os_result, pkg_result) -> RecordingWinRMSession:
    return RecordingWinRMSession(
        {
            "Win32_OperatingSystem": os_result,
            "Uninstall": pkg_result,
        }
    )


def test_windows_winrm_collection_server2019_full_normalization():
    """End-to-end WinRM collection for Windows Server 2019 (Req 1.2)."""
    session = _windows_session(_WIN_SERVER_2019_OS, _WIN_SERVER_2019_PKGS)
    collector = WindowsCollector(winrm_session_factory=lambda endpoint, auth: session)
    target = TargetMachine(id="win-2019", hostname="win2019.example", platform=Platform.WINDOWS)

    inv = collector.collect(target, CREDS)

    assert inv.machine_id == "win-2019"
    assert inv.os_info.name == "Microsoft Windows Server 2019 Datacenter"
    assert inv.os_info.version == "10.0.17763"
    assert [(p.name, p.version, p.ecosystem) for p in inv.packages] == [
        ("7-Zip 22.01 (x64)", "22.01", "windows"),
        ("Microsoft Edge", "118.0.2088.76", "windows"),
        ("Mozilla Firefox", "118.0", "windows"),
        ("Notepad++", "8.5.8", "windows"),
    ]
    assert inv.collected_at is not None


def test_windows_winrm_collection_win11_full_normalization():
    """End-to-end WinRM collection for Windows 11 (Req 1.2)."""
    session = _windows_session(_WIN_11_OS, _WIN_11_PKGS)
    collector = WindowsCollector(winrm_session_factory=lambda endpoint, auth: session)
    target = TargetMachine(id="win-11", hostname="win11.example", platform=Platform.WINDOWS)

    inv = collector.collect(target, CREDS)

    assert inv.os_info.name == "Microsoft Windows 11 Pro"
    assert inv.os_info.version == "10.0.22631"
    names = {p.name: p.version for p in inv.packages}
    assert names == {
        "Google Chrome": "119.0.6045.106",
        "Python 3.12.0": "3.12.0150.0",
        # Missing version normalized to "unknown".
        "Legacy Tool": "unknown",
    }
    assert all(p.ecosystem == "windows" for p in inv.packages)


def test_windows_winrm_endpoint_is_wsman_url():
    """The collector builds a WinRM endpoint from the target hostname (Req 1.2)."""
    captured: dict[str, object] = {}

    def factory(endpoint, auth):
        captured["endpoint"] = endpoint
        captured["auth"] = auth
        return _windows_session(_WIN_SERVER_2019_OS, _WIN_SERVER_2019_PKGS)

    collector = WindowsCollector(winrm_session_factory=factory)
    target = TargetMachine(id="win-ep", hostname="host.example", platform=Platform.WINDOWS)

    collector.collect(target, CREDS)

    assert captured["endpoint"] == "http://host.example:5985/wsman"
    # Credentials are forwarded as a (username, password) tuple.
    assert captured["auth"] == ("scanner", "s3cret")


def test_windows_winrm_issued_scripts_are_read_only():
    """Read-only review of every PowerShell script issued (Req 1.3)."""
    session = _windows_session(_WIN_SERVER_2019_OS, _WIN_SERVER_2019_PKGS)
    collector = WindowsCollector(winrm_session_factory=lambda endpoint, auth: session)
    target = TargetMachine(id="win-ro", hostname="ro.example", platform=Platform.WINDOWS)

    collector.collect(target, CREDS)

    assert session.scripts, "expected the collector to issue at least one script"

    for script in session.scripts:
        lowered = script.lower()
        for forbidden in _FORBIDDEN_WINDOWS:
            assert forbidden not in lowered, (
                f"read-only violation: {forbidden!r} in {script!r}"
            )
        # No PowerShell file-write redirect either.
        assert ">" not in script.replace("->", ""), (
            f"script contains a write redirect: {script!r}"
        )

    # The issued scripts are exactly the expected read-only inventory queries.
    assert any("get-ciminstance" in s.lower() for s in session.scripts)
    assert any("get-itemproperty" in s.lower() for s in session.scripts)


# ===========================================================================
# Cross-platform read-only guarantee (Req 1.3)
# ===========================================================================


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WINDOWS])
def test_collection_issues_only_read_only_commands(platform):
    """Both collectors only ever issue read-only inventory commands (Req 1.3)."""
    if platform is Platform.LINUX:
        fake = _linux_client(_UBUNTU_OS_RELEASE, _UBUNTU_DPKG)
        collector = LinuxCollector(ssh_client_factory=lambda: fake)
        target = TargetMachine(id="lin", hostname="lin.example", platform=platform)
        collector.collect(target, CREDS)
        issued = fake.commands
        forbidden_verbs = _FORBIDDEN_LINUX
    else:
        session = _windows_session(_WIN_SERVER_2019_OS, _WIN_SERVER_2019_PKGS)
        collector = WindowsCollector(
            winrm_session_factory=lambda endpoint, auth: session
        )
        target = TargetMachine(id="win", hostname="win.example", platform=platform)
        collector.collect(target, CREDS)
        issued = session.scripts
        forbidden_verbs = _FORBIDDEN_WINDOWS

    assert issued
    joined = " ; ".join(issued).lower()
    for forbidden in forbidden_verbs:
        assert forbidden not in joined, (
            f"{platform.value} collector issued a mutating command: {forbidden!r}"
        )
