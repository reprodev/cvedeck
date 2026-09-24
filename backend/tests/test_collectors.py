"""Unit tests for the agentless inventory collectors (task 5.1).

These tests mock the paramiko/pywinrm transports through the collectors'
injectable factories so no real host is ever contacted. They verify:

- normalization of raw SSH/WinRM output into an ``Inventory`` (Req 1.1, 1.2),
- that an unreachable host raises ``ConnectionError`` (Req 1.4), and
- that an authentication failure raises ``AuthError`` (Req 1.5).

The commands issued by the collectors are also asserted to be read-only
(Req 1.3): they only read files / query package databases and never install
or modify anything on the target.
"""

from __future__ import annotations

import io

import socket

import paramiko
import pytest

from app.enums import Platform
from app.models import Credentials, TargetMachine
from app.scanner.collectors import (
    LinuxCollector,
    WindowsCollector,
    get_collector,
)
from app.scanner.exceptions import AuthError, InventoryUnavailableError


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeChannelFile(io.BytesIO):
    """stdout/stderr as paramiko returns them: a stream read to EOF."""


class FakeSSHClient:
    """Stand-in for ``paramiko.SSHClient`` driven by canned command output."""

    def __init__(
        self,
        command_output: dict[str, bytes] | None = None,
        *,
        connect_exc: Exception | None = None,
    ) -> None:
        self._command_output = command_output or {}
        self._connect_exc = connect_exc
        self.connected = False
        self.closed = False
        self.commands: list[str] = []

    def set_missing_host_key_policy(self, policy) -> None:  # pragma: no cover
        pass

    def connect(self, **kwargs) -> None:
        if self._connect_exc is not None:
            raise self._connect_exc
        self.connected = True

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        data = self._command_output.get(command, b"")
        return None, _FakeChannelFile(data), _FakeChannelFile(b"")

    def close(self) -> None:
        self.closed = True


class FakeWinRMResult:
    def __init__(self, std_out=b"", std_err=b"", status_code=0) -> None:
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class FakeWinRMSession:
    def __init__(self, script_output: dict[str, FakeWinRMResult] | None = None) -> None:
        self._script_output = script_output or {}
        self.scripts: list[str] = []

    def run_ps(self, script):
        self.scripts.append(script)
        for key, result in self._script_output.items():
            if key in script:
                return result
        return FakeWinRMResult(std_out=b"", status_code=0)


LINUX_TARGET = TargetMachine(id="m-1", hostname="linux.example", platform=Platform.LINUX)
WINDOWS_TARGET = TargetMachine(
    id="m-2", hostname="win.example", platform=Platform.WINDOWS
)
CREDS = Credentials(username="admin", password="s3cret")


# ---------------------------------------------------------------------------
# LinuxCollector
# ---------------------------------------------------------------------------

_OS_RELEASE = (
    b'NAME="Ubuntu"\n'
    b'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
    b"VERSION_ID=\"22.04\"\n"
    b'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
)
_DPKG_OUTPUT = b"openssl\t3.0.2-0ubuntu1.10\nbash\t5.1-6ubuntu1\n"


def _linux_command_map():
    from app.scanner import collectors

    return {
        collectors._LINUX_CONTEXT_CMD: _linux_context(_OS_RELEASE),
        collectors._LINUX_PACKAGES_CMD: _DPKG_OUTPUT,
    }


def _linux_context(
    os_release: bytes,
    kernel: bytes = b"5.15.0-56-generic",
    reboot: bytes = b"no",
) -> bytes:
    """Build the sectioned output of the batched Linux context command.

    The kernel and reboot probes ride along with the os-release read in one SSH
    round trip, so fakes have to emit all three sections.
    """
    from app.scanner import collectors

    marker = collectors._SECTION.encode()
    nl = b"\n"
    return os_release + nl + marker + nl + kernel + nl + marker + nl + reboot


def test_linux_collect_normalizes_inventory():
    fake = FakeSSHClient(_linux_command_map())
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    inv = collector.collect(LINUX_TARGET, CREDS)

    assert inv.machine_id == "m-1"
    assert inv.os_info.name == "Ubuntu"
    assert inv.os_info.version == "22.04"
    names = {p.name: p.version for p in inv.packages}
    assert names == {
        "openssl": "3.0.2-0ubuntu1.10",
        "bash": "5.1-6ubuntu1",
    }
    assert inv.collected_at is not None
    # Connection was opened and closed (no leak).
    assert fake.connected is True
    assert fake.closed is True


def test_linux_commands_are_read_only():
    fake = FakeSSHClient(_linux_command_map())
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    collector.collect(LINUX_TARGET, CREDS)

    joined = " ; ".join(fake.commands).lower()
    # No installation / mutation verbs appear in any issued command. Note the
    # only redirect used is `2>/dev/null` (discarding stderr), which does not
    # write to the target, so a bare `>` file-redirect must be absent.
    for forbidden in (
        "apt-get install",
        "yum install",
        "install ",
        "rm ",
        "dd ",
        "> /",
        ">/etc",
        ">>",
    ):
        assert forbidden not in joined
    # The commands only read os-release and query the package DB.
    assert any("os-release" in c for c in fake.commands)
    assert any("dpkg-query" in c or "rpm -qa" in c for c in fake.commands)


def test_linux_unreachable_host_raises_connection_error():
    fake = FakeSSHClient(connect_exc=socket.timeout("timed out"))
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(ConnectionError):
        collector.collect(LINUX_TARGET, CREDS)
    # Client is still cleaned up on failure.
    assert fake.closed is True


def test_linux_ssh_exception_raises_connection_error():
    fake = FakeSSHClient(connect_exc=paramiko.SSHException("no route"))
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(ConnectionError):
        collector.collect(LINUX_TARGET, CREDS)


def test_linux_auth_failure_raises_auth_error():
    fake = FakeSSHClient(
        connect_exc=paramiko.AuthenticationException("bad password")
    )
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(AuthError):
        collector.collect(LINUX_TARGET, CREDS)
    assert fake.closed is True


def test_linux_os_release_fallback_to_unknown():
    # Packages present: a host whose os-release is unreadable is still scannable,
    # and an empty package list is refused separately (Req 1.7).
    fake = FakeSSHClient(
        {
            _linux_cmd("os"): b"",
            _linux_cmd("pkg"): b"curl\t7.88.1\tlibc6\n",
        }
    )
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    inv = collector.collect(LINUX_TARGET, CREDS)
    assert inv.os_info.name == "unknown"
    assert inv.os_info.version == "unknown"
    assert [p.name for p in inv.packages] == ["curl"]


def _linux_cmd(which: str) -> str:
    from app.scanner import collectors

    return (
        collectors._LINUX_OS_RELEASE_CMD
        if which == "os"
        else collectors._LINUX_PACKAGES_CMD
    )


# ---------------------------------------------------------------------------
# WindowsCollector
# ---------------------------------------------------------------------------


def _windows_output_map():
    from app.scanner import collectors

    return {
        "Win32_OperatingSystem": FakeWinRMResult(
            std_out=b"Microsoft Windows Server 2019 Datacenter\n10.0.17763\n"
        ),
        "Uninstall": FakeWinRMResult(
            std_out=b"7-Zip 22.01\t22.01\nMozilla Firefox\t118.0\n"
        ),
    }


def test_windows_collect_normalizes_inventory():
    session = FakeWinRMSession(_windows_output_map())
    collector = WindowsCollector(winrm_session_factory=lambda endpoint, auth: session)

    inv = collector.collect(WINDOWS_TARGET, CREDS)

    assert inv.machine_id == "m-2"
    assert inv.os_info.name == "Microsoft Windows Server 2019 Datacenter"
    assert inv.os_info.version == "10.0.17763"
    names = {p.name: p.version for p in inv.packages}
    assert names == {"7-Zip 22.01": "22.01", "Mozilla Firefox": "118.0"}
    assert inv.collected_at is not None


def test_windows_commands_are_read_only():
    session = FakeWinRMSession(_windows_output_map())
    collector = WindowsCollector(winrm_session_factory=lambda endpoint, auth: session)

    collector.collect(WINDOWS_TARGET, CREDS)

    joined = " ; ".join(session.scripts).lower()
    for forbidden in (
        "install-",
        "set-itemproperty",
        "new-item",
        "remove-item",
        "start-process",
    ):
        assert forbidden not in joined
    assert any("get-ciminstance" in s.lower() for s in session.scripts)
    assert any("get-itemproperty" in s.lower() for s in session.scripts)


def test_windows_unreachable_host_raises_connection_error():
    def factory(endpoint, auth):
        session = FakeWinRMSession()

        def boom(script):
            raise ConnectionError("network down")

        session.run_ps = boom  # type: ignore[assignment]
        return session

    collector = WindowsCollector(winrm_session_factory=factory)
    with pytest.raises(ConnectionError):
        collector.collect(WINDOWS_TARGET, CREDS)


def test_windows_transport_error_raises_connection_error():
    def factory(endpoint, auth):
        session = FakeWinRMSession()

        def boom(script):
            raise OSError("connection refused")

        session.run_ps = boom  # type: ignore[assignment]
        return session

    collector = WindowsCollector(winrm_session_factory=factory)
    with pytest.raises(ConnectionError):
        collector.collect(WINDOWS_TARGET, CREDS)


def test_windows_auth_failure_from_exception_raises_auth_error():
    class UnauthorizedError(Exception):
        pass

    def factory(endpoint, auth):
        session = FakeWinRMSession()

        def boom(script):
            raise UnauthorizedError("the server returned 401 Unauthorized")

        session.run_ps = boom  # type: ignore[assignment]
        return session

    collector = WindowsCollector(winrm_session_factory=factory)
    with pytest.raises(AuthError):
        collector.collect(WINDOWS_TARGET, CREDS)


def test_windows_auth_failure_from_status_code_raises_auth_error():
    def factory(endpoint, auth):
        return FakeWinRMSession(
            {
                "Win32_OperatingSystem": FakeWinRMResult(
                    std_err=b"Access is denied.", status_code=1
                )
            }
        )

    collector = WindowsCollector(winrm_session_factory=factory)
    with pytest.raises(AuthError):
        collector.collect(WINDOWS_TARGET, CREDS)


def test_windows_nonzero_status_non_auth_raises_connection_error():
    def factory(endpoint, auth):
        return FakeWinRMSession(
            {
                "Win32_OperatingSystem": FakeWinRMResult(
                    std_err=b"some transient error", status_code=1
                )
            }
        )

    collector = WindowsCollector(winrm_session_factory=factory)
    with pytest.raises(ConnectionError):
        collector.collect(WINDOWS_TARGET, CREDS)


# ---------------------------------------------------------------------------
# get_collector
# ---------------------------------------------------------------------------


def test_get_collector_selects_by_platform():
    assert isinstance(get_collector(Platform.LINUX), LinuxCollector)
    assert isinstance(get_collector(Platform.WINDOWS), WindowsCollector)


def test_context_split_survives_a_marker_inside_os_release():
    """Only the first section is target-controlled free text.

    `/etc/os-release` is arbitrary vendor-supplied content. A marker appearing
    inside it (in a HOME_URL, say) would shift every later section if the split
    were left-to-right, silently yielding a garbage kernel version rather than
    an error. Splitting from the right keeps the trailing sections -- `uname -r`
    output and a fixed yes/no/unknown token -- correctly anchored.
    """
    from app.scanner import collectors

    marker = collectors._SECTION
    os_release = (
        'NAME="Ubuntu"\n'
        "ID=ubuntu\n"
        'VERSION_ID="22.04"\n'
        f'HOME_URL="https://example.invalid/{marker}/docs"'
    )
    output = f"{os_release}\n{marker}\n6.1.0-generic\n{marker}\nno"

    parsed_os_release, kernel, reboot = collectors._split_context(output)

    assert kernel == "6.1.0-generic"
    assert reboot is False
    _os_info, eco = collectors._parse_os_release(parsed_os_release)
    assert eco == "Ubuntu:22.04:LTS"


def test_context_split_tolerates_a_truncated_response():
    """A connection dropped mid-stream must not lose the sections that arrived."""
    from app.scanner import collectors

    marker = collectors._SECTION

    assert collectors._split_context("ID=ubuntu")[1:] == (None, None)
    assert collectors._split_context(f"ID=ubuntu\n{marker}\n6.1.0")[1:] == ("6.1.0", None)


def test_reboot_required_is_none_when_undeterminable():
    """"unknown" must not be coerced to False; absence of evidence is not evidence."""
    from app.scanner import collectors

    marker = collectors._SECTION
    _os, _kernel, reboot = collectors._split_context(
        f"ID=ubuntu\n{marker}\n6.1.0\n{marker}\nunknown"
    )
    assert reboot is None


# ---------------------------------------------------------------------------
# An unreadable package inventory is refused, never reported as an empty one
# (Req 1.7)
# ---------------------------------------------------------------------------


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeChannelFileWithStatus(_FakeChannelFile):
    """stdout that can report an exit status, as paramiko's does."""

    def __init__(self, data: bytes, exit_status: int) -> None:
        super().__init__(data)
        self.channel = _FakeChannel(exit_status)


class FailingPackageClient(FakeSSHClient):
    """A host where every package manager arm fails."""

    def __init__(self, os_output: bytes, *, stderr: bytes, exit_status: int) -> None:
        super().__init__({})
        self._os_output = os_output
        self._stderr = stderr
        self._exit_status = exit_status

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        if command == _linux_cmd("os"):
            return None, _FakeChannelFile(self._os_output), _FakeChannelFile(b"")
        return (
            None,
            _FakeChannelFileWithStatus(b"", self._exit_status),
            _FakeChannelFile(self._stderr),
        )


def test_a_host_with_no_readable_packages_is_refused_not_reported_empty():
    """Validates Req 1.7."""
    fake = FailingPackageClient(
        b'NAME="Debian GNU/Linux"\nVERSION_ID="12"\n',
        stderr=b"dpkg: error: dpkg frontend lock is locked by another process\n",
        exit_status=127,
    )
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(InventoryUnavailableError) as excinfo:
        collector.collect(LINUX_TARGET, CREDS)

    message = str(excinfo.value)
    assert LINUX_TARGET.hostname in message
    # The reason travels with it, so a scan run can say why it failed.
    assert "127" in message
    assert "frontend lock" in message


def test_the_refusal_carries_no_exit_status_when_the_channel_cannot_report_one():
    """Validates Req 1.7: an unknown exit status is not read as success."""
    fake = FakeSSHClient(
        {_linux_cmd("os"): b'NAME="Alpine Linux"\n', _linux_cmd("pkg"): b""}
    )
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(InventoryUnavailableError):
        collector.collect(LINUX_TARGET, CREDS)


def test_output_that_parses_to_no_packages_is_also_refused():
    """Validates Req 1.7: unparsable output is not an empty inventory."""
    fake = FakeSSHClient(
        {
            _linux_cmd("os"): b'NAME="Debian GNU/Linux"\n',
            # A banner, a warning, anything without a tab-separated pair.
            _linux_cmd("pkg"): b"bash: dpkg-query: command not found\n",
        }
    )
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    with pytest.raises(InventoryUnavailableError):
        collector.collect(LINUX_TARGET, CREDS)


# ---------------------------------------------------------------------------
# A scanned host is not trusted: its output is bounded in size and time
# (Req 1.11)
# ---------------------------------------------------------------------------


class _EndlessClient(FakeSSHClient):
    """A host whose package command returns ``stdout`` and ``channel``."""

    def __init__(self, stdout) -> None:
        super().__init__({})
        self._stdout = stdout

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        if command == _linux_cmd("packages"):
            return None, self._stdout, _FakeChannelFile(b"")
        return None, _FakeChannelFile(b'NAME="Debian GNU/Linux"\n'), _FakeChannelFile(b"")


def test_a_host_that_floods_output_fails_the_scan(monkeypatch):
    """Too much output is a failed scan, never a truncated inventory.

    Truncating would parse as a smaller host, and every finding on a package
    past the cut would be reported resolved -- the Req 1.7 failure by another
    road. The output here is well-formed package lines, so a reader that
    silently kept the first ``limit`` bytes would return a plausible answer.
    """
    from app.scanner import collectors

    monkeypatch.setattr(collectors, "_OUTPUT_LIMIT_BYTES", 1024)
    flood = b"".join(b"pkg%d\t1.0\n" % i for i in range(1000))
    collector = LinuxCollector(ssh_client_factory=lambda: _EndlessClient(_FakeChannelFile(flood)))

    with pytest.raises(InventoryUnavailableError) as excinfo:
        collector.collect(LINUX_TARGET, CREDS)

    assert "more than 1,024 bytes" in str(excinfo.value)


def test_output_just_under_the_limit_is_read_in_full(monkeypatch):
    """The bound is a ceiling, not a truncation: everything below it counts."""
    from app.scanner import collectors

    body = b"".join(b"pkg%d\t1.0\n" % i for i in range(50))
    monkeypatch.setattr(collectors, "_OUTPUT_LIMIT_BYTES", len(body))
    collector = LinuxCollector(ssh_client_factory=lambda: _EndlessClient(_FakeChannelFile(body)))

    inventory = collector.collect(LINUX_TARGET, CREDS)

    assert len(inventory.packages) == 50


class _TricklingStdout:
    """Sends a byte, then never another -- until the channel is closed.

    paramiko's ``read`` behaves the same way: it blocks for more data and
    returns EOF once the channel closes, so the only way to stop it is to
    close the channel, which is what the deadline has to do.
    """

    def __init__(self) -> None:
        import threading

        self._closed = threading.Event()
        self._sent = False
        outer = self

        class _Channel:
            def close(self) -> None:
                outer._closed.set()

            def recv_exit_status(self) -> int:
                return -1

        self.channel = _Channel()

    def read(self, size=-1) -> bytes:
        if not self._sent:
            self._sent = True
            return b"p"
        # A real trickler never stops; a test must, so cap the wait.
        if not self._closed.wait(timeout=10):
            raise AssertionError("the deadline never closed the channel")
        return b""


def test_a_host_that_trickles_output_fails_at_the_deadline(monkeypatch):
    """The per-read timeout never trips for a host sending one byte at a time."""
    from app.scanner import collectors

    monkeypatch.setattr(collectors, "_COMMAND_DEADLINE", 0.2)
    collector = LinuxCollector(ssh_client_factory=lambda: _EndlessClient(_TricklingStdout()))

    with pytest.raises(InventoryUnavailableError) as excinfo:
        collector.collect(LINUX_TARGET, CREDS)

    assert "did not finish within" in str(excinfo.value)
