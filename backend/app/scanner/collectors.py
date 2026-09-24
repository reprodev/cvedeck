"""Agentless inventory collectors for Linux (SSH) and Windows (WinRM).

Both collectors implement the ``InventoryCollector`` protocol: they connect to
a Target_Machine read-only, run a small set of inventory commands, normalize
the raw output into an ``Inventory`` structure, and disconnect. They install
nothing on the target (Req 1.3).

Failure handling follows the design's Collector Interface:

- an unreachable host raises the built-in ``ConnectionError`` (Req 1.4), and
- an authentication failure raises ``AuthError`` (Req 1.5).

The concrete transport (``paramiko`` for SSH, ``pywinrm`` for WinRM) is
constructed lazily through an injectable factory. This keeps the real
dependency as the default while letting unit tests substitute a fake client,
so tests never touch a real host.
"""

from __future__ import annotations

import re

import io
import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

import paramiko
import winrm

from app.enums import Platform
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine

from .exceptions import AuthError, InventoryUnavailableError
from .host_keys import POLICY_TOFU, HostKeyStore, connect_pinned
from .releases import UBUNTU_CODENAMES, ubuntu_ecosystem

# Default remoting ports.
_SSH_PORT = 22
_CONNECT_TIMEOUT = 5.0
_COMMAND_TIMEOUT = 45.0

#: The most output one command may return. ``_COMMAND_TIMEOUT`` bounds each
#: read, not the command, and nothing bounded the size: a scanned host is not
#: trusted, and one that streamed forever held the scan open and grew the
#: process without limit. A full dpkg listing with dependencies for thousands
#: of packages is a few megabytes, so this is generous rather than tight.
_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024

#: Wall-clock ceiling for one command, however its bytes arrive. A host that
#: sends one byte every 44 seconds never trips the per-read timeout.
_COMMAND_DEADLINE = 180.0

#: Stderr only ever feeds a 300-character failure detail.
_STDERR_LIMIT_BYTES = 64 * 1024

_READ_CHUNK = 64 * 1024


class InventoryCollector(Protocol):
    """Connect read-only to a target and return normalized inventory."""

    def collect(
        self, target: TargetMachine, credentials: Credentials
    ) -> Inventory:  # pragma: no cover - protocol definition
        """Connect read-only and return normalized inventory.

        Raises ``ConnectionError`` on unreachable host, ``AuthError`` on auth
        failure.
        """
        ...


# ---------------------------------------------------------------------------
# Linux collector (SSH via paramiko)
# ---------------------------------------------------------------------------

# Read-only inventory commands across Linux distributions (Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky/Alma, Alpine, Arch, openSUSE).
_LINUX_OS_RELEASE_CMD = "cat /etc/os-release"

# Marker separating sections of the batched inventory command. Each SSH
# round trip pays full network latency, so the kernel and reboot probes ride
# along with the os-release read rather than opening two more channels
# (Req 12.3).
_SECTION = "___CVEDECK___"

# Running kernel, and whether a reboot is pending (Req 12.1, 12.2). A host can
# be fully patched and still running the vulnerable kernel it booted from,
# which every package-list-only scanner reports as clean.
#
# Strictly read-only, per the collector invariant and Req 12.4: `test -f` and
# `needs-restarting -r` only inspect state. `needs-restarting` is run with
# `-r` (report) and its exit status is captured rather than acted on.
_LINUX_CONTEXT_CMD = (
    "cat /etc/os-release 2>/dev/null; "
    f"echo {_SECTION}; "
    "uname -r 2>/dev/null; "
    f"echo {_SECTION}; "
    "if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then "
    "echo yes; "
    # Output is captured into a shell variable rather than redirected, so the
    # command contains no write redirect other than 2>/dev/null. The read-only
    # collector invariant is enforced by test_linux_ssh_issued_commands_are_
    # read_only, which treats any other '>' as a write.
    "elif [ -n \"$(command -v needs-restarting 2>/dev/null)\" ]; then "
    "_nr=$(needs-restarting -r 2>/dev/null); "
    "if [ $? -eq 0 ]; then echo no; else echo yes; fi; "
    "else echo unknown; fi"
)
# One arm per package manager, each emitting `name<TAB>version<TAB>depends`.
#
# Dispatched on `command -v` rather than chained with `||`, because `|` binds
# tighter than `||`: the previous version's third arm was the *pipeline*
# `apk info -v | sed ...`, and a pipeline's status is its last command's. On a
# host without `apk`, `sed` read empty stdin and exited 0, so the pipeline
# "succeeded" and the `pacman` arm was never reached -- every Arch host
# collected an empty inventory and was refused under Req 1.7. Wrapping the
# pipeline in braces does not fix it; only not depending on its exit status
# does (Req 1.1, 1.8).
#
# Every arm carries the package's declared dependencies as a third field, so
# impact assessment has the same evidence on every supported distribution
# (Req 1.9).
#
# The rpm arm iterates `[%{REQUIRENAME},]`. A bare `%{REQUIRES}` expands to the
# FIRST element of the array only, so every RPM host reported exactly one
# dependency per package -- usually a file path such as `/usr/bin/sh` rather
# than a package at all (Req 10.13).
#
# apk and pacman are read from their local databases rather than from
# `apk info -R` / `pacman -Qi`: one read instead of a per-package loop, and
# `pacman -Qi`'s field labels are localised, so parsing them would break on a
# host that is not in English.
#
# The final sentinel distinguishes "no supported package manager" from "the
# command failed", so neither is inferred from an empty inventory.
_NO_PKG_MANAGER = "CVEDECK_NO_PKG_MANAGER"
_LINUX_PACKAGES_CMD = (
    "if command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${Package}\\t${Version}\\t${Depends}\\n'; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t[%{REQUIRENAME},]\\n'; "
    "elif [ -f /lib/apk/db/installed ]; then "
    "awk '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} "
    '/^D:/{d=substr($0,3); gsub(/ +/,",",d)} '
    '/^$/{if(p!="")print p"\\t"v"\\t"d; p="";v="";d=""} '
    'END{if(p!="")print p"\\t"v"\\t"d}\' /lib/apk/db/installed; '
    "elif [ -d /var/lib/pacman/local ]; then "
    # NR!=1 rather than NR>1: equivalent here, and it keeps a '>' out of the
    # command so the read-only guard in the test suite does not have to tell a
    # comparison apart from a redirect.
    "awk 'FNR==1&&NR!=1{if(n!=\"\")print n\"\\t\"v\"\\t\"d; n=\"\";v=\"\";d=\"\";s=\"\"} "
    '/^%NAME%$/{s="n";next} /^%VERSION%$/{s="v";next} /^%DEPENDS%$/{s="d";next} '
    '/^%/{s="";next} /^$/{next} '
    's=="n"{n=$0} s=="v"{v=$0} s=="d"{d=d (d==""?"":",") $0} '
    'END{if(n!="")print n"\\t"v"\\t"d}\' /var/lib/pacman/local/*/desc; '
    f"else echo {_NO_PKG_MANAGER}; fi"
)


def _default_ssh_client_factory() -> paramiko.SSHClient:
    # No host key policy here: connect_pinned installs one per connection.
    return paramiko.SSHClient()


# Key types paramiko can load, tried in order. Ed25519 first because it is the
# modern default; RSA last because its loader is the most permissive and will
# happily raise a confusing error on a key of another type.
_PKEY_TYPES: tuple[type, ...] = (
    paramiko.Ed25519Key,
    paramiko.ECDSAKey,
    paramiko.RSAKey,
)


def parse_private_key(
    material: str, passphrase: str | None = None
) -> "paramiko.PKey":
    """Parse PEM or OpenSSH private key material held in memory (Req 9.1, 11.1).

    The key never touches disk (Req 9.3, 11.2): scans are
    credential-per-request, so writing a caller's private key to a temp file
    would widen its exposure well beyond the lifetime of the request that
    supplied it.

    Raises:
        AuthError: If no supported key type can read the material
            (Req 11.3). A wrong passphrase is reported distinctly
            (Req 11.4), because "your key is malformed" and "your passphrase
            is wrong" call for different user actions.
    """
    text = (material or "").strip()
    if not text:
        raise AuthError("private key is empty")
    # paramiko requires a trailing newline for OpenSSH-format keys.
    if not text.endswith("\n"):
        text += "\n"

    secret = passphrase or None
    saw_password_error = False

    for key_type in _PKEY_TYPES:
        try:
            return key_type.from_private_key(io.StringIO(text), password=secret)
        except paramiko.PasswordRequiredException:
            saw_password_error = True
        except paramiko.SSHException as exc:
            # Once a passphrase is supplied, a wrong one surfaces here as a
            # decryption failure rather than as PasswordRequiredException.
            # A type mismatch ("encountered RSA key, expected EC key") just
            # means this is not the right loader, so keep trying.
            message = str(exc).lower()
            if secret is not None and (
                "bad password" in message
                or "corrupt" in message
                or "decrypt" in message
            ):
                saw_password_error = True
        except Exception:
            # Not this key type; try the next.
            continue

    if saw_password_error:
        raise AuthError(
            "private key is encrypted and the passphrase is missing or incorrect"
        )
    raise AuthError(
        "unsupported or malformed private key "
        "(expected an Ed25519, ECDSA, or RSA key in PEM or OpenSSH format)"
    )


class LinuxCollector:
    """Collect inventory from a Linux host over SSH using ``paramiko``."""

    def __init__(
        self,
        ssh_client_factory: Callable[[], "paramiko.SSHClient"] | None = None,
        *,
        port: int = _SSH_PORT,
        connect_timeout: float = _CONNECT_TIMEOUT,
        command_timeout: float = _COMMAND_TIMEOUT,
        host_key_store: HostKeyStore | None = None,
        host_key_policy: str = POLICY_TOFU,
    ) -> None:
        self._ssh_client_factory = ssh_client_factory or _default_ssh_client_factory
        self._host_key_store = host_key_store
        self._host_key_policy = host_key_policy
        self._port = port
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout

    def collect(
        self, target: TargetMachine, credentials: Credentials
    ) -> Inventory:
        """Connect read-only over SSH and return normalized inventory."""
        # Resolve the authentication material before allocating a client or
        # touching the network, so a malformed key or wrong passphrase is
        # reported as exactly that rather than as a connection failure
        # (Req 11.3).
        auth_kwargs: dict[str, object] = {}
        if credentials.uses_key:
            auth_kwargs["pkey"] = parse_private_key(
                credentials.private_key.get_secret_value(),
                credentials.passphrase.get_secret_value()
                if credentials.passphrase is not None
                else None,
            )
        else:
            auth_kwargs["password"] = credentials.password.get_secret_value()

        client = self._ssh_client_factory()
        try:
            try:
                # A refused host key raises HostKeyError, which is neither
                # clause below: it is not a network failure (Req 17.3).
                connect_pinned(
                    client,
                    hostname=target.hostname,
                    port=self._port,
                    store=self._host_key_store,
                    policy=self._host_key_policy,
                    username=credentials.username,
                    timeout=self._connect_timeout,
                    allow_agent=False,
                    look_for_keys=False,
                    **auth_kwargs,
                )
            except paramiko.AuthenticationException as exc:
                method = "key" if credentials.uses_key else "password"
                raise AuthError(
                    f"{method} authentication rejected for "
                    f"{credentials.username}@{target.hostname}"
                ) from exc
            except (paramiko.SSHException, socket.error, OSError) as exc:
                raise ConnectionError(
                    f"could not connect to {target.hostname}:{self._port}"
                ) from exc

            try:
                context_output = _run_ssh_command(
                    client, _LINUX_CONTEXT_CMD, timeout=self._command_timeout
                )
                packages = _run_ssh_command_detailed(
                    client, _LINUX_PACKAGES_CMD, timeout=self._command_timeout
                )
            except CommandOutputLimitError as exc:
                # The host answered but would not stop. Failing the scan keeps
                # the previous findings; a truncated inventory would not
                # (Req 1.7, 1.11).
                raise InventoryUnavailableError(target.hostname, detail=str(exc)) from exc
        finally:
            client.close()

        os_release, kernel_version, reboot_required = _split_context(context_output)
        os_info, eco = _parse_os_release(os_release)
        if _NO_PKG_MANAGER in packages.stdout:
            # The host answered, and said it has none of the four package
            # managers CveDeck can read. That is a different fact from a
            # command that failed, and saying so beats reporting an empty
            # inventory or a generic failure (Req 1.7, 1.10).
            raise InventoryUnavailableError(
                target.hostname,
                detail=(
                    "no supported package manager found: CveDeck reads dpkg, "
                    "rpm, apk and pacman"
                ),
            )
        parsed = _parse_linux_packages(packages.stdout, default_ecosystem=eco)
        if not parsed:
            # The package command failed, or none of its output parsed.
            # Reporting that as an empty inventory would delete this host's
            # findings and call them resolved (Req 1.7).
            raise InventoryUnavailableError(
                target.hostname, detail=packages.failure_detail()
            )
        return Inventory(
            machine_id=target.id,
            os_info=os_info,
            packages=parsed,
            kernel_version=kernel_version,
            reboot_required=reboot_required,
            collected_at=datetime.now(timezone.utc),
        )


#: How much of a command's stderr is kept for a failure message. Enough to
#: carry "dpkg: error: dpkg frontend lock is locked by another process", short
#: enough that a chatty host cannot fill the scan-run row it ends up in.
_STDERR_DETAIL_LIMIT = 300


@dataclass(frozen=True)
class _CommandResult:
    """One remote command's output, with what it said about failing.

    ``exit_status`` is ``None`` when the channel could not report one, which is
    not evidence of success -- hence the empty-inventory check stands on its own
    rather than on this field.
    """

    stdout: str
    stderr: str
    exit_status: int | None

    def failure_detail(self) -> str | None:
        """A short reason for a caller to show a person, or ``None``."""
        first_line = next(
            (line.strip() for line in self.stderr.splitlines() if line.strip()), ""
        )
        detail = first_line[:_STDERR_DETAIL_LIMIT]
        if self.exit_status not in (None, 0):
            status = f"the package command exited {self.exit_status}"
            return f"{status} ({detail})" if detail else status
        return detail or None


def _run_ssh_command(client: "paramiko.SSHClient", command: str, timeout: float = _COMMAND_TIMEOUT) -> str:
    """Execute a command over SSH and return its decoded stdout."""
    return _run_ssh_command_detailed(client, command, timeout=timeout).stdout


def _run_ssh_command_detailed(
    client: "paramiko.SSHClient",
    command: str,
    timeout: float = _COMMAND_TIMEOUT,
    *,
    deadline: float | None = None,
    limit: int | None = None,
) -> _CommandResult:
    """Execute a command over SSH and return stdout, stderr and exit status.

    The exit status is read through ``getattr`` because it lives on the
    channel behind the stdout file, which not every client object exposes.

    Bounded in size and in time, because the other end is a host being
    scanned, not one that is trusted (Req 1.11). The deadline is enforced by
    closing the channel from a timer rather than by checking a clock between
    reads: paramiko's ``read(n)`` blocks until ``n`` bytes or EOF, so a host
    trickling bytes would never return control to a check. Either bound raises
    ``CommandOutputLimitError`` -- never a truncated result, which would parse
    as a smaller inventory and quietly report the missing packages resolved.
    """
    deadline = _COMMAND_DEADLINE if deadline is None else deadline
    limit = _OUTPUT_LIMIT_BYTES if limit is None else limit
    watchdog: threading.Timer | None = None
    expired = threading.Event()
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        channel = getattr(stdout, "channel", None)
        close = getattr(channel, "close", None)
        if callable(close):
            def _expire() -> None:
                expired.set()
                close()

            watchdog = threading.Timer(deadline, _expire)
            watchdog.daemon = True
            watchdog.start()
        raw = _read_bounded(stdout, limit)
        if raw is None:
            if callable(close):
                close()
            raise CommandOutputLimitError(
                f"the host sent more than {limit:,} bytes of output"
            )
        raw_err = _read_bounded(stderr, _STDERR_LIMIT_BYTES, truncate=True) if stderr is not None else b""
        recv_exit_status = getattr(channel, "recv_exit_status", None)
        exit_status = recv_exit_status() if callable(recv_exit_status) else None
    except (paramiko.SSHException, socket.error, OSError) as exc:
        if expired.is_set():
            raise CommandOutputLimitError(
                f"the command did not finish within {deadline:.0f} seconds"
            ) from exc
        raise ConnectionError(f"command failed over SSH: {command!r}") from exc
    finally:
        if watchdog is not None:
            watchdog.cancel()
    if expired.is_set():
        raise CommandOutputLimitError(
            f"the command did not finish within {deadline:.0f} seconds"
        )
    return _CommandResult(_decode(raw), _decode(raw_err), exit_status)


class CommandOutputLimitError(Exception):
    """A remote command exceeded ``_OUTPUT_LIMIT_BYTES`` or ``_COMMAND_DEADLINE``.

    Internal to this module: ``LinuxCollector.collect`` turns it into an
    ``InventoryUnavailableError`` carrying the reason, so the scan fails loudly
    and the previous findings stand (Req 1.7, 1.11).
    """


def _read_bounded(stream, limit: int, *, truncate: bool = False) -> bytes | None:
    """Read ``stream`` to EOF, or up to ``limit`` bytes.

    Returns ``None`` when the stream holds more than ``limit`` bytes, unless
    ``truncate`` is set, in which case the first ``limit`` bytes are returned.
    """
    parts: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(_READ_CHUNK)
        if not chunk:
            return b"".join(parts)
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        total += len(chunk)
        if total > limit:
            if truncate:
                parts.append(chunk[: len(chunk) - (total - limit)])
                return b"".join(parts)
            return None
        parts.append(chunk)


def _split_context(output: str) -> tuple[str, str | None, bool | None]:
    """Split the batched context command into its three sections.

    Tolerates a truncated response: an older or unusual host that emits fewer
    sections still yields whatever it did send, because losing the package
    inventory over a missing kernel probe would be a bad trade.

    Split from the right, because only the first section is target-controlled
    free text: a marker appearing inside ``/etc/os-release`` (in a ``HOME_URL``,
    say) would otherwise shift every later section, silently yielding a garbage
    kernel version rather than an error. The trailing sections are ``uname -r``
    output and a fixed yes/no/unknown token, neither of which can contain it.

    Returns:
        The ``/etc/os-release`` text, the running kernel release (or ``None``),
        and whether a reboot is pending (``None`` when undeterminable).
    """
    sections = output.rsplit(_SECTION, 2)
    os_release = sections[0] if sections else ""

    kernel = sections[1].strip() if len(sections) > 1 else ""
    kernel_version = kernel.splitlines()[0].strip() if kernel else None

    reboot_required: bool | None = None
    if len(sections) > 2:
        answer = sections[2].strip().lower()
        if answer.startswith("yes"):
            reboot_required = True
        elif answer.startswith("no"):
            reboot_required = False

    return os_release, kernel_version or None, reboot_required


def _parse_os_release(output: str) -> tuple[OsInfo, str]:
    """Parse ``/etc/os-release`` key=value lines into ``OsInfo`` and primary OSV ecosystem."""
    fields: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip().upper()] = value.strip().strip('"').strip("'")

    distro_id = fields.get("ID", "").lower()
    distro_like = fields.get("ID_LIKE", "").lower()
    version_id = fields.get("VERSION_ID", "").strip()
    name = fields.get("NAME") or fields.get("PRETTY_NAME") or "unknown"
    version = version_id or fields.get("VERSION") or "unknown"

    # Derive the OSV ecosystem, including the release wherever OSV tracks one
    # (Req 14.7). Advisories list a separate fix per release, so a host recorded
    # only as "Debian" is matched against every Debian release's fixes.
    if "ubuntu" in distro_id or "ubuntu" in distro_like:
        # Any YY.04 / YY.10 release, not a fixed list: 26.04 LTS was missing from
        # the old one and silently fell back to unversioned matching. A
        # derivative (Linux Mint, elementary OS) has its own VERSION_ID, and
        # names the Ubuntu release it is built on in UBUNTU_CODENAME instead.
        ubuntu_version = version_id if distro_id == "ubuntu" else ""
        if not ubuntu_ecosystem(ubuntu_version):
            ubuntu_version = UBUNTU_CODENAMES.get(fields.get("UBUNTU_CODENAME", "").lower(), "")
        if not ubuntu_ecosystem(ubuntu_version) and ubuntu_ecosystem(version_id):
            ubuntu_version = version_id  # Pop!_OS uses Ubuntu's own numbering
        eco = ubuntu_ecosystem(ubuntu_version) or "Ubuntu"
    elif distro_id in ("debian", "raspbian"):
        major = version_id.split(".")[0] if version_id else ""
        eco = f"Debian:{major}" if major.isdigit() else "Debian"
    elif "debian" in distro_like:
        # A Debian derivative's VERSION_ID is its own (Kali's is 2025.2), not a
        # Debian release, so it is not turned into one.
        eco = "Debian"
    elif "almalinux" in distro_id:
        major = version_id.split(".")[0] if version_id else "9"
        eco = f"AlmaLinux:{major}"
    elif "rocky" in distro_id:
        major = version_id.split(".")[0] if version_id else "9"
        eco = f"Rocky Linux:{major}"
    elif "alpine" in distro_id:
        ver_parts = version_id.split(".")
        branch = f"v{ver_parts[0]}.{ver_parts[1]}" if len(ver_parts) >= 2 else "Alpine"
        eco = f"Alpine:{branch}"
    elif "arch" in distro_id or "arch" in distro_like or "manjaro" in distro_id:
        eco = "Arch Linux"
    elif "fedora" in distro_id:
        eco = "Fedora"
    # Oracle Linux and Amazon Linux are Enterprise Linux derivatives: they track
    # upstream Red Hat advisories, so they resolve into that family rather than
    # falling through to the generic branch.
    elif distro_id == "ol" or "oracle" in distro_id:
        major = version_id.split(".")[0] if version_id else ""
        eco = f"Oracle Linux:{major}" if major else "Oracle Linux"
    elif distro_id == "amzn" or "amazon" in distro_id:
        eco = f"Amazon Linux:{version_id}" if version_id else "Amazon Linux"
    # openSUSE must be tested before SLES: "opensuse-leap" contains "suse",
    # so the enterprise branch would otherwise swallow the community distro.
    elif "opensuse" in distro_id:
        if "tumbleweed" in distro_id:
            eco = "openSUSE:Tumbleweed"
        elif "leap" in distro_id and re.fullmatch(r"\d+\.\d+", version_id):
            eco = f"openSUSE:Leap {version_id}"
        else:
            eco = "openSUSE"
    elif "sles" in distro_id or "sled" in distro_id or "suse" in distro_id:
        eco = f"SUSE:{version_id}" if version_id else "SUSE"
    elif "rhel" in distro_id or "redhat" in distro_id or "centos" in distro_id:
        # The major version is recorded, but never sent to OSV as "Red Hat:9",
        # which OSV accepts and answers with nothing. The resolver still queries
        # "Red Hat"; app.scanner.releases adds the per-release repositories
        # (Red Hat:enterprise_linux:9::baseos) that OSV does describe.
        major = version_id.split(".")[0] if version_id else ""
        eco = f"Red Hat:{major}" if major.isdigit() else "Red Hat"
    elif "wolfi" in distro_id:
        eco = "Wolfi"
    # Deliberately not "deb": silently assuming Debian on an unrecognized
    # distribution produced confidently wrong matches. "unknown" routes to the
    # universal fallback in _resolve_ecosystems, which queries every canonical
    # Linux ecosystem instead of guessing one.
    elif "debian" in distro_like or "ubuntu" in distro_like:
        eco = "Debian"
    elif "rhel" in distro_like or "fedora" in distro_like or "centos" in distro_like:
        eco = "Red Hat"
    elif "suse" in distro_like:
        eco = "openSUSE"
    else:
        eco = "unknown"

    return OsInfo(name=name, version=version), eco


#: Namespaced requirements that name a capability, not a package. apk writes
#: these for shared objects, commands and pkg-config files.
_DEP_NAMESPACES = ("so:", "cmd:", "pc:")

#: rpm capability namespaces, written as ``namespace(detail)``. rpm emits these
#: for every package, so filtering them is what keeps a displayed dependency
#: list readable. They resolve to no installed package either way, so they
#: never produced a false blast-radius edge -- only noise in the UI.
#:
#: Deliberately NOT "drop anything containing parentheses": rpm writes an
#: architecture-qualified package dependency the same way, as
#: ``rpm-libs(x86-64)``, and a versioned virtual provide as ``rocky-repos(9)``.
#: Both are real installed packages, and dropping them cost 24 genuine edges on
#: a stock Rocky 9 host when this was tried the other way round.
_RPM_CAPABILITY_NAMESPACES = ("rpmlib", "config", "rtld", "pkgconfig")

#: Characters that begin a version constraint written without a space, as apk
#: (``musl>=1.2.3``) and pacman (``linux-api-headers>=4.10``) do.
_DEP_CONSTRAINT_CHARS = "<>=!"


def _parse_dependencies(depends_str: str) -> list[str]:
    """Extract package dependency names from a package manager's depends field.

    Handles all four supported managers, which the collection command has
    already normalised to a comma-separated list:

    - dpkg: ``libc6 (>= 2.38), gpgv | gpgv2, zlib1g:amd64``
    - rpm:  ``/usr/bin/sh,config(bash),filesystem,libc.so.6()(64bit),rpmlib(...)``
    - apk:  ``musl>=1.2.3,libapk=3.0.8-r0,so:libz.so.1,/bin/sh``
    - pacman: ``readline,libreadline.so=8-64,linux-api-headers>=4.10``

    Only names a package manager could actually resolve to an installed package
    are kept, because this list is both shown to the reader and counted to
    derive a blast radius (Req 10.13). A file path, a soname, an rpm internal
    or an apk capability is not a package, and counting one inflates the
    dependents of everything that requires it.

    The filters run on the RAW token, before any splitting. The predecessor
    computed ``item.split("(")[0].split(":")[0]`` first and only then tested
    ``startswith("rpmlib(")``, so that test could never fire: ``rpmlib(X)`` had
    already become ``rpmlib``. Every RPM host carried fictional packages named
    ``rpmlib`` and ``config``; applied to apk, the same line turned
    ``so:libc.musl-x86_64.so.1`` into ``so``.
    """
    if not depends_str or depends_str.strip() == "(none)":
        return []
    deps: list[str] = []
    for raw in depends_str.split(","):
        item = raw.strip()
        if not item:
            continue
        # First alternative of a dpkg choice: 'pkgA | pkgB' -> 'pkgA'.
        item = item.split("|")[0].strip()
        if not item:
            continue

        # --- filters on the raw token, before any splitting ---
        # An rpm file requirement, or an apk path dependency.
        if item.startswith("/"):
            continue
        # An apk capability: so:, cmd:, pc:.
        if item.startswith(_DEP_NAMESPACES):
            continue
        # An rpm rich dependency: '(a if b)'.
        if item.startswith("("):
            continue

        # A space-separated constraint: rpm 'glibc >= 2.38', dpkg
        # 'libc6 (>= 2.38)'. Everything after the name is the constraint.
        name = item.split()[0]
        # The base name, before any rpm qualifier or capability detail:
        # 'rpm-libs(x86-64)' -> 'rpm-libs', 'rpmlib(FileDigests)' -> 'rpmlib'.
        base = name.split("(")[0]
        if base in _RPM_CAPABILITY_NAMESPACES:
            continue
        name = base
        # A constraint written without a space: musl>=1.2.3, libapk=3.0.8-r0.
        for index, char in enumerate(name):
            if char in _DEP_CONSTRAINT_CHARS:
                name = name[:index]
                break
        # A dpkg architecture qualifier: zlib1g:amd64.
        name = name.split(":")[0].strip()
        # A pacman or dpkg soname dependency: libreadline.so, libc.so.6.
        if ".so" in name:
            continue

        if name and name not in deps:
            deps.append(name)
    return deps


def _parse_linux_packages(
    output: str, default_ecosystem: str = "deb"
) -> list[Package]:
    """Parse tab-separated ``name<TAB>version<TAB>depends`` lines into ``Package`` records."""
    packages: list[Package] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            name, version = parts[0].strip(), parts[1].strip()
            deps_str = parts[2].strip() if len(parts) >= 3 else ""
        else:
            # Fallback to whitespace-separated
            ws_parts = line.split()
            if len(ws_parts) < 2:
                continue
            name, version = ws_parts[0].strip(), ws_parts[1].strip()
            deps_str = ""

        if not name or not version:
            continue
        # The whitespace fallback above is permissive enough to read a shell
        # error as a package: "bash: dpkg-query: command not found" parses to
        # name "bash:", version "dpkg-query:". Every real package version from
        # dpkg, rpm, apk and pacman contains a digit, and a scan is better off
        # finding nothing here -- which is now refused (Req 1.7) -- than
        # matching advisories against a line of stderr.
        if not any(char.isdigit() for char in version):
            continue
        dependencies = _parse_dependencies(deps_str)
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem=default_ecosystem,
                dependencies=dependencies,
            )
        )
    return packages


# ---------------------------------------------------------------------------
# Windows collector (WinRM via pywinrm)
# ---------------------------------------------------------------------------

# Read-only PowerShell. `Get-CimInstance`/registry reads only *query* state;
# nothing is installed or modified on the target (Req 1.3).
_WINDOWS_OS_PS = (
    "$os = Get-CimInstance Win32_OperatingSystem; "
    "Write-Output $os.Caption; Write-Output $os.Version"
)
_WINDOWS_PACKAGES_PS = (
    "Get-ItemProperty "
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
    "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
    "| Where-Object { $_.DisplayName } "
    "| ForEach-Object { \"$($_.DisplayName)`t$($_.DisplayVersion)\" }"
)


def _default_winrm_session_factory(
    endpoint: str, auth: tuple[str, str]
) -> "winrm.Session":
    return winrm.Session(
        endpoint,
        auth=auth,
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=5,
        operation_timeout_sec=5,
    )


class WindowsCollector:
    """Collect inventory from a Windows host over WinRM using ``pywinrm``."""

    def __init__(
        self,
        winrm_session_factory: Callable[[str, tuple[str, str]], "winrm.Session"]
        | None = None,
        *,
        scheme: str = "http",
        port: int = 5985,
    ) -> None:
        self._winrm_session_factory = (
            winrm_session_factory or _default_winrm_session_factory
        )
        self._scheme = scheme
        self._port = port

    def collect(
        self, target: TargetMachine, credentials: Credentials
    ) -> Inventory:
        """Connect read-only over WinRM and return normalized inventory."""
        # Fast TCP pre-flight check when using the live factory to fail fast on unreachable ports
        if self._winrm_session_factory is _default_winrm_session_factory:
            try:
                sock = socket.create_connection(
                    (target.hostname, self._port), timeout=2.5
                )
                sock.close()
            except (socket.error, OSError) as exc:
                raise ConnectionError(
                    f"could not connect to WinRM on {target.hostname}:{self._port}"
                ) from exc

        endpoint = f"{self._scheme}://{target.hostname}:{self._port}/wsman"
        auth = (credentials.username, credentials.password.get_secret_value())

        try:
            session = self._winrm_session_factory(endpoint, auth)
        except Exception as exc:  # pragma: no cover - factory-specific
            raise ConnectionError(
                f"could not create WinRM session to {target.hostname}"
            ) from exc

        os_output = _run_ps(session, _WINDOWS_OS_PS, target.hostname)
        packages_output = _run_ps(session, _WINDOWS_PACKAGES_PS, target.hostname)

        packages = _parse_windows_packages(packages_output)
        if not packages:
            # Same rule as the Linux collector: nothing readable is not the
            # same claim as nothing installed (Req 1.7).
            raise InventoryUnavailableError(target.hostname)

        return Inventory(
            machine_id=target.id,
            os_info=_parse_windows_os(os_output),
            packages=packages,
            collected_at=datetime.now(timezone.utc),
        )


def _run_ps(session: "winrm.Session", script: str, hostname: str) -> str:
    """Run PowerShell over WinRM and return decoded stdout.

    Maps transport errors to ``ConnectionError`` and WinRM authentication
    errors to ``AuthError``. A non-zero exit status with authentication-related
    stderr is also treated as an auth failure.
    """
    try:
        result = session.run_ps(script)
    except Exception as exc:  # pywinrm raises transport/auth errors here
        if _is_auth_error(exc):
            raise AuthError(f"authentication failed for WinRM host {hostname}") from exc
        raise ConnectionError(f"could not connect to WinRM host {hostname}") from exc

    stderr = _decode(getattr(result, "std_err", b""))
    if getattr(result, "status_code", 0) != 0:
        if _is_auth_message(stderr):
            raise AuthError(f"authentication failed for WinRM host {hostname}")
        raise ConnectionError(
            f"WinRM command failed on {hostname}: {stderr.strip()[:200]}"
        )
    return _decode(getattr(result, "std_out", b""))


def _is_auth_error(exc: Exception) -> bool:
    """Best-effort classification of a pywinrm exception as an auth failure."""
    name = type(exc).__name__.lower()
    if "auth" in name or "unauthorized" in name:
        return True
    return _is_auth_message(str(exc))


def _is_auth_message(message: str) -> bool:
    lowered = message.lower()
    return (
        "401" in lowered
        or "unauthorized" in lowered
        or "authentication" in lowered
        or "access is denied" in lowered
    )


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def _parse_windows_os(output: str) -> OsInfo:
    """Parse the two-line ``Caption`` / ``Version`` PowerShell output."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    name = lines[0] if len(lines) >= 1 else "unknown"
    version = lines[1] if len(lines) >= 2 else "unknown"
    return OsInfo(name=name, version=version)


def _parse_windows_packages(output: str) -> list[Package]:
    """Parse ``DisplayName<TAB>DisplayVersion`` lines into ``Package`` records."""
    packages: list[Package] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        name, sep, version = line.partition("\t")
        name = name.strip()
        version = version.strip() if sep else ""
        if not name:
            continue
        packages.append(
            Package(name=name, version=version or "unknown", ecosystem="windows")
        )
    return packages


def get_collector(platform: Platform) -> InventoryCollector:
    """Return the collector implementation for a platform.

    Provided for convenience; the ScannerEngine (task 5.3) selects a collector
    by platform.
    """
    if platform is Platform.LINUX:
        return LinuxCollector()
    if platform is Platform.WINDOWS:
        return WindowsCollector()
    raise ValueError(f"unsupported platform: {platform!r}")  # pragma: no cover
