"""Pinned SSH host keys: trust on first use, then hold every host to its key.

Both SSH paths, a scan and a connection test, connect through
:func:`connect_pinned`, so a key accepted by one is the key the other is held
to (Req 17.6).

One connection goes like this:

1. If a key is pinned for ``(hostname, port)``, it is added to the client's
   host keys before connecting. paramiko then offers that key type first, so a
   host that also has other key types still presents the pinned one (Req 17.4),
   and raises :class:`paramiko.BadHostKeyException` if the key differs. That
   check runs after key exchange and before authentication, so a refused host
   never receives a password or a key signature.
2. If nothing is pinned, :class:`PinningPolicy` sees the presented key. Under
   ``tofu`` it records it; under ``strict`` it refuses (Req 17.5).
3. A new key is pinned only after ``connect`` succeeds, once the host has
   proved it holds the key and has accepted the credentials (Req 17.1). A
   mistyped hostname or a rejected login pins nothing.

The store is a protocol so this layer stays free of the database, like the
engine's ``_Repository``. With no store the old behaviour is kept: any key is
accepted and nothing is remembered. Only tests build collectors that way; the
deployment always supplies one.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol

import paramiko

from .exceptions import HostKeyMismatchError, HostKeyUnknownError

POLICY_TOFU = "tofu"
POLICY_STRICT = "strict"
POLICIES = (POLICY_TOFU, POLICY_STRICT)


@dataclass(frozen=True)
class PinnedHostKey:
    """A host's public key as pinned, in known_hosts terms."""

    key_type: str
    key_base64: str
    fingerprint_sha256: str

    @classmethod
    def from_key(cls, key: paramiko.PKey) -> "PinnedHostKey":
        return cls(
            key_type=key.get_name(),
            key_base64=key.get_base64(),
            fingerprint_sha256=fingerprint(key),
        )

    def to_key(self) -> paramiko.PKey:
        return paramiko.PKey.from_type_string(
            self.key_type, base64.b64decode(self.key_base64)
        )


class HostKeyStore(Protocol):
    """Where pinned keys are kept, one per ``(hostname, port)``."""

    def get(self, hostname: str, port: int) -> PinnedHostKey | None:
        ...

    def pin(self, hostname: str, port: int, key: PinnedHostKey) -> None:
        ...

    def touch(self, hostname: str, port: int) -> None:
        ...


def fingerprint(key: paramiko.PKey) -> str:
    """The key's SHA-256 fingerprint, in the form ``ssh-keygen -lf`` prints."""
    return key.fingerprint


def _known_hosts_name(hostname: str, port: int) -> str:
    """The name paramiko looks a host up under, which depends on the port."""
    return hostname if port == 22 else f"[{hostname}]:{port}"


def _bare_hostname(name: str) -> str:
    """Undo :func:`_known_hosts_name`, for messages."""
    if name.startswith("[") and "]:" in name:
        return name[1 : name.index("]:")]
    return name


class PinningPolicy(paramiko.MissingHostKeyPolicy):
    """Decides about a host that has no pinned key (Req 17.1, 17.5).

    Under ``tofu`` the presented key is only recorded here. It is pinned by
    :func:`connect_pinned` after the connection succeeds, never from inside the
    handshake.
    """

    def __init__(self, policy: str, port: int) -> None:
        if policy not in POLICIES:
            raise ValueError(f"unknown host key policy: {policy!r}")
        self._policy = policy
        self._port = port
        self.presented: paramiko.PKey | None = None

    def missing_host_key(self, client, hostname, key) -> None:
        if self._policy == POLICY_STRICT:
            raise HostKeyUnknownError(
                _bare_hostname(hostname), self._port, presented=fingerprint(key)
            )
        self.presented = key


def connect_pinned(
    client: paramiko.SSHClient,
    *,
    hostname: str,
    port: int,
    store: HostKeyStore | None,
    policy: str = POLICY_TOFU,
    **connect_kwargs: object,
) -> None:
    """``client.connect``, with the host held to its pinned key (Req 17).

    Raises:
        HostKeyMismatchError: A key is pinned and the host presented another
            (Req 17.3).
        HostKeyUnknownError: Nothing is pinned and ``policy`` is ``strict``
            (Req 17.5).

    Every other exception from ``connect`` propagates unchanged, so callers
    classify authentication and network failures as they did before.
    """
    if store is None:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=hostname, port=port, **connect_kwargs)
        return

    pinned = store.get(hostname, port)
    if pinned is not None:
        client.get_host_keys().add(
            _known_hosts_name(hostname, port), pinned.key_type, pinned.to_key()
        )
    missing = PinningPolicy(policy, port)
    client.set_missing_host_key_policy(missing)

    try:
        client.connect(hostname=hostname, port=port, **connect_kwargs)
    except paramiko.BadHostKeyException as exc:
        # Caught here because it subclasses SSHException, which every caller
        # would otherwise report as an ordinary connection failure.
        raise HostKeyMismatchError(
            hostname,
            port,
            pinned=(
                pinned.fingerprint_sha256
                if pinned is not None
                else fingerprint(exc.expected_key)
            ),
            presented=fingerprint(exc.key),
        ) from exc

    if pinned is not None:
        store.touch(hostname, port)  # Req 17.2
    elif missing.presented is not None:
        store.pin(hostname, port, PinnedHostKey.from_key(missing.presented))
