"""Exceptions raised by the agentless collectors.

Collectors surface two distinct, recoverable failure modes so the
``ScannerEngine`` can map them to per-target statuses (``CONNECTION_FAILURE``
and ``AUTH_FAILURE``) without aborting a batch scan:

- ``ConnectionError`` (the built-in) is raised when a Target_Machine is
  unreachable (network error, refused connection, timeout). The collectors
  reuse Python's built-in ``ConnectionError`` per the design's Collector
  Interface, so it is intentionally not redefined here.
- ``AuthError`` (defined below) is raised when the target is reachable but
  authentication fails (bad username/password/key).
"""

from __future__ import annotations


class CollectorError(Exception):
    """Base class for collector failures."""


class AuthError(CollectorError):
    """Raised when authentication to a Target_Machine fails.

    Distinct from a connection failure: the host was reachable but rejected
    the supplied credentials. The ScannerEngine maps this to an
    ``AUTH_FAILURE`` status for the affected target (Req 1.5).
    """


class HostKeyError(CollectorError):
    """Base class for a refused SSH host key (Req 17).

    Raised before authentication, so no credential was offered to the host.
    Deliberately not a ``ConnectionError``: the host answered, and presenting a
    possible interception as an ordinary network failure would invite the user
    to retry until it goes through.
    """

    def __init__(self, hostname: str, port: int, message: str) -> None:
        super().__init__(message)
        self.hostname = hostname
        self.port = port


class HostKeyMismatchError(HostKeyError):
    """The host presented a key other than the one pinned for it (Req 17.3).

    Maps to ``HOST_KEY_MISMATCH``. Either the host was rebuilt or its keys were
    regenerated, or something between the scanner and the host is answering in
    its place. Nothing on the wire tells those apart, so the scan is refused
    and a person decides.
    """

    def __init__(
        self, hostname: str, port: int, *, pinned: str, presented: str
    ) -> None:
        super().__init__(
            hostname,
            port,
            f"SSH host key for {hostname}:{port} has changed: pinned "
            f"{pinned}, presented {presented}. Refused before any credentials "
            "were sent. If the host was rebuilt or its keys regenerated, "
            "forget the pinned key and scan again.",
        )
        self.pinned = pinned
        self.presented = presented


class HostKeyUnknownError(HostKeyError):
    """No key is pinned for the host and the policy is ``strict`` (Req 17.5).

    Maps to ``HOST_KEY_UNKNOWN``.
    """

    def __init__(self, hostname: str, port: int, *, presented: str) -> None:
        super().__init__(
            hostname,
            port,
            f"No SSH host key is pinned for {hostname}:{port} and "
            "CVEDECK_SSH_HOST_KEY_POLICY is strict. The host presented "
            f"{presented}. Refused before any credentials were sent.",
        )
        self.presented = presented
