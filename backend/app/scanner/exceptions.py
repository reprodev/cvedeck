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
