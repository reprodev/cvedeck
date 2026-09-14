"""Back off repeated failed sign-ins and setup attempts (Req 16.8).

Counted per client address *and* username together, so someone hammering one
account from one address is slowed down without locking the real owner out from
everywhere else. After :data:`FREE_ATTEMPTS` failures each further attempt is
refused for a doubling interval, from :data:`BASE_DELAY` up to
:data:`MAX_DELAY`. A success clears the count.

The state is in memory. That fits how CveDeck runs -- one process, one worker,
as the Dockerfile starts it -- and a restart forgetting the counts is an
acceptable cost for not writing a row per failed attempt. Behind a reverse proxy
every request comes from the proxy's address unless uvicorn is started with
``--proxy-headers``; DEPLOYMENT.md says so.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

FREE_ATTEMPTS = 5
BASE_DELAY = 30.0
MAX_DELAY = 15 * 60.0
#: Forget a key this long after its last failure.
_FORGET_AFTER = 60 * 60.0


@dataclass
class _Entry:
    failures: int = 0
    locked_until: float = 0.0
    last_failure: float = 0.0


class LoginThrottle:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(client: str, username: str) -> tuple[str, str]:
        return (client, username.strip().lower())

    def retry_after(self, client: str, username: str) -> int:
        """Seconds until another attempt is allowed; 0 when it is allowed now."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(self._key(client, username))
            if entry is None:
                return 0
            remaining = entry.locked_until - now
            return max(0, int(remaining + 0.999))

    def record_failure(self, client: str, username: str) -> None:
        now = self._clock()
        with self._lock:
            self._forget_stale(now)
            entry = self._entries.setdefault(self._key(client, username), _Entry())
            entry.failures += 1
            entry.last_failure = now
            if entry.failures >= FREE_ATTEMPTS:
                over = entry.failures - FREE_ATTEMPTS
                delay = min(MAX_DELAY, BASE_DELAY * (2**over))
                entry.locked_until = now + delay

    def record_success(self, client: str, username: str) -> None:
        with self._lock:
            self._entries.pop(self._key(client, username), None)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def _forget_stale(self, now: float) -> None:
        stale = [
            key
            for key, entry in self._entries.items()
            if now - entry.last_failure > _FORGET_AFTER and now >= entry.locked_until
        ]
        for key in stale:
            del self._entries[key]


#: The process-wide throttle the auth routes use.
throttle = LoginThrottle()
