"""Back off repeated failed sign-ins and setup attempts (Req 16.8).

Counted per client address *and* username together, so someone hammering one
account from one address is slowed down without locking the real owner out from
everywhere else. After :data:`FREE_ATTEMPTS` failures each further attempt is
refused for a doubling interval, from :data:`BASE_DELAY` up to
:data:`MAX_DELAY`. A success clears the count.

Failures are also counted per client address alone, with a looser limit
(:data:`FREE_ATTEMPTS_PER_CLIENT`). The per-account key never trips for someone
who tries a different made-up username every time, and every one of those
attempts costs a full scrypt verification -- about 32 MiB and a tenth of a
second -- so without a per-address count, sign-in was an unauthenticated way to
spend the server's memory and CPU at will (Req 16.20).

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
#: Failures from one address, across all usernames, before it is slowed down.
#: Loose enough that one person mistyping a few accounts never meets it.
FREE_ATTEMPTS_PER_CLIENT = 20
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
        # (client, username) per account; (client,) per address alone.
        self._entries: dict[tuple[str, ...], _Entry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(client: str, username: str) -> tuple[str, str]:
        return (client, username.strip().lower())

    def retry_after(self, client: str, username: str) -> int:
        """Seconds until another attempt is allowed; 0 when it is allowed now.

        The longer of the account's wait and the address's.
        """
        now = self._clock()
        with self._lock:
            waits = [
                entry.locked_until - now
                for entry in (
                    self._entries.get(self._key(client, username)),
                    self._entries.get((client,)),
                )
                if entry is not None
            ]
            return max(0, int(max(waits, default=0) + 0.999))

    def record_failure(self, client: str, username: str) -> None:
        now = self._clock()
        with self._lock:
            self._forget_stale(now)
            self._fail(self._key(client, username), FREE_ATTEMPTS, now)
            self._fail((client,), FREE_ATTEMPTS_PER_CLIENT, now)

    def _fail(self, key: tuple[str, ...], free: int, now: float) -> None:
        entry = self._entries.setdefault(key, _Entry())
        entry.failures += 1
        entry.last_failure = now
        if entry.failures >= free:
            over = entry.failures - free
            delay = min(MAX_DELAY, BASE_DELAY * (2**over))
            entry.locked_until = now + delay

    def record_success(self, client: str, username: str) -> None:
        with self._lock:
            self._entries.pop(self._key(client, username), None)
            self._entries.pop((client,), None)

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
