"""Password hashing and policy (Req 16.2).

scrypt from the standard library, so login adds no dependency. The stored form
is ``scrypt$n$r$p$salt$hash`` (salt and hash in unpadded base64), which carries
its own parameters: raising the cost later only needs :func:`needs_rehash` and a
rehash on the next successful login, not a migration.

The policy is length only -- at least :data:`MIN_LENGTH` characters -- with no
composition rules. Composition rules push people towards ``Password1!``; length
is what makes a password expensive to guess, and a password manager makes a long
one free.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading

MIN_LENGTH = 12
#: An upper bound, so a multi-megabyte "password" cannot be used to make the
#: server spend its memory on scrypt.
MAX_LENGTH = 1024

_N = 2**15
_R = 8
_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32
# scrypt needs about 128 * r * n bytes; OpenSSL's default ceiling is 32 MiB,
# which n=2^15, r=8 sits exactly on, so give it headroom.
_MAXMEM = 64 * 1024 * 1024


class PasswordPolicyError(ValueError):
    """A proposed password does not meet the policy. The message says why."""


def check_policy(password: str) -> None:
    """Raise :class:`PasswordPolicyError` if ``password`` is not acceptable."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(
            f"Use at least {MIN_LENGTH} characters. A passphrase of a few words works well."
        )
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_LENGTH} characters.")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


#: How many scrypt derivations may run at once. Each holds about 32 MiB for
#: about a tenth of a second, and sign-in runs in a thread pool about forty
#: threads wide, so without a bound a burst of sign-ins -- real usernames or
#: made-up ones, which cost the same by design -- could ask for over a
#: gigabyte at once. Queued callers wait their turn; nothing is refused
#: (Req 16.20).
SCRYPT_CONCURRENCY = 4
_SCRYPT_SLOTS = threading.BoundedSemaphore(SCRYPT_CONCURRENCY)


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    with _SCRYPT_SLOTS:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=_MAXMEM,
            dklen=_KEY_BYTES,
        )


def hash_password(password: str) -> str:
    """Hash ``password`` for storage. Does not apply the policy."""
    salt = secrets.token_bytes(_SALT_BYTES)
    key = _derive(password, salt, _N, _R, _P)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    """Whether ``password`` matches ``stored``. Never raises on a bad hash.

    A malformed stored value is a mismatch rather than an exception, so a
    corrupted row locks that account instead of turning login into a 500.
    """
    try:
        scheme, n, r, p, salt, key = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = _unb64(key)
        actual = _derive(password, _unb64(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    """Whether ``stored`` was made with weaker parameters than today's."""
    try:
        scheme, n, r, p, *_ = stored.split("$")
        return scheme != "scrypt" or (int(n), int(r), int(p)) != (_N, _R, _P)
    except ValueError:
        return True


# Hashed once at import. Verifying against it when the username is unknown means
# a login for a real account and a login for a made-up one take the same time,
# so response timing does not reveal which usernames exist (Req 16.2).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def burn_time(password: str) -> None:
    """Spend the same effort as a real verification, and discard the result."""
    verify_password(password, _DUMMY_HASH)
