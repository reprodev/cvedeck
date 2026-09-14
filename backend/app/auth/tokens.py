"""Random tokens, and the only form in which they are stored (Req 16.5, 16.7).

Session cookies and API tokens are 32 random bytes from :mod:`secrets`. The
database holds their SHA-256, never the token: a stolen database, backup or log
of it cannot be replayed as a login. A fast hash is right here, unlike for
passwords, because the input already has 256 bits of entropy -- there is
nothing to brute-force.
"""

from __future__ import annotations

import hashlib
import secrets

#: API tokens start with this, so they are recognisable in a script, a secret
#: scanner, or a leaked paste.
API_TOKEN_PREFIX = "cvd_"

_TOKEN_BYTES = 32


def new_session_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def new_api_token() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def display_prefix(token: str) -> str:
    """The part of an API token that is safe to show in a list."""
    return token[: len(API_TOKEN_PREFIX) + 6]


_SETUP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L


def new_setup_code() -> str:
    """A code like ``7KQ4-M2XD-9HPA``, easy to read out of a log and type.

    Twelve characters from a 31-character alphabet, about 59 bits. It only has
    to survive guessing for as long as the instance sits unclaimed, and the
    same throttling as login applies to it.
    """
    groups = [
        "".join(secrets.choice(_SETUP_ALPHABET) for _ in range(4)) for _ in range(3)
    ]
    return "-".join(groups)


def normalise_setup_code(code: str) -> str:
    """Accept the code however it was typed: any case, with or without dashes."""
    return "".join(ch for ch in code.upper() if ch.isalnum())
