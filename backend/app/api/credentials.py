"""Resolve the credentials a scan target authenticates with.

Implements credential resolution for Req 11 (Req 11.5, 11.6, 11.7, 11.8,
11.9).

A request may supply a password, a private key, or nothing at all. "Nothing"
is the interesting case: when the deployment configures
``CVEDECK_DEFAULT_SSH_KEY_PATH``, a Linux target with no credentials
authenticates with that server-managed key. That is what makes a one-click
fleet re-scan possible -- without it, re-scanning twenty hosts means retyping
twenty passwords, which is the single largest source of friction in the tool.

Windows deliberately has no such fallback: WinRM has no equivalent of an SSH
key, so a Windows target without credentials is an error rather than a silent
attempt with nothing.
"""

from __future__ import annotations

from pydantic import ValidationError

from .. import config
from ..enums import Platform
from ..models import Credentials
from ..scanner.exceptions import AuthError


class CredentialResolutionError(AuthError):
    """No usable credentials could be resolved for a target."""


def _read_default_key() -> tuple[str, str | None]:
    """Read the server-managed SSH key from disk (Req 11.6).

    Read per scan rather than cached so rotating the key on disk takes effect
    without restarting the service (Req 11.7).
    """
    key_path = config.default_ssh_key_path()
    if key_path is None:
        raise CredentialResolutionError(
            "no credentials supplied and CVEDECK_DEFAULT_SSH_KEY_PATH is not set"
        )
    try:
        material = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CredentialResolutionError(
            f"could not read the server SSH key at {key_path}: {exc}"
        ) from exc
    return material, config.default_ssh_key_passphrase()


def resolve_credentials(
    platform: Platform,
    *,
    username: str | None = None,
    password: str | None = None,
    private_key: str | None = None,
    passphrase: str | None = None,
) -> Credentials:
    """Build :class:`Credentials` from a request, falling back to the server key.

    A Linux target with no credentials authenticates with the server-managed
    key (Req 11.6); a Windows target with none is rejected, since WinRM has no
    SSH-key equivalent (Req 11.8).

    Raises:
        CredentialResolutionError: When no credentials were supplied and no
            usable server-managed default is configured for this platform.
            The caller fails that target alone rather than the batch
            (Req 11.9).
    """
    supplied_secret = bool(password) or bool(private_key)

    if not supplied_secret:
        if platform is not Platform.LINUX:
            raise CredentialResolutionError(
                "credentials are required for Windows targets; the "
                "server-managed SSH key applies to Linux only"
            )
        private_key, passphrase = _read_default_key()

    resolved_user = username or config.default_ssh_user()
    if not resolved_user:
        raise CredentialResolutionError(
            "no username supplied and CVEDECK_DEFAULT_SSH_USER is not set"
        )

    try:
        return Credentials(
            username=resolved_user,
            password=password or None,
            private_key=private_key or None,
            passphrase=passphrase or None,
        )
    except ValidationError as exc:
        # Surface the model's own rule (exactly one secret, Req 11.5) as an
        # auth error so
        # the API reports it the same way as any other credential problem.
        # Pydantic prefixes custom validator messages with "Value error, ",
        # which is framework noise in a message shown to an operator.
        message = str(exc.errors()[0]["msg"]).removeprefix("Value error, ")
        raise CredentialResolutionError(message) from exc
