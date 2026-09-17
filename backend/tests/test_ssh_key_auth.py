"""Tests for SSH key-based authentication (roadmap Phase A and B).

Password-only auth ruled out every passwordless Linux environment, which is
most hardened fleets. These cover in-memory key parsing, the collector's use of
it, and the server-managed key fallback that makes a credential-free fleet
re-scan possible.

No test touches a real host: keys are generated in-process and the collector's
transport is injected.
"""

from __future__ import annotations

import io

import paramiko
import pytest
from pydantic import ValidationError

from app.api.credentials import CredentialResolutionError, resolve_credentials
from app.enums import Platform
from app.models import Credentials, TargetMachine
from app.scanner.collectors import LinuxCollector, parse_private_key
from app.scanner.exceptions import AuthError


def _rsa_pem(password: str | None = None) -> str:
    key = paramiko.RSAKey.generate(2048)
    buffer = io.StringIO()
    key.write_private_key(buffer, password=password)
    return buffer.getvalue()


def _ecdsa_pem() -> str:
    buffer = io.StringIO()
    paramiko.ECDSAKey.generate().write_private_key(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Key parsing
# ---------------------------------------------------------------------------


def test_parses_rsa_and_ecdsa_keys():
    assert parse_private_key(_rsa_pem()).get_name() == "ssh-rsa"
    assert parse_private_key(_ecdsa_pem()).get_name().startswith("ecdsa-")


def test_parses_an_encrypted_key_with_the_right_passphrase():
    assert parse_private_key(_rsa_pem("hunter2"), "hunter2").get_name() == "ssh-rsa"


def test_missing_passphrase_is_reported_distinctly_from_a_bad_key():
    """A malformed key and a wrong passphrase call for different user actions."""
    with pytest.raises(AuthError, match="passphrase"):
        parse_private_key(_rsa_pem("hunter2"))


def test_wrong_passphrase_is_reported_as_a_passphrase_problem():
    with pytest.raises(AuthError, match="passphrase"):
        parse_private_key(_rsa_pem("hunter2"), "wrong")


def test_malformed_key_names_the_supported_formats():
    with pytest.raises(AuthError, match="Ed25519, ECDSA, or RSA"):
        parse_private_key("-----BEGIN NONSENSE-----\nzzz\n-----END NONSENSE-----")


def test_empty_key_is_rejected():
    with pytest.raises(AuthError, match="empty"):
        parse_private_key("   ")


def test_key_material_tolerates_a_missing_trailing_newline():
    """Copy-pasting a key out of a terminal routinely drops the final newline."""
    assert parse_private_key(_rsa_pem().rstrip("\n")).get_name() == "ssh-rsa"


# ---------------------------------------------------------------------------
# Credentials model
# ---------------------------------------------------------------------------


def test_credentials_require_exactly_one_secret():
    with pytest.raises(ValidationError, match="either password or private_key"):
        Credentials(username="u")
    with pytest.raises(ValidationError, match="not both"):
        Credentials(username="u", password="p", private_key="k")
    with pytest.raises(ValidationError, match="passphrase is only meaningful"):
        Credentials(username="u", password="p", passphrase="x")


def test_credentials_never_leak_secrets_in_repr():
    creds = Credentials(username="u", private_key="SECRET-KEY", passphrase="SECRET-PW")
    rendered = f"{creds!r} {creds}"
    assert "SECRET-KEY" not in rendered
    assert "SECRET-PW" not in rendered


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class _FakeSshClient:
    def __init__(self):
        self.connect_kwargs: dict = {}
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

    def exec_command(self, command, timeout=None):
        # One package: an empty inventory is refused (Req 1.7), and these
        # tests are about which credential reaches connect().
        return None, io.BytesIO(b"curl\t7.88.1\n"), io.BytesIO(b"")

    def close(self):
        self.closed = True


_TARGET = TargetMachine(id="m1", hostname="host", platform=Platform.LINUX)


def test_collector_authenticates_with_a_pkey_not_a_password():
    fake = _FakeSshClient()
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    collector.collect(_TARGET, Credentials(username="root", private_key=_rsa_pem()))

    assert "pkey" in fake.connect_kwargs
    assert isinstance(fake.connect_kwargs["pkey"], paramiko.PKey)
    assert "password" not in fake.connect_kwargs
    assert fake.connect_kwargs["look_for_keys"] is False
    assert fake.connect_kwargs["allow_agent"] is False
    assert fake.closed


def test_collector_still_authenticates_with_a_password():
    fake = _FakeSshClient()
    collector = LinuxCollector(ssh_client_factory=lambda: fake)

    collector.collect(_TARGET, Credentials(username="root", password="pw"))

    assert fake.connect_kwargs["password"] == "pw"
    assert "pkey" not in fake.connect_kwargs


def test_a_malformed_key_fails_before_the_network_is_touched():
    """Reported as a key problem, not as a generic authentication rejection."""

    def _factory():
        raise AssertionError("must not connect with an unparseable key")

    collector = LinuxCollector(ssh_client_factory=_factory)

    with pytest.raises(AuthError, match="malformed"):
        collector.collect(_TARGET, Credentials(username="root", private_key="junk"))


def test_key_rejection_message_names_the_method_used():
    class _Rejecting(_FakeSshClient):
        def connect(self, **kwargs):
            raise paramiko.AuthenticationException()

    collector = LinuxCollector(ssh_client_factory=_Rejecting)

    with pytest.raises(AuthError, match="key authentication rejected"):
        collector.collect(_TARGET, Credentials(username="root", private_key=_rsa_pem()))


# ---------------------------------------------------------------------------
# Server-managed key (Phase B)
# ---------------------------------------------------------------------------


def test_supplied_password_wins_over_any_server_default(monkeypatch, tmp_path):
    key_file = tmp_path / "id_rsa"
    key_file.write_text(_rsa_pem(), encoding="utf-8")
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(key_file))

    creds = resolve_credentials(Platform.LINUX, username="u", password="p")

    assert creds.uses_key is False


def test_missing_credentials_fall_back_to_the_server_key(monkeypatch, tmp_path):
    """This is what makes a one-click fleet re-scan possible."""
    key_file = tmp_path / "id_rsa"
    key_file.write_text(_rsa_pem(), encoding="utf-8")
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(key_file))
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_USER", "scanner")

    creds = resolve_credentials(Platform.LINUX)

    assert creds.uses_key is True
    assert creds.username == "scanner"


def test_server_key_is_reread_so_rotation_needs_no_restart(monkeypatch, tmp_path):
    key_file = tmp_path / "id_rsa"
    key_file.write_text(_rsa_pem(), encoding="utf-8")
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(key_file))
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_USER", "scanner")

    first = resolve_credentials(Platform.LINUX).private_key.get_secret_value()
    rotated = _rsa_pem()
    key_file.write_text(rotated, encoding="utf-8")
    second = resolve_credentials(Platform.LINUX).private_key.get_secret_value()

    assert first != second
    assert second == rotated


def test_unreadable_server_key_names_the_path(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "CVEDECK_DEFAULT_SSH_KEY_PATH", str(tmp_path / "does-not-exist")
    )
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_USER", "scanner")

    with pytest.raises(CredentialResolutionError, match="could not read"):
        resolve_credentials(Platform.LINUX)


def test_windows_has_no_server_key_fallback(monkeypatch, tmp_path):
    """WinRM has no SSH-key equivalent, so this must be an error, not an attempt."""
    key_file = tmp_path / "id_rsa"
    key_file.write_text(_rsa_pem(), encoding="utf-8")
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(key_file))

    with pytest.raises(CredentialResolutionError, match="Windows"):
        resolve_credentials(Platform.WINDOWS, username="u")


def test_missing_username_with_no_default_is_an_error(monkeypatch, tmp_path):
    key_file = tmp_path / "id_rsa"
    key_file.write_text(_rsa_pem(), encoding="utf-8")
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(key_file))
    monkeypatch.delenv("CVEDECK_DEFAULT_SSH_USER", raising=False)

    with pytest.raises(CredentialResolutionError, match="DEFAULT_SSH_USER"):
        resolve_credentials(Platform.LINUX)
