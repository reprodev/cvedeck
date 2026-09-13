"""Core domain models shared across the CveDeck layers.

These are the in-memory domain structures produced by collectors and consumed
by the matcher, scanner engine, and persistence layer. They are deliberately
separate from the SQLAlchemy ORM tables (defined in the persistence layer):
collectors normalize raw target output into these structures, and the
persistence layer maps them to/from stored rows.

`Credentials` carries the secret used to authenticate to a Target_Machine --
either a password or an SSH private key -- and is modeled so no secret value
leaks through ``repr``/``str`` or JSON serialization.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from .enums import Platform


class OsInfo(BaseModel):
    """Operating-system details collected from a Target_Machine.

    Matched against NVD to identify OS-level CVEs.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str


class Package(BaseModel):
    """A single installed software package collected from a Target_Machine.

    Matched against OSV_Source for package-level advisories. ``ecosystem``
    (e.g. PyPI, npm, deb) is optional and, when present, refines OSV matching.
    ``dependencies`` records the package names required by this package.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    ecosystem: str | None = None
    dependencies: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    """Normalized inventory collected from a single Target_Machine.

    Combines OS details and the installed-package list. This is the unit the
    Matcher consumes and the persistence layer stores (Req 1.6, 5.1).
    """

    machine_id: str
    os_info: OsInfo
    packages: list[Package] = Field(default_factory=list)
    #: Running kernel release (``uname -r``), when the host reported one. A
    #: host can be fully patched and still running the vulnerable kernel it
    #: booted from, which a package-list-only scan reports as clean.
    kernel_version: str | None = None
    #: Whether the host has a pending reboot. ``None`` when undeterminable
    #: (the distribution offers no read-only way to ask).
    reboot_required: bool | None = None
    collected_at: datetime | None = None


class TargetMachine(BaseModel):
    """A Windows or Linux host that the system scans remotely.

    Identifies a target for the scanner engine and collector selection.
    """

    id: str
    hostname: str
    platform: Platform


class Credentials(BaseModel):
    """Authentication material for connecting to a Target_Machine.

    Supports either a password or an SSH private key (Ed25519/ECDSA/RSA, PEM or
    OpenSSH format), with an optional ``passphrase`` for an encrypted key
    (Req 9.1, 11.1). Exactly one of ``password`` / ``private_key`` must be
    supplied (Req 11.5): accepting both would leave which one is actually used
    to paramiko's argument precedence rather than to an explicit decision
    here.

    Every secret is a ``SecretStr`` so it is not exposed through logging,
    ``repr``, or default serialization (Req 9.2). Use ``get_secret_value()``
    to read the plaintext at the point of authentication and nowhere else.
    """

    model_config = ConfigDict(frozen=True)

    username: str
    password: SecretStr | None = None
    private_key: SecretStr | None = None
    passphrase: SecretStr | None = None

    @model_validator(mode="after")
    def _exactly_one_secret(self) -> "Credentials":
        """Require exactly one authentication method."""
        has_password = self.password is not None and bool(
            self.password.get_secret_value()
        )
        has_key = self.private_key is not None and bool(
            self.private_key.get_secret_value()
        )
        if has_password and has_key:
            raise ValueError(
                "supply either password or private_key, not both"
            )
        if not has_password and not has_key:
            raise ValueError("either password or private_key is required")
        if self.passphrase is not None and not has_key:
            raise ValueError("passphrase is only meaningful with private_key")
        return self

    @property
    def uses_key(self) -> bool:
        """Whether this credential authenticates with a private key."""
        return self.private_key is not None and bool(
            self.private_key.get_secret_value()
        )
