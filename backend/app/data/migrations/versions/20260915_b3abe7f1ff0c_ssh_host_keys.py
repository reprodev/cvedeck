"""ssh host keys: pinned keys and the two host-key scan statuses

Adds ``ssh_host_keys`` (Req 17). Before this revision both SSH paths accepted
whatever key a host presented and remembered nothing, so every connection was
a first use and a machine in the middle was indistinguishable from the host.

Also widens ``scan_status`` with ``HOST_KEY_MISMATCH`` and
``HOST_KEY_UNKNOWN``. On SQLite the column is a plain string with no CHECK
constraint, so there is nothing to alter. On PostgreSQL it is a native enum
type, which the ``NEVER_SCANNED`` revision never widened either, so that value
is added here too. ``ADD VALUE IF NOT EXISTS`` makes each one safe to repeat.

An existing database upgrades with no pins, so the first scan of each host
after upgrading pins the key it presents.

Revision ID: b3abe7f1ff0c
Revises: c3d9e1f27a60
Create Date: 2026-09-15 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b3abe7f1ff0c"
down_revision: Union[str, None] = "c3d9e1f27a60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# SQLAlchemy's Enum persists member names, not values.
_NEW_SCAN_STATUSES = ("NEVER_SCANNED", "HOST_KEY_MISMATCH", "HOST_KEY_UNKNOWN")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # ALTER TYPE ... ADD VALUE cannot be used inside the transaction that
        # added it, so it runs on its own.
        with op.get_context().autocommit_block():
            for name in _NEW_SCAN_STATUSES:
                op.execute(
                    sa.text(f"ALTER TYPE scan_status ADD VALUE IF NOT EXISTS '{name}'")
                )

    op.create_table(
        "ssh_host_keys",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("key_type", sa.String(), nullable=False),
        sa.Column("key_base64", sa.String(), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname", "port"),
    )


def downgrade() -> None:
    op.drop_table("ssh_host_keys")

    # An older build has no member for the host-key refusals. They were
    # connections that did not complete, which is what that build called them.
    # (PostgreSQL cannot drop enum values; the unused labels stay behind.)
    op.execute(
        sa.text(
            "UPDATE target_machines "
            "SET last_scan_status = 'CONNECTION_FAILURE' "
            "WHERE last_scan_status IN ('HOST_KEY_MISMATCH', 'HOST_KEY_UNKNOWN')"
        )
    )
