"""inventory_unavailable: a host that answered but could not be inventoried

Widens ``scan_status`` with ``INVENTORY_UNAVAILABLE`` (Req 1.7). Before this
revision a host whose package managers all failed -- an unsupported
distribution, a locked package database, a restricted shell -- produced an
empty inventory, which the scan recorded as a success with nothing found. That
deleted every finding from the previous scan and reported them resolved.

On SQLite the column is a plain string with no CHECK constraint, so there is
nothing to alter. On PostgreSQL it is a native enum type, so the value is added
there; ``ADD VALUE IF NOT EXISTS`` makes it safe to repeat.

No data migration: a status nothing has written yet cannot be present in an
existing database, and the next scan of an affected host records it.

Revision ID: e4f1b8c05d31
Revises: d7e2a9c41f08
Create Date: 2026-09-17 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e4f1b8c05d31"
down_revision: Union[str, None] = "d7e2a9c41f08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # ALTER TYPE ... ADD VALUE cannot run inside the transaction that would
        # then use it, so it runs on its own.
        with op.get_context().autocommit_block():
            op.execute(
                sa.text(
                    "ALTER TYPE scan_status ADD VALUE IF NOT EXISTS "
                    "'inventory_unavailable'"
                )
            )


def downgrade() -> None:
    # PostgreSQL cannot drop a value from an enum type, and the rows carrying it
    # would have nothing to become. Leaving the value in place is harmless: it
    # is simply never written by an older build.
    pass
