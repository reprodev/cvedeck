"""package source: the name advisories are published under

Adds ``packages.source_name`` and ``packages.source_version``. Distribution
advisories are keyed by source package -- Debian's ``glibc``, not the ``libc6``
binary that is actually installed -- so matching needs both (Req 1.12).

Nullable, and null for every existing row: an inventory collected before this
release is matched as it always was, by binary name, until the host is scanned
again.

Revision ID: e6a1c0b7d2f4
Revises: d8b31c6fa042
Create Date: 2026-09-25 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e6a1c0b7d2f4"
down_revision: Union[str, None] = "d8b31c6fa042"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("packages", sa.Column("source_name", sa.String(), nullable=True))
    op.add_column("packages", sa.Column("source_version", sa.String(), nullable=True))


def downgrade() -> None:
    # Batched, like every other column drop here: see d8b31c6fa042.
    with op.batch_alter_table("packages", schema=None) as batch_op:
        batch_op.drop_column("source_version")
        batch_op.drop_column("source_name")
