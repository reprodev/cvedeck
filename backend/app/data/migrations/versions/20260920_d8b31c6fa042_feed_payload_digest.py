"""feed payload digest: skip a refresh that carries no news

Adds ``feed_refreshes.payload_digest``. Every refresh used to DELETE and
re-INSERT the whole catalogue -- roughly 270k rows for EPSS -- and then reapply
it to every stored finding, whether or not a single record had changed. Both
feeds publish daily; most days nothing a deployment stores actually moves.

Nullable, and null for every existing row: nothing has been digested yet, so the
first refresh after upgrading does the full rewrite and records the digest, and
later identical ones short-circuit.

Revision ID: d8b31c6fa042
Revises: c71f4a2be095
Create Date: 2026-09-20 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d8b31c6fa042"
down_revision: Union[str, None] = "c71f4a2be095"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "feed_refreshes", sa.Column("payload_digest", sa.String(), nullable=True)
    )


def downgrade() -> None:
    # Batched, like every other column drop here: SQLite gained a native
    # ALTER TABLE ... DROP COLUMN only in 3.35, and the bundled SQLite in a
    # supported Python is not something this project pins. Batch mode rebuilds
    # the table instead, which works everywhere.
    with op.batch_alter_table("feed_refreshes", schema=None) as batch_op:
        batch_op.drop_column("payload_digest")
