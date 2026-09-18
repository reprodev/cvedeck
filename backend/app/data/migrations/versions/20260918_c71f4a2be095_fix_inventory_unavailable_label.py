"""fix the inventory_unavailable enum label on PostgreSQL

``20260917_e4f1b8c05d31`` added the ScanStatus value as the lower-case
``'inventory_unavailable'``. SQLAlchemy's Enum persists member *names*, so the
value actually written is ``'INVENTORY_UNAVAILABLE'`` -- which the type still
does not contain. On PostgreSQL, recording a host whose package inventory could
not be read therefore fails with an invalid-input-value error; the status
reaches the database only on SQLite, where these columns are plain VARCHARs
with no type to violate.

That migration is already applied on any deployment that has it, so it cannot
be edited. This adds the label it meant to add. The mistaken lower-case label
stays behind: PostgreSQL cannot drop a value from an enum type, and an unused
label is inert.

Found while adding the UNSCORED Severity label, which is the same shape of
change and would have repeated the same mistake.

Revision ID: c71f4a2be095
Revises: a5c60d81e7b3
Create Date: 2026-09-18 10:05:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c71f4a2be095"
down_revision: Union[str, None] = "a5c60d81e7b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute(
                sa.text(
                    "ALTER TYPE scan_status ADD VALUE IF NOT EXISTS "
                    "'INVENTORY_UNAVAILABLE'"
                )
            )


def downgrade() -> None:
    # PostgreSQL cannot drop a value from an enum type. Rows carrying it would
    # have nothing to become, and an older build simply never writes it.
    pass
