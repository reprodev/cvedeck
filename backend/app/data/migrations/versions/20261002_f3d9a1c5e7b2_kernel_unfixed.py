"""kernel CVEs counted, not listed: inventories.kernel_unfixed

A kernel CVE becomes a finding row only when the host's own release has a fix
for it, or it is known exploited. The rest -- an up-to-date Debian 12 kernel has
over two thousand, none with a published severity and none fixable in Debian
12 -- are counted per installed kernel, and the counts are stored with the
inventory they were matched against, so the machine page can say how many there
are and where their fixes live (Req 12.9).

A JSON object as text. Null for every existing row, and for a scan whose kernel
was not looked up: not assessed, which is not zero.

Revision ID: f3d9a1c5e7b2
Revises: e6a1c0b7d2f4
Create Date: 2026-10-02 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f3d9a1c5e7b2"
down_revision: Union[str, None] = "e6a1c0b7d2f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("inventories", sa.Column("kernel_unfixed", sa.String(), nullable=True))


def downgrade() -> None:
    # Batched, like every other column drop here: see d8b31c6fa042.
    with op.batch_alter_table("inventories", schema=None) as batch_op:
        batch_op.drop_column("kernel_unfixed")
