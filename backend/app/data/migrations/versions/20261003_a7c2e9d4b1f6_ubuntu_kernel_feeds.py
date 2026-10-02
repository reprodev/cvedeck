"""Ubuntu kernel advisories from Canonical's OVAL feed: ubuntu_kernel_feeds

One compressed row per (Ubuntu release, kernel flavour), refreshed daily with
the other feeds (Req 12.11). Empty until the first refresh, which reads as the
kernel not checked -- never as a clean one.

Revision ID: a7c2e9d4b1f6
Revises: f3d9a1c5e7b2
Create Date: 2026-10-03 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a7c2e9d4b1f6"
down_revision: Union[str, None] = "f3d9a1c5e7b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ubuntu_kernel_feeds",
        sa.Column("codename", sa.String(), nullable=False),
        sa.Column("flavour", sa.String(), nullable=False),
        sa.Column("entries", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("codename", "flavour"),
    )


def downgrade() -> None:
    op.drop_table("ubuntu_kernel_feeds")
