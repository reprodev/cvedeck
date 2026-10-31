"""kernel advisories for Fedora, Arch, Oracle Linux and Amazon Linux 2023: kernel_feeds

One compressed row per (feed, kernel stream), refreshed daily with the other
feeds (Req 12.12-12.14): ``upstream`` (the kernel CNA's records, for Fedora
and Arch), ``oracle:ol<N>`` and ``amazon:al2023``. Empty until the first
refresh, which reads as the kernel not checked -- never as a clean one.

Revision ID: e5b8c3a1f907
Revises: d9a4b2e71c58
Create Date: 2026-11-01 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e5b8c3a1f907"
down_revision: Union[str, None] = "d9a4b2e71c58"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "kernel_feeds",
        sa.Column("feed", sa.String(), nullable=False),
        sa.Column("stream", sa.String(), nullable=False),
        sa.Column("entries", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("feed", "stream"),
    )


def downgrade() -> None:
    op.drop_table("kernel_feeds")
