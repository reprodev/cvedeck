"""scan run error detail: why a failed scan failed

Adds ``scan_runs.error_detail`` (Req 18.10). The history recorded every attempt,
including failures, but a failed row said only "Failed" -- which does not
distinguish a bad password from an unreachable port, a refused host key, or a
host whose package database could not be read.

Nullable, and null for every existing row: the runs already recorded did not
keep their message, and inventing one would be worse than the gap.

Revision ID: f2a7c93be105
Revises: e4f1b8c05d31
Create Date: 2026-09-17 11:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f2a7c93be105"
down_revision: Union[str, None] = "e4f1b8c05d31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("error_detail", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "error_detail")
