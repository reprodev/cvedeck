"""notifications: notification_settings, and each scheduled job's alert outcome

Adds the one-row ``notification_settings`` table (Req 21) -- only what the
dashboard may decide: on or off, the threshold, whether unchecked hosts are
reported, and the last result. Where alerts go, and how much they say, live in
the environment and are never stored (Req 21.10).

Adds ``scan_jobs.notification_status`` and ``notification_error`` (Req 21.8).
Both start NULL for every existing job, which is the truth: no job before this
revision sent an alert.

Statuses and thresholds are plain strings, not database enums, so a value added
later needs no PostgreSQL enum migration.

Revision ID: f2c8a5d0b613
Revises: e5b8c3a1f907
Create Date: 2026-11-06 12:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f2c8a5d0b613"
down_revision: Union[str, None] = "e5b8c3a1f907"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("threshold", sa.String(), nullable=False),
        sa.Column(
            "include_not_checked", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
        sa.Column("last_sent_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", sa.String(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("last_job_id", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("notification_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("notification_error", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.drop_column("notification_error")
        batch_op.drop_column("notification_status")
    op.drop_table("notification_settings")
