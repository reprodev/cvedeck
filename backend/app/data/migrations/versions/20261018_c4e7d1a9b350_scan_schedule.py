"""scheduled scans: scan_schedule, and which hosts the server key reached

Adds the one-row ``scan_schedule`` table (Req 20), ``target_machines.
last_scan_server_key`` -- whether a host's last successful scan used the
server-managed key, which decides whether it is scanned on schedule -- and
``scan_job_targets.server_key``, the per-host fact that sets it.

``last_scan_server_key`` starts NULL for every existing host: not known until
its next successful scan, and not scheduled until then.

Revision ID: c4e7d1a9b350
Revises: b81f3c6d2a94
Create Date: 2026-10-18 18:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c4e7d1a9b350"
down_revision: Union[str, None] = "b81f3c6d2a94"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_schedule",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("time_of_day", sa.String(), nullable=False),
        sa.Column("armed_at", sa.DateTime(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_job_id", sa.String(), nullable=True),
        sa.Column("last_note", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("target_machines", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_scan_server_key", sa.Boolean(), nullable=True))
    with op.batch_alter_table("scan_job_targets", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("server_key", sa.Boolean(), server_default=sa.false(), nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_job_targets", schema=None) as batch_op:
        batch_op.drop_column("server_key")
    with op.batch_alter_table("target_machines", schema=None) as batch_op:
        batch_op.drop_column("last_scan_server_key")
    op.drop_table("scan_schedule")
