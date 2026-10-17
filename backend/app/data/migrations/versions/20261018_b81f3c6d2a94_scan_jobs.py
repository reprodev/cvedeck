"""background scan jobs: scan_jobs and scan_job_targets

Adds the two tables behind background scanning (Req 19): a job per scan
request, and a row per host carrying its progress and then its outcome. They
hold no credentials, which live only in the process, and are never synced.

On PostgreSQL the target table reuses the existing ``platform`` and
``scan_status`` types; the two new types are created here and dropped on
downgrade. Labels are the enum member *names*, which is what SQLAlchemy
persists -- the lower-case-value mistake that ``c71f4a2be095`` had to repair.

Revision ID: b81f3c6d2a94
Revises: a7c2e9d4b1f6
Create Date: 2026-10-18 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "b81f3c6d2a94"
down_revision: Union[str, None] = "a7c2e9d4b1f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_enum(name: str, *labels: str) -> sa.types.TypeEngine:
    """An enum column type that does not try to create its type on PostgreSQL."""
    return sa.Enum(*labels, name=name).with_variant(
        postgresql.ENUM(*labels, name=name, create_type=False), "postgresql"
    )


_PLATFORM = ("LINUX", "WINDOWS")
_SCAN_STATUS = (
    "NEVER_SCANNED",
    "SUCCESS",
    "CONNECTION_FAILURE",
    "AUTH_FAILURE",
    "INVENTORY_UNAVAILABLE",
    "HOST_KEY_MISMATCH",
    "HOST_KEY_UNKNOWN",
)


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("QUEUED", "RUNNING", "FINISHED", "INTERRUPTED", name="scan_job_status"),
            nullable=False,
        ),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("error_detail", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])

    op.create_table(
        "scan_job_targets",
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("machine_id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("platform", _existing_enum("platform", *_PLATFORM), nullable=False),
        sa.Column(
            "state",
            sa.Enum("QUEUED", "RUNNING", "DONE", name="scan_job_target_state"),
            nullable=False,
        ),
        sa.Column("status", _existing_enum("scan_status", *_SCAN_STATUS), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=True),
        sa.Column("sources_ok", sa.Boolean(), nullable=True),
        sa.Column("unavailable_sources", sa.String(), nullable=True),
        sa.Column("message", sa.String(), nullable=True),
        sa.Column("new_count", sa.Integer(), nullable=True),
        sa.Column("resolved_count", sa.Integer(), nullable=True),
        sa.Column("baseline", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("job_id", "position"),
    )


def downgrade() -> None:
    op.drop_table("scan_job_targets")
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP TYPE IF EXISTS scan_job_target_state"))
        op.execute(sa.text("DROP TYPE IF EXISTS scan_job_status"))
