"""scan history: a run per scan attempt, its changes, and first-seen dates

Adds ``scan_runs`` and ``scan_finding_changes`` (Req 18), and
``cve_findings.first_seen_at``. Before this revision each scan deleted a
machine's findings and wrote them again, so nothing could say what was new
since the last scan, what a patch had cleared, or how long a finding had been
open.

``first_seen_at`` is backfilled from the machine's ``last_scanned_at``, the
earliest time the finding is known to have existed, or the upgrade time when
the machine has no timestamp. No runs are backfilled, so each machine's first
scan after upgrading is a baseline and reports nothing new or resolved.

On PostgreSQL the new tables reuse the existing ``scan_status``, ``severity``
and ``sync_status`` types rather than creating them again.

Revision ID: d7e2a9c41f08
Revises: b3abe7f1ff0c
Create Date: 2026-09-15 14:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "d7e2a9c41f08"
down_revision: Union[str, None] = "b3abe7f1ff0c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_enum(name: str, *labels: str) -> sa.types.TypeEngine:
    """An enum column type that does not try to create its type on PostgreSQL."""
    return sa.Enum(*labels, name=name).with_variant(
        postgresql.ENUM(*labels, name=name, create_type=False), "postgresql"
    )


_SCAN_STATUS = (
    "NEVER_SCANNED",
    "SUCCESS",
    "CONNECTION_FAILURE",
    "AUTH_FAILURE",
    "HOST_KEY_MISMATCH",
    "HOST_KEY_UNKNOWN",
)
_SEVERITY = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SYNC_STATUS = ("SYNCED", "PENDING_SYNC")


def upgrade() -> None:
    with op.batch_alter_table("cve_findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("first_seen_at", sa.DateTime(), nullable=True))

    op.execute(
        sa.text(
            "UPDATE cve_findings SET first_seen_at = COALESCE("
            "(SELECT last_scanned_at FROM target_machines "
            "WHERE target_machines.id = cve_findings.machine_id), "
            "CURRENT_TIMESTAMP)"
        )
    )

    with op.batch_alter_table("cve_findings", schema=None) as batch_op:
        batch_op.alter_column(
            "first_seen_at", existing_type=sa.DateTime(), nullable=False
        )

    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("machine_id", sa.String(), nullable=False),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.Column("status", _existing_enum("scan_status", *_SCAN_STATUS), nullable=False),
        sa.Column("sources_ok", sa.Boolean(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("new_count", sa.Integer(), nullable=True),
        sa.Column("resolved_count", sa.Integer(), nullable=True),
        sa.Column("baseline", sa.Boolean(), nullable=False),
        sa.Column("sync_status", _existing_enum("sync_status", *_SYNC_STATUS), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_id"], ["target_machines.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_runs_machine_id", "scan_runs", ["machine_id"], unique=False)

    op.create_table(
        "scan_finding_changes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("scan_run_id", sa.String(), nullable=False),
        sa.Column(
            "change", sa.Enum("NEW", "RESOLVED", name="finding_change"), nullable=False
        ),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("package_identifier", sa.String(), nullable=True),
        sa.Column("severity", _existing_enum("severity", *_SEVERITY), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("kev_listed", sa.Boolean(), nullable=True),
        sa.Column("sync_status", _existing_enum("sync_status", *_SYNC_STATUS), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scan_finding_changes_scan_run_id",
        "scan_finding_changes",
        ["scan_run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scan_finding_changes_scan_run_id", table_name="scan_finding_changes")
    op.drop_table("scan_finding_changes")
    op.drop_index("ix_scan_runs_machine_id", table_name="scan_runs")
    op.drop_table("scan_runs")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP TYPE IF EXISTS finding_change"))
    with op.batch_alter_table("cve_findings", schema=None) as batch_op:
        batch_op.drop_column("first_seen_at")
