"""scan trust signals: source health + never-scanned status

Adds ``target_machines.last_scan_sources_ok`` so a partial scan (one that ran
against an unreachable advisory source) is distinguishable from a clean one,
and backfills the new ``NEVER_SCANNED`` status onto rows that were enrolled but
never actually scanned.

Before this, enrollment stamped ``CONNECTION_FAILURE`` on a brand-new row, so
every host added from network discovery rendered as a red failure in the fleet
view before anything had tried to reach it. The distinguishing signal is
``last_scanned_at IS NULL`` -- a row that has never recorded a scan timestamp
never had a connection attempted, so its failure status was provisional, not
observed. Rows that genuinely failed to connect have a timestamp and are left
alone.

Note that SQLAlchemy's ``Enum`` type persists member *names*, not values, so
this migration compares against ``'CONNECTION_FAILURE'`` rather than
``'connection_failure'``.

Revision ID: 630af2701d55
Revises: b4c20174d4db
Create Date: 2026-09-01 19:35:31.735263
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "630af2701d55"
down_revision: Union[str, None] = "b4c20174d4db"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("target_machines", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "last_scan_sources_ok",
                sa.Boolean(),
                server_default=sa.text("1"),
                nullable=False,
            )
        )

    # Rows enrolled but never scanned carry a provisional CONNECTION_FAILURE.
    op.execute(
        sa.text(
            "UPDATE target_machines "
            "SET last_scan_status = 'NEVER_SCANNED' "
            "WHERE last_scan_status = 'CONNECTION_FAILURE' "
            "AND last_scanned_at IS NULL"
        )
    )


def downgrade() -> None:
    # Fold the new status back into the value it previously shared, so an older
    # build reading this database still sees a member of its own enum.
    op.execute(
        sa.text(
            "UPDATE target_machines "
            "SET last_scan_status = 'CONNECTION_FAILURE' "
            "WHERE last_scan_status = 'NEVER_SCANNED'"
        )
    )

    with op.batch_alter_table("target_machines", schema=None) as batch_op:
        batch_op.drop_column("last_scan_sources_ok")
