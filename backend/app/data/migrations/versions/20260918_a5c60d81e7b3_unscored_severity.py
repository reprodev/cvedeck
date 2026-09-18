"""unscored severity: a score we do not have

Adds the ``UNSCORED`` Severity_Level and makes ``cvss_score`` nullable on both
``cve_findings`` and ``scan_finding_changes`` (Req 2.6, 2.7).

A Severity_Level and a CVSS_Score become independent facts. An advisory that
publishes a qualitative severity and no vector keeps its band and records no
score; one that publishes neither is ``UNSCORED``. Both used to be stored as a
CVSS_Score of 5.0, which read back as ``MEDIUM``.

Rows already holding that fabricated 5.0 are deliberately left alone. They are
indistinguishable from a finding OSV genuinely scored 5.0 -- that is the defect
-- so there is nothing to select on, and rewriting every 5.0 would corrupt the
measured ones to fix the invented ones. They correct themselves the next time
their host is scanned.

On PostgreSQL the Severity type gains a label. On SQLite there is nothing to do
for the enum: ``schema.py`` builds its columns with SQLAlchemy's default
``create_constraint=False``, so they are plain VARCHARs with no CHECK to widen.
Dropping NOT NULL, however, does need ``batch_alter_table`` there, since SQLite
cannot alter a column in place.

Revision ID: a5c60d81e7b3
Revises: f2a7c93be105
Create Date: 2026-09-18 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a5c60d81e7b3"
down_revision: Union[str, None] = "f2a7c93be105"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCORED_TABLES = ("cve_findings", "scan_finding_changes")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # ALTER TYPE ... ADD VALUE cannot run inside the transaction that would
        # then use it, so it runs on its own.
        #
        # The label is upper case because SQLAlchemy's Enum persists member
        # *names*, not values: the baseline created this type as
        # Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'). A lower-case label would
        # add a value nothing ever writes, and every UNSCORED insert would
        # still fail.
        with op.get_context().autocommit_block():
            op.execute(
                sa.text(
                    "ALTER TYPE severity ADD VALUE IF NOT EXISTS 'UNSCORED'"
                )
            )

    for table in _SCORED_TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(
                "cvss_score", existing_type=sa.Float(), nullable=True
            )


def downgrade() -> None:
    # The old schema cannot express "no score", and the old code would read a
    # substituted one. Deleting the scoreless rows is recoverable -- rescanning
    # the host restores them -- whereas backfilling them with a number would
    # reintroduce exactly the defect this migration removes, and would be
    # indistinguishable from measured data afterwards.
    for table in _SCORED_TABLES:
        op.execute(sa.text(f"DELETE FROM {table} WHERE cvss_score IS NULL"))

    for table in _SCORED_TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(
                "cvss_score", existing_type=sa.Float(), nullable=False
            )

    # PostgreSQL cannot drop a value from an enum type, and there are no rows
    # left carrying it. Leaving the label in place is harmless: an older build
    # simply never writes it.
