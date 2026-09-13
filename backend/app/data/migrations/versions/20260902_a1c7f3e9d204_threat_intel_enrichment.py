"""threat intel enrichment: KEV + EPSS caches and per-finding enrichment

Adds the first locally cached, periodically refreshed datasets in the system.
Unlike OSV -- which is queried live, per scan -- CISA's KEV catalogue and
FIRST's EPSS score set are small complete files published daily, so they are
downloaded whole and joined locally.

Three tables:

- ``kev_entries``  -- the KEV catalogue, keyed by CVE.
- ``epss_scores``  -- EPSS score and percentile, keyed by CVE.
- ``feed_refreshes`` -- when each feed last refreshed and whether it worked.

``feed_refreshes`` is the one that matters for correctness. A KEV cache that
has silently failed to refresh for a month reports the same "not exploited" for
every finding as a healthy one does, which is the same false-negative failure
mode ``last_scan_sources_ok`` was added to prevent on target machines. Recording
the refresh outcome is what lets the dashboard distinguish "not exploited" from
"we do not currently know".

Four nullable columns are added to ``cve_findings``. They are nullable rather
than defaulted for the same reason: NULL means unenriched, and only an explicit
``kev_listed = 0`` means genuinely absent from the catalogue. Existing rows are
therefore left NULL rather than backfilled to false -- they were written before
enrichment existed and nothing has checked them.

Revision ID: a1c7f3e9d204
Revises: e451e20b58e2
Create Date: 2026-09-02 10:12:44.128907
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a1c7f3e9d204"
down_revision: Union[str, None] = "e451e20b58e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# SQLAlchemy's Enum type persists member *names*, so the constraint values here
# are the uppercase names, matching how scan_status/severity are already stored.
_FEED_STATUS = sa.Enum(
    "NEVER_REFRESHED", "OK", "FAILED", name="feed_status"
)


def upgrade() -> None:
    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("vendor_project", sa.String(), nullable=True),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("vulnerability_name", sa.String(), nullable=True),
        sa.Column("date_added", sa.String(), nullable=True),
        sa.Column("due_date", sa.String(), nullable=True),
        sa.Column(
            "known_ransomware_use",
            sa.Boolean(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("notes", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("scored_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "feed_refreshes",
        sa.Column("feed_name", sa.String(), nullable=False),
        sa.Column("last_refreshed_at", sa.DateTime(), nullable=True),
        sa.Column("last_attempted_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", _FEED_STATUS, nullable=False),
        sa.Column(
            "record_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("error_detail", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("feed_name"),
    )

    # Findings are looked up by CVE id during enrichment, which is a full-table
    # join against two feeds; without this the enrichment pass degrades to a
    # scan per finding on a fleet with tens of thousands of rows.
    op.create_index(
        "ix_cve_findings_cve_id", "cve_findings", ["cve_id"], unique=False
    )

    with op.batch_alter_table("cve_findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("kev_listed", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("kev_due_date", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("epss_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("epss_percentile", sa.Float(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cve_findings", schema=None) as batch_op:
        batch_op.drop_column("epss_percentile")
        batch_op.drop_column("epss_score")
        batch_op.drop_column("kev_due_date")
        batch_op.drop_column("kev_listed")

    op.drop_index("ix_cve_findings_cve_id", table_name="cve_findings")

    op.drop_table("feed_refreshes")
    op.drop_table("epss_scores")
    op.drop_table("kev_entries")

    # PostgreSQL keeps the enum type behind after the table is gone; SQLite has
    # no such type to drop, hence the dialect guard.
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        _FEED_STATUS.drop(bind, checkfirst=True)
