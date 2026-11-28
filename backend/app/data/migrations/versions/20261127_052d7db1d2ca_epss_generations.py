"""epss generations: the EPSS cache is rewritten in parts behind a swap

Adds ``epss_scores.generation`` and makes the key ``(generation, cve_id)``, and
adds ``feed_generations``, which says which generation readers see (Req 13.12,
Property 26). A refresh writes its whole set under a new generation, committing
in parts so the 400,000-row rewrite no longer holds the write lock for its
whole length, and one small commit then makes that generation live.

Every stored score is kept, as generation 0. No ``feed_generations`` row is
written: a feed with no row reads generation 0, so the upgraded cache stays in
use exactly as it was, and the first refresh after the upgrade claims
generation 1.

The key cannot be altered in place on SQLite, so the table is rebuilt: create
the new shape, copy the rows across, drop the old table, rename. The same steps
work on PostgreSQL.

Revision ID: 052d7db1d2ca
Revises: a7d3e9b1c428
Create Date: 2026-11-27 12:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "052d7db1d2ca"
down_revision: Union[str, None] = "a7d3e9b1c428"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = "cve_id, score, percentile, scored_at"


def upgrade() -> None:
    op.create_table(
        "epss_scores_next",
        sa.Column("generation", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("scored_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("generation", "cve_id"),
    )
    op.execute(
        f"INSERT INTO epss_scores_next (generation, {_COLUMNS}) "
        f"SELECT 0, {_COLUMNS} FROM epss_scores"
    )
    op.drop_table("epss_scores")
    op.rename_table("epss_scores_next", "epss_scores")
    op.create_table(
        "feed_generations",
        sa.Column("feed_name", sa.String(), nullable=False),
        sa.Column("live", sa.Integer(), nullable=False),
        sa.Column("claimed", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("feed_name"),
    )


def downgrade() -> None:
    """Keep the live generation's scores, as the single set 0.18 expects."""
    op.create_table(
        "epss_scores_prev",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("scored_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.execute(
        f"INSERT INTO epss_scores_prev ({_COLUMNS}) SELECT {_COLUMNS} FROM epss_scores "
        "WHERE generation = COALESCE((SELECT live FROM feed_generations "
        "WHERE feed_name = 'epss'), 0)"
    )
    op.drop_table("feed_generations")
    op.drop_table("epss_scores")
    op.rename_table("epss_scores_prev", "epss_scores")
