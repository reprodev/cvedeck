"""cancelling scan jobs: a CANCELLED job status and host state

Adds ``CANCELLED`` to ``scan_job_status`` and ``scan_job_target_state``
(Req 19.7, 19.8). Who cancelled, and when, go in the job's existing
``error_detail`` and ``finished_at``, so no column is added.

On PostgreSQL each type gains a label. On SQLite there is nothing to do:
``schema.py`` builds its enum columns with SQLAlchemy's default
``create_constraint=False``, so they are plain VARCHARs with no CHECK to widen.

Revision ID: d9a4b2e71c58
Revises: c4e7d1a9b350
Create Date: 2026-10-24 10:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d9a4b2e71c58"
down_revision: Union[str, None] = "c4e7d1a9b350"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TYPES = ("scan_job_status", "scan_job_target_state")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # ALTER TYPE ... ADD VALUE cannot run inside the transaction that would
    # then use it, so it runs on its own. Upper case, because SQLAlchemy's Enum
    # persists member names, not values.
    with op.get_context().autocommit_block():
        for name in _TYPES:
            op.execute(sa.text(f"ALTER TYPE {name} ADD VALUE IF NOT EXISTS 'CANCELLED'"))


def downgrade() -> None:
    # PostgreSQL cannot drop a label from an enum type, and a cancelled job
    # written before the downgrade would still need it. Nothing to undo.
    pass
