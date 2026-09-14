"""access control: accounts, sessions, API tokens and the setup code

Adds built-in login (Req 16). Before this revision every endpoint was open to
anyone who could reach the port, and the only advice was to put a proxy in
front.

Four tables, none of them synchronized to the Online_Database:

- ``users``         -- accounts, with a scrypt password hash.
- ``auth_sessions`` -- browser sessions, keyed by the SHA-256 of the cookie.
- ``api_tokens``    -- named bearer tokens for scripts, stored as hashes.
- ``auth_setup``    -- the hash of the outstanding first-run setup code.

An existing database upgrades with no account, so the next start logs a setup
code and the dashboard asks for it. Nothing already stored is touched.

Revision ID: c3d9e1f27a60
Revises: a1c7f3e9d204
Create Date: 2026-09-14 09:30:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c3d9e1f27a60"
down_revision: Union[str, None] = "a1c7f3e9d204"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        "ix_auth_sessions_user_id", "auth_sessions", ["user_id"], unique=False
    )

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("prefix", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )

    op.create_table(
        "auth_setup",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("auth_setup")
    op.drop_table("api_tokens")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_table("users")
