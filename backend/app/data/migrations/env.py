"""Alembic environment for the CveDeck.

The database URL is resolved through :mod:`app.config` rather than alembic.ini
so migrations target exactly the database the application uses, honouring
``CVEDECK_DB_URL`` and ``CVEDECK_DATA_DIR``. This keeps the invariant
that ``app/config.py`` is the only module reading the environment.

``render_as_batch`` is enabled because the default deployment is SQLite, which
cannot ``ALTER COLUMN``; batch mode rewrites the table instead. It is harmless
on PostgreSQL.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app import config as app_config
from app.data.schema import Base

from pathlib import Path

config = context.config

if config.config_file_name is not None and Path(config.config_file_name).is_file():
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", app_config.database_url())

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade --sql``)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    connectable = config.attributes.get("connection", None)

    if connectable is None:
        connectable = engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        with connectable.connect() as connection:
            _run(connection)
    else:
        _run(connectable)


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
