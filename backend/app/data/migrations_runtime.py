"""Bring a database schema up to date at application startup.

Before this module existed, ``Base.metadata.create_all`` was the entire
migration story: fine for a fresh database, and no answer at all for an
existing one. Adding a column meant every deployed instance broke on upgrade.

The bootstrap distinguishes three cases:

- **Empty database** -- create every table from the ORM metadata (fast, and
  identical to the previous behaviour), then stamp ``head`` so later upgrades
  know the schema is current.
- **Existing database with no ``alembic_version`` table** -- a pre-Alembic
  deployment. Stamp the baseline revision (which describes exactly the schema
  those deployments already have), then run the remaining migrations.
- **Existing database already under Alembic** -- upgrade to ``head``.

Tests and in-memory databases take the first path, so the suite never runs a
migration and stays fast.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect

from .schema import Base

_LOGGER = logging.getLogger(__name__)

# The revision describing the schema as it stood before Alembic was introduced.
# A pre-Alembic database is stamped with this and then migrated forward.
BASELINE_REVISION = "b4c20174d4db"

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


def alembic_config(engine: Engine | None = None) -> Config:
    """Build an Alembic ``Config`` pointing at this project's migrations."""
    ini_path = _BACKEND_ROOT / "alembic.ini"
    cfg = Config(str(ini_path) if ini_path.is_file() else None)
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "app" / "data" / "migrations"))
    if engine is not None:
        cfg.attributes["connection"] = engine
    return cfg


def _current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def upgrade_to_head(engine: Engine) -> None:
    """Ensure ``engine``'s schema matches the ORM metadata.

    Safe to call on every startup and idempotent. Never drops or rewrites data.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    known_tables = set(Base.metadata.tables)

    if not (tables & known_tables):
        # Fresh database: create everything, then record it as current.
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            cfg = alembic_config()
            cfg.attributes["connection"] = connection
            command.stamp(cfg, "head")
        _LOGGER.info("initialized a fresh database at the current schema")
        return

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection

        if "alembic_version" not in tables:
            # Pre-Alembic deployment: adopt it at the baseline, then migrate.
            _LOGGER.info(
                "existing database is not under version control; "
                "stamping baseline %s before upgrading",
                BASELINE_REVISION,
            )
            command.stamp(cfg, BASELINE_REVISION)

        command.upgrade(cfg, "head")

    _LOGGER.info("database schema is at revision %s", _current_revision(engine))
