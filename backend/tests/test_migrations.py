"""Tests for the schema migration story.

Before Alembic, ``Base.metadata.create_all`` was the whole story: correct for a
fresh database and silently useless for an existing one, so any column added
after v0.3.0 would break every deployed instance on upgrade. These tests pin the
three cases the bootstrap has to handle.
"""

from __future__ import annotations

from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app.data.migrations_runtime import (
    BASELINE_REVISION,
    alembic_config,
    upgrade_to_head,
)
from app.data.schema import Base


def _revision(engine) -> str | None:
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).fetchone()
    return row[0] if row else None


def _head() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def _make_pre_alembic_database(url: str) -> None:
    """Build a database with the schema as it stood before Alembic existed.

    Deliberately *not* ``Base.metadata.create_all``: the ORM metadata tracks the
    current schema, so using it here would hand the migration a database that
    already has the columns it is about to add, and the test would pass while
    proving nothing. Migrating to the baseline revision and then removing the
    version table reproduces a genuine v0.3.0 database, and stays correct as
    further revisions land.
    """
    engine = create_engine(url)
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, BASELINE_REVISION)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
    engine.dispose()


def test_baseline_revision_exists_in_the_script_directory():
    """BASELINE_REVISION must name a real migration, or stamping is a no-op."""
    script = ScriptDirectory.from_config(alembic_config())
    assert script.get_revision(BASELINE_REVISION) is not None


def test_fresh_database_is_created_and_stamped_at_head(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")

    upgrade_to_head(engine)

    tables = set(inspect(engine).get_table_names())
    assert "target_machines" in tables
    assert "alembic_version" in tables
    assert _revision(engine) == _head()


def test_pre_alembic_database_is_adopted_and_upgraded(tmp_path):
    """A v0.3.0 database has tables but no alembic_version; it must migrate."""
    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    _make_pre_alembic_database(url)

    engine = create_engine(url)
    tables_before = set(inspect(engine).get_table_names())
    assert "alembic_version" not in tables_before
    assert "last_scan_sources_ok" not in {
        c["name"] for c in inspect(engine).get_columns("target_machines")
    }

    upgrade_to_head(engine)

    assert _revision(engine) == _head()
    columns = {c["name"] for c in inspect(engine).get_columns("target_machines")}
    assert "last_scan_sources_ok" in columns, "migration did not apply"



def test_upgrade_is_idempotent(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'repeat.db').as_posix()}")

    upgrade_to_head(engine)
    first = _revision(engine)
    upgrade_to_head(engine)

    assert _revision(engine) == first == _head()


def test_existing_rows_survive_migration(tmp_path):
    """Migrations must never drop data from a deployed database."""
    url = f"sqlite:///{(tmp_path / 'data.db').as_posix()}"
    _make_pre_alembic_database(url)
    legacy = create_engine(url)
    with legacy.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, sync_status) "
                "VALUES ('m1', 'host-1', 'LINUX', 'SUCCESS', 'SYNCED')"
            )
        )
    legacy.dispose()

    engine = create_engine(url)
    upgrade_to_head(engine)

    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT hostname FROM target_machines WHERE id = 'm1'")
        ).fetchone()
    assert row is not None and row[0] == "host-1"


def test_threat_intel_migration_round_trips(tmp_path):
    """The enrichment revision applies and reverses cleanly.

    A downgrade path that does not work is a downgrade path nobody can use, and
    this revision adds three tables plus an enum -- the shape most likely to
    leave PostgreSQL with an orphaned type after a rollback.
    """
    url = f"sqlite:///{(tmp_path / 'intel.db').as_posix()}"
    engine = create_engine(url)
    upgrade_to_head(engine)

    tables = set(inspect(engine).get_table_names())
    assert {"kev_entries", "epss_scores", "feed_refreshes"} <= tables

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        # Named, not "-1": later revisions sit on top of this one.
        command.downgrade(cfg, "e451e20b58e2")

    tables = set(inspect(engine).get_table_names())
    assert not {"kev_entries", "epss_scores", "feed_refreshes"} & tables

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")

    assert _revision(engine) == _head()


def test_enrichment_columns_are_null_on_pre_existing_findings(tmp_path):
    """Existing findings must migrate to NULL, not to "not exploited".

    Backfilling ``kev_listed`` to false would assert that every finding written
    before enrichment existed had been checked against CISA's catalogue and
    cleared. Nothing checked them. NULL is the only honest value.
    """
    url = f"sqlite:///{(tmp_path / 'findings.db').as_posix()}"
    _make_pre_alembic_database(url)
    legacy = create_engine(url)
    with legacy.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, sync_status) "
                "VALUES ('m1', 'host-1', 'LINUX', 'SUCCESS', 'SYNCED')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO cve_findings "
                "(id, machine_id, cve_id, cvss_score, severity, source, sync_status) "
                "VALUES ('f1', 'm1', 'CVE-2021-44228', 10.0, 'CRITICAL', "
                "'osv', 'SYNCED')"
            )
        )
    legacy.dispose()

    engine = create_engine(url)
    upgrade_to_head(engine)

    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT kev_listed, kev_due_date, epss_score, epss_percentile "
                "FROM cve_findings WHERE id = 'f1'"
            )
        ).fetchone()

    assert row is not None
    assert all(value is None for value in row)


def test_never_scanned_backfill_only_touches_unscanned_rows(tmp_path):
    """Enrolled-but-unscanned rows become NEVER_SCANNED; real failures do not.

    Enrollment used to stamp CONNECTION_FAILURE on a brand-new row, so every
    host added from discovery showed a red failure badge before anything had
    tried to reach it. `last_scanned_at IS NULL` separates the provisional
    status from an observed one. Note SQLAlchemy persists enum *names*.
    """
    url = f"sqlite:///{(tmp_path / 'backfill.db').as_posix()}"
    _make_pre_alembic_database(url)

    legacy = create_engine(url)
    with legacy.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, last_scanned_at, sync_status) "
                "VALUES "
                # enrolled from discovery, never scanned -> should be rewritten
                "('enrolled', 'a', 'LINUX', 'CONNECTION_FAILURE', NULL, 'SYNCED'), "
                # genuinely failed to connect -> must be left alone
                "('failed', 'b', 'LINUX', 'CONNECTION_FAILURE', '2026-01-01 00:00:00', 'SYNCED'), "
                # unrelated statuses must be untouched
                "('ok', 'c', 'LINUX', 'SUCCESS', '2026-01-01 00:00:00', 'SYNCED'), "
                "('auth', 'd', 'LINUX', 'AUTH_FAILURE', NULL, 'SYNCED')"
            )
        )
    legacy.dispose()

    engine = create_engine(url)
    upgrade_to_head(engine)

    with engine.connect() as connection:
        statuses = dict(
            connection.execute(
                text("SELECT id, last_scan_status FROM target_machines")
            ).fetchall()
        )

    assert statuses["enrolled"] == "NEVER_SCANNED"
    assert statuses["failed"] == "CONNECTION_FAILURE"
    assert statuses["ok"] == "SUCCESS"
    assert statuses["auth"] == "AUTH_FAILURE"


def test_backfilled_rows_load_through_the_orm(tmp_path):
    """The backfilled value must be a member the ORM can actually read back."""
    from sqlalchemy.orm import Session

    from app.data.schema import TargetMachine as TargetMachineRow
    from app.enums import ScanStatus

    url = f"sqlite:///{(tmp_path / 'orm.db').as_posix()}"
    _make_pre_alembic_database(url)
    legacy = create_engine(url)
    with legacy.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, last_scanned_at, sync_status) "
                "VALUES ('m', 'h', 'LINUX', 'CONNECTION_FAILURE', NULL, 'SYNCED')"
            )
        )
    legacy.dispose()

    engine = create_engine(url)
    upgrade_to_head(engine)

    with Session(engine) as session:
        row = session.get(TargetMachineRow, "m")
        assert row.last_scan_status is ScanStatus.NEVER_SCANNED
        assert row.last_scan_sources_ok is True


def test_a_0_6_0_database_upgrades_to_access_control_with_its_data(tmp_path):
    """Validates Req 16.3: an upgraded instance keeps its fleet and asks for setup."""
    url = f"sqlite:///{(tmp_path / 'v060.db').as_posix()}"
    engine = create_engine(url)
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "a1c7f3e9d204")
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, last_scan_sources_ok, sync_status) "
                "VALUES ('m1', 'web-01', 'LINUX', 'SUCCESS', 1, 'SYNCED')"
            )
        )

    upgrade_to_head(engine)

    assert _revision(engine) == _head()
    tables = set(inspect(engine).get_table_names())
    assert {"users", "auth_sessions", "api_tokens", "auth_setup"} <= tables
    with engine.connect() as connection:
        assert connection.execute(text("SELECT hostname FROM target_machines")).scalar() == "web-01"
        assert connection.execute(text("SELECT COUNT(*) FROM users")).scalar() == 0


def test_the_access_control_migration_round_trips(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'auth.db').as_posix()}")
    upgrade_to_head(engine)

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "a1c7f3e9d204")
    assert not {"users", "auth_sessions", "api_tokens", "auth_setup"} & set(
        inspect(engine).get_table_names()
    )

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
    assert _revision(engine) == _head()


def test_a_0_7_3_database_upgrades_to_host_keys_with_its_data(tmp_path):
    """Validates Req 17: an upgraded instance keeps its fleet and has no pins."""
    from sqlalchemy.orm import Session

    from app.data.schema import SshHostKey
    from app.data.schema import TargetMachine as TargetMachineRow
    from app.enums import ScanStatus

    url = f"sqlite:///{(tmp_path / 'v073.db').as_posix()}"
    engine = create_engine(url)
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "c3d9e1f27a60")
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, last_scan_sources_ok, sync_status) "
                "VALUES ('m1', 'web-01', 'LINUX', 'SUCCESS', 1, 'SYNCED')"
            )
        )

    upgrade_to_head(engine)

    assert _revision(engine) == _head()
    with Session(engine) as session:
        assert session.query(SshHostKey).count() == 0
        row = session.get(TargetMachineRow, "m1")
        assert row.hostname == "web-01"
        # The widened status round-trips through the ORM.
        row.last_scan_status = ScanStatus.HOST_KEY_MISMATCH
        session.commit()
        session.expire_all()
        assert session.get(TargetMachineRow, "m1").last_scan_status is ScanStatus.HOST_KEY_MISMATCH


def test_the_host_keys_migration_round_trips(tmp_path):
    """Downgrading folds the host-key refusals into a status the old build knows."""
    engine = create_engine(f"sqlite:///{(tmp_path / 'keys.db').as_posix()}")
    upgrade_to_head(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO target_machines "
                "(id, hostname, platform, last_scan_status, last_scan_sources_ok, sync_status) "
                "VALUES ('m1', 'a', 'LINUX', 'HOST_KEY_MISMATCH', 1, 'SYNCED'), "
                "('m2', 'b', 'LINUX', 'HOST_KEY_UNKNOWN', 1, 'SYNCED'), "
                "('m3', 'c', 'LINUX', 'SUCCESS', 1, 'SYNCED')"
            )
        )

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "c3d9e1f27a60")
    assert "ssh_host_keys" not in inspect(engine).get_table_names()
    with engine.connect() as connection:
        statuses = dict(
            connection.execute(text("SELECT id, last_scan_status FROM target_machines")).fetchall()
        )
    assert statuses == {"m1": "CONNECTION_FAILURE", "m2": "CONNECTION_FAILURE", "m3": "SUCCESS"}

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
    assert _revision(engine) == _head()


def test_there_is_exactly_one_head():
    assert len(ScriptDirectory.from_config(alembic_config()).get_heads()) == 1


def test_the_payload_digest_migration_round_trips(tmp_path):
    """Down and back up again, on the feed table (Req 10.14).

    The drop is batched because SQLite below 3.35 has no native DROP COLUMN.
    An unbatched one passes on a modern developer machine and fails on an older
    runtime, which is the least useful place to find out.
    """
    engine = create_engine(f"sqlite:///{(tmp_path / 'digest.db').as_posix()}")
    upgrade_to_head(engine)
    assert "payload_digest" in {
        c["name"] for c in inspect(engine).get_columns("feed_refreshes")
    }

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "c71f4a2be095")
    assert "payload_digest" not in {
        c["name"] for c in inspect(engine).get_columns("feed_refreshes")
    }

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
    assert _revision(engine) == _head()


def test_an_upgraded_database_keeps_its_feed_row_and_digests_nothing_yet(tmp_path):
    """Upgrading must not invent a digest for a catalogue it never checked.

    A non-null digest here would match nothing on the next refresh, or -- worse,
    if it somehow did -- would skip the first rewrite and leave the stored
    findings reconciled against a catalogue that was never compared.
    """
    engine = create_engine(f"sqlite:///{(tmp_path / 'upgraded.db').as_posix()}")
    upgrade_to_head(engine)

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "c71f4a2be095")
        connection.execute(
            text(
                "INSERT INTO feed_refreshes (feed_name, last_status, record_count) "
                "VALUES ('kev', 'ok', 1687)"
            )
        )

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")

    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT record_count, payload_digest FROM feed_refreshes")
        ).one()
    assert row[0] == 1687, "the existing cache state survives"
    assert row[1] is None, "nothing has been digested yet"
