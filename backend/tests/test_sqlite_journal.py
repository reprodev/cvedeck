"""Which journal SQLite keeps, and backing the database up while it runs (Req 13.10, 13.11).

The point of WAL, reproduced deterministically: under the rollback journal a
reader is refused while another connection holds an exclusive lock -- the
moment of a large commit -- and under WAL it is not.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest
from sqlalchemy import create_engine, text

from app.data import sqlite_journal
from app.data.sqlite_journal import (
    LOCAL,
    NETWORK,
    configure_sqlite,
    decide,
    mount_type_for,
)

# Real /proc/self/mountinfo shapes, from a container and from hosts.
CONTAINER = r"""1205 1052 0:328 / / rw,relatime master:571 - overlay overlay rw,lowerdir=/x,upperdir=/y,workdir=/z
1206 1205 0:331 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1218 1205 8:80 /docker/volumes/cvedeck-data/_data /data rw,relatime - ext4 /dev/sdf rw,discard,errors=remount-ro
1219 1205 0:62 / /data/shared rw,relatime - nfs4 nas.example.lan:/export/cvedeck rw,vers=4.2
1220 1205 0:63 / /mnt/smb rw,relatime - cifs //nas/share rw,vers=3.1.1
1221 1205 0:64 / /mnt/my\040files rw,nosuid - fuse.sshfs user@host:/srv rw
1222 1205 0:65 / /mnt/c rw,noatime - 9p drvfs rw,aname=drvfs
1223 1205 0:66 / /run/desktop/mnt/host rw - virtiofs mount0 rw
1224 1205 0:67 / /tmp/ram rw - tmpfs tmpfs rw
"""
PROC_MOUNTS = """overlay / overlay rw,relatime 0 0
/dev/sdf /data ext4 rw,relatime 0 0
"""


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/data/cvedeck.db", "ext4"),
        # The longest mount point wins: /data/shared is NFS inside an ext4 /data.
        ("/data/shared/cvedeck.db", "nfs4"),
        ("/mnt/smb/cvedeck.db", "cifs"),
        # mountinfo escapes a space as \040.
        ("/mnt/my files/cvedeck.db", "fuse.sshfs"),
        ("/mnt/c/Users/x/cvedeck.db", "9p"),
        ("/run/desktop/mnt/host/db", "virtiofs"),
        ("/tmp/ram/cvedeck.db", "tmpfs"),
        ("/app/cvedeck.db", "overlay"),
        # A shared prefix is not the same mount.
        ("/database/cvedeck.db", "overlay"),
    ],
)
def test_the_filesystem_holding_a_path(path, expected):
    assert mount_type_for(path, CONTAINER) == expected


def test_proc_mounts_is_read_too():
    assert mount_type_for("/data/cvedeck.db", PROC_MOUNTS) == "ext4"


@pytest.mark.parametrize("setting", ["delete", "auto", "wal"])
@pytest.mark.parametrize("filesystem", ["ext4", "overlay", "nfs4", "cifs", "9p", "virtiofs", None])
def test_the_whole_policy(setting, filesystem):
    """Req 13.10: never WAL on a network filesystem; auto only on a known local one."""
    decision = decide(setting, filesystem)
    if setting == "delete":
        assert decision.mode == "delete" and not decision.refused
    elif filesystem in NETWORK:
        assert decision.mode == "delete"
        assert decision.refused is (setting == "wal")
        assert "network" in decision.reason
    elif setting == "wal":
        assert decision.mode == "wal"
    else:
        assert decision.mode == ("wal" if filesystem in LOCAL else "delete")
        if decision.mode == "delete":
            assert "CVEDECK_SQLITE_JOURNAL=wal" in decision.reason


def test_the_lists_do_not_overlap():
    assert not LOCAL & NETWORK


# --- On a real database file -------------------------------------------------


def _engine(path):
    return create_engine(f"sqlite:///{path.as_posix()}", connect_args={"timeout": 0.2})


def _mode(path) -> str:
    with sqlite3.connect(path) as con:
        return con.execute("PRAGMA journal_mode").fetchone()[0]


@pytest.mark.parametrize("setting, filesystem, expected", [
    ("wal", "ext4", "wal"),
    ("delete", "ext4", "delete"),
    ("auto", "ext4", "wal"),
    ("auto", None, "delete"),
    ("wal", "nfs4", "delete"),
])
def test_the_journal_is_set_and_read_back(tmp_path, setting, filesystem, expected):
    db = tmp_path / "cvedeck.db"
    state = configure_sqlite(_engine(db), setting, filesystem=filesystem)
    assert state.mode == expected
    assert _mode(db) == expected
    assert sqlite_journal.current() == state


def test_a_database_left_in_wal_is_switched_back(tmp_path):
    db = tmp_path / "cvedeck.db"
    first = _engine(db)
    configure_sqlite(first, "wal", filesystem="ext4")
    first.dispose()
    configure_sqlite(_engine(db), "delete", filesystem="ext4")
    assert _mode(db) == "delete"


def test_what_sqlite_actually_kept_is_reported(tmp_path, caplog):
    """SQLite keeps the old mode silently when it cannot switch; never assume it did."""
    db = tmp_path / "cvedeck.db"
    configure_sqlite(_engine(db), "wal", filesystem="ext4")
    holder = sqlite3.connect(db)
    holder.execute("BEGIN")
    holder.execute("SELECT 1 FROM sqlite_master").fetchall()
    try:
        state = configure_sqlite(_engine(db), "delete", filesystem="ext4")
    finally:
        holder.close()
    assert state.mode == "wal"
    assert any("SQLite kept wal" in r.getMessage() for r in caplog.records)


def test_postgres_and_memory_databases_are_left_alone():
    assert configure_sqlite(create_engine("sqlite:///:memory:"), "wal", filesystem="ext4") is None


@pytest.mark.parametrize("setting, blocked", [("delete", True), ("wal", False)])
def test_a_reader_is_not_held_up_by_a_commit_under_wal(tmp_path, setting, blocked):
    """Req 13.10, the reason for any of this: the 20-second read stall, in miniature.

    One connection holds the exclusive lock a large commit takes. Under the
    rollback journal a reader waits for it -- here, past a 0.2 s timeout -- and
    under WAL it reads at once.
    """
    db = tmp_path / "cvedeck.db"
    engine = _engine(db)
    configure_sqlite(engine, setting, filesystem="ext4")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE t (x INTEGER)"))
        connection.execute(text("INSERT INTO t VALUES (1)"))

    writer = sqlite3.connect(db, timeout=0.2)
    writer.execute("BEGIN EXCLUSIVE")
    writer.execute("INSERT INTO t VALUES (2)")
    try:
        if blocked:
            with pytest.raises(Exception, match="locked"):
                with engine.connect() as reader:
                    reader.execute(text("SELECT count(*) FROM t")).scalar()
        else:
            with engine.connect() as reader:
                assert reader.execute(text("SELECT count(*) FROM t")).scalar() == 1
    finally:
        writer.rollback()
        writer.close()


def test_a_clean_stop_folds_the_wal_back(tmp_path):
    db = tmp_path / "cvedeck.db"
    engine = _engine(db)
    configure_sqlite(engine, "wal", filesystem="ext4")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE t (x INTEGER)"))
        connection.execute(text("INSERT INTO t VALUES (1)"))
    wal = db.with_name(db.name + "-wal")
    assert wal.exists() and wal.stat().st_size > 0

    sqlite_journal.checkpoint(engine)

    assert not wal.exists() or wal.stat().st_size == 0


def test_an_unknown_setting_is_refused_at_start_up(monkeypatch):
    from app import config

    monkeypatch.setenv("CVEDECK_SQLITE_JOURNAL", "fast")
    with pytest.raises(ValueError, match="delete, auto or wal"):
        config.sqlite_journal()
    monkeypatch.delenv("CVEDECK_SQLITE_JOURNAL")
    assert config.sqlite_journal() == "delete"


def test_health_reports_the_journal_to_a_signed_in_caller(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app.api.app import create_app
    from tests.auth_helpers import override_auth

    monkeypatch.setenv("CVEDECK_AUTH", "off")
    configure_sqlite(_engine(tmp_path / "cvedeck.db"), "wal", filesystem="ext4")
    client = TestClient(override_auth(create_app()))
    database = client.get("/api/health").json()["capabilities"]["database"]
    assert database == {"engine": "sqlite", "journal": "wal"}


# --- cvedeck-admin backup (Req 13.11) ------------------------------------------


@pytest.fixture()
def live(tmp_path, monkeypatch):
    db = tmp_path / "cvedeck.db"
    monkeypatch.setenv("CVEDECK_DB_URL", f"sqlite:///{db.as_posix()}")
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (x INTEGER)")
    con.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(1000)])
    con.commit()
    yield db, con
    con.close()


def test_a_backup_is_a_complete_consistent_copy_taken_while_writes_continue(live, tmp_path):
    from app.auth.cli import main

    db, con = live
    stop = threading.Event()

    def keep_writing():
        writer = sqlite3.connect(db, timeout=5)
        while not stop.is_set():
            writer.execute("INSERT INTO t VALUES (-1)")
            writer.commit()
        writer.close()

    thread = threading.Thread(target=keep_writing)
    thread.start()
    try:
        assert main(["backup", str(tmp_path / "copy.db")]) == 0
    finally:
        stop.set()
        thread.join()

    with sqlite3.connect(tmp_path / "copy.db") as copy:
        assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert copy.execute("SELECT count(*) FROM t WHERE x >= 0").fetchone()[0] == 1000
        # A self-contained file, whatever journal the live database keeps.
        assert copy.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_a_backup_will_not_overwrite_a_file_unless_told_to(live, tmp_path, capsys):
    from app.auth.cli import main

    target = tmp_path / "copy.db"
    target.write_text("keep me", encoding="utf-8")
    assert main(["backup", str(target)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "keep me"
    assert main(["backup", str(target), "--force"]) == 0


def test_a_backup_will_not_write_over_the_live_database(live, capsys):
    from app.auth.cli import main

    db, _con = live
    assert main(["backup", str(db), "--force"]) == 1
    assert "live database" in capsys.readouterr().err


def test_a_backup_of_a_postgres_deployment_points_at_pg_dump(monkeypatch, tmp_path, capsys):
    from app.auth.cli import main

    monkeypatch.setenv("CVEDECK_DB_URL", "postgresql+psycopg://u:p@db.invalid/cvedeck")
    assert main(["backup", str(tmp_path / "x.db")]) == 1
    assert "pg_dump" in capsys.readouterr().err


def test_a_copy_that_fails_its_integrity_check_is_not_kept(live, tmp_path, monkeypatch, capsys):
    """A backup that will not open must be found now, not on the day it is needed."""
    from app.auth import cli

    monkeypatch.setattr(cli, "_integrity_check", lambda connection: ("*** page 3: btree corrupt",))
    target = tmp_path / "copy.db"

    assert cli.main(["backup", str(target)]) == 1

    assert "integrity check" in capsys.readouterr().err
    assert not target.exists()
    assert not target.with_name("copy.db.partial").exists()
