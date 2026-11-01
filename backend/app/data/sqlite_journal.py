"""Which journal SQLite keeps: the rollback journal by default, WAL when asked (Req 13.10).

SQLite's default rollback journal blocks every reader while a write commits.
Measured with disk writes throttled to 5 MB/s, dashboard reads waited about 20 s
while the Ubuntu kernel feed's 844,000 rows committed. Write-ahead logging (WAL)
lets readers carry on through a commit.

WAL relies on shared memory and file locking that network filesystems -- NFS,
SMB/CIFS, sshfs, 9p -- do not provide reliably, and a database on one can be
corrupted. So, by the owner's decision:

- WAL is opt-in: ``CVEDECK_SQLITE_JOURNAL`` defaults to ``delete``, the
  rollback journal, as every release before this one used.
- ``auto`` uses WAL only on a filesystem known to be local, and keeps the
  rollback journal on anything else, saying how to force it.
- ``wal`` uses WAL, except on a filesystem known to be a network one, where it
  is refused: an explicit request is not allowed to corrupt the database.

The whole policy is :func:`decide`. The mode actually in force is read back
from SQLite after it is set, because SQLite quietly keeps the old mode when it
cannot switch.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, event, text

_LOGGER = logging.getLogger(__name__)

SETTINGS = ("delete", "auto", "wal")

#: Filesystems WAL is known to work on: local disks, and the layers a container
#: puts over them.
LOCAL = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs",
    "overlay", "tmpfs", "apfs", "hfs",
})
#: Filesystems WAL must never be used on: shared or remote storage without the
#: shared-memory and locking guarantees WAL depends on.
NETWORK = frozenset({
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "fuse.sshfs",
    "fuse.glusterfs", "fuse.cephfs", "9p", "afs", "lustre", "gpfs", "beegfs",
    "fuse.rclone", "davfs", "fuse.s3fs",
})


@dataclass(frozen=True)
class JournalDecision:
    """What :func:`decide` chose, and why, in words for the log."""

    mode: str
    reason: str
    #: True when ``wal`` was asked for and refused on a network filesystem.
    refused: bool = False


@dataclass(frozen=True)
class JournalState:
    """The journal in force, as SQLite reports it, for the health route and the log."""

    requested: str
    mode: str
    filesystem: str | None
    reason: str


_state: JournalState | None = None


def current() -> JournalState | None:
    """The journal configured for this process's database, or ``None`` (PostgreSQL, tests)."""
    return _state


def decide(setting: str, filesystem: str | None) -> JournalDecision:
    """The journal mode for ``setting`` on ``filesystem`` (``None``: unknown). Req 13.10."""
    fs = filesystem or "unknown"
    if setting == "delete":
        return JournalDecision("delete", "the rollback journal, the default")
    if filesystem in NETWORK:
        return JournalDecision(
            "delete",
            f"filesystem {fs}: WAL is unsafe on network filesystems",
            refused=setting == "wal",
        )
    if setting == "wal":
        return JournalDecision("wal", f"requested, on filesystem {fs}")
    if filesystem in LOCAL:
        return JournalDecision("wal", f"auto, on local filesystem {fs}")
    return JournalDecision(
        "delete",
        f"auto: filesystem {fs} is not one CveDeck knows to be local; "
        "set CVEDECK_SQLITE_JOURNAL=wal to use WAL on it anyway",
    )


def _unescape(field: str) -> str:
    """mountinfo escapes space, tab, newline and backslash as octal: ``\\040``."""
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 4 <= len(field) and field[i + 1 : i + 4].isdigit():
            out.append(chr(int(field[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def _mounts(text_: str) -> list[tuple[str, str]]:
    """(mount point, filesystem type) per line of mountinfo or /proc/mounts."""
    mounts: list[tuple[str, str]] = []
    for line in text_.splitlines():
        if " - " in line:
            # mountinfo: "id parent maj:min root mountpoint opts [tags] - fstype source opts"
            before, after = line.split(" - ", 1)
            fields, rest = before.split(), after.split()
            if len(fields) >= 5 and rest:
                mounts.append((_unescape(fields[4]), rest[0]))
        else:
            # /proc/mounts: "device mountpoint fstype opts 0 0"
            fields = line.split()
            if len(fields) >= 3:
                mounts.append((_unescape(fields[1]), fields[2]))
    return mounts


def mount_type_for(path: str, mountinfo: str) -> str | None:
    """The filesystem type holding ``path``: the mount with the longest matching mount point."""
    best: tuple[int, str] | None = None
    for point, fstype in _mounts(mountinfo):
        prefix = point.rstrip("/") + "/"
        if path == point or path.startswith(prefix):
            if best is None or len(point) > best[0]:
                best = (len(point), fstype)
    return best[1] if best else None


def filesystem_type(path: Path) -> str | None:
    """The type of filesystem ``path`` lives on, on Linux; ``None`` where it cannot tell."""
    if not sys.platform.startswith("linux"):
        return None
    resolved = os.path.realpath(path)
    for source in ("/proc/self/mountinfo", "/proc/mounts"):
        try:
            with open(source, encoding="utf-8", errors="replace") as fh:
                found = mount_type_for(resolved, fh.read())
        except OSError:
            continue
        if found:
            return found
    return None


def configure_sqlite(engine: Engine, setting: str, *, filesystem: str | None = None) -> JournalState | None:
    """Set the journal on every connection of a SQLite file engine, and report what took (Req 13.10).

    ``None`` for anything that is not a SQLite file: PostgreSQL, or an
    in-memory database, which has no journal to choose.
    """
    global _state
    database = engine.url.database
    if engine.dialect.name != "sqlite" or not database or database == ":memory:":
        return None
    if filesystem is None:
        filesystem = filesystem_type(Path(database).resolve().parent)
    decision = decide(setting, filesystem)
    pragmas = (
        ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL"]
        if decision.mode == "wal"
        else ["PRAGMA journal_mode=DELETE"]
    )

    @event.listens_for(engine, "connect")
    def _set_journal(dbapi_connection, _record) -> None:  # pragma: no branch - trivial
        cursor = dbapi_connection.cursor()
        try:
            for pragma in pragmas:
                try:
                    cursor.execute(pragma)
                except sqlite3.OperationalError:
                    # Changing journal mode needs the database to itself; with
                    # another process holding it (the server, beside this CLI)
                    # SQLite refuses. Keep the mode it has; the read-back below
                    # reports it, rather than failing the start-up.
                    break
        finally:
            cursor.close()

    with engine.connect() as connection:
        actual = str(connection.execute(text("PRAGMA journal_mode")).scalar() or "").lower()
    state = JournalState(requested=setting, mode=actual or decision.mode, filesystem=filesystem, reason=decision.reason)
    if decision.refused:
        _LOGGER.error(
            "CVEDECK_SQLITE_JOURNAL=wal refused: %s. Using the rollback journal.", decision.reason
        )
    if actual and actual != decision.mode:
        _LOGGER.warning(
            "SQLite journal: asked for %s but SQLite kept %s (another process may hold the "
            "database open)", decision.mode, actual,
        )
    else:
        _LOGGER.info("SQLite journal: %s (%s)", state.mode, decision.reason)
    _state = state
    return state


def checkpoint(engine: Engine) -> None:
    """Fold the WAL back into the database file on a clean stop, best effort.

    After it the data directory holds one self-contained ``.db`` again, which is
    what an operator copying the volume expects.
    """
    if _state is None or _state.mode != "wal":
        return
    try:
        with engine.connect() as connection:
            connection.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
    except Exception:  # a stop must not fail on this
        _LOGGER.warning("Could not checkpoint the SQLite WAL on shutdown", exc_info=True)
