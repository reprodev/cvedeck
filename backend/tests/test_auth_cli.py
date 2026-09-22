"""``cvedeck-admin``: getting back in from a shell on the host.

Validates Req 16.12.
"""

from __future__ import annotations

import io

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.auth import cli
from app.auth.service import AuthService

GOOD = "correct horse battery"


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CVEDECK_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CVEDECK_DB_URL", raising=False)
    return tmp_path


def _service(data_dir):
    engine = create_engine(f"sqlite:///{(data_dir / 'cvedeck.db').as_posix()}")
    return Session(engine)


def _run(monkeypatch, argv, stdin):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(argv)


def test_create_user_then_reset_password(data_dir, monkeypatch, capsys):
    assert _run(monkeypatch, ["create-user", "admin", "--password-stdin"], GOOD + "\n") == 0

    assert _run(monkeypatch, ["reset-password", "--password-stdin"], "a brand new passphrase\n") == 0

    with _service(data_dir) as session:
        service = AuthService(session)
        assert service.authenticate("admin", GOOD) is None
        assert service.authenticate("admin", "a brand new passphrase") is not None
    assert "admin" in capsys.readouterr().out


def test_reset_signs_out_existing_sessions(data_dir, monkeypatch):
    _run(monkeypatch, ["create-user", "admin", "--password-stdin"], GOOD + "\n")
    with _service(data_dir) as session:
        service = AuthService(session)
        token = service.start_session(service.get_user("admin"))
        session.commit()

    _run(monkeypatch, ["reset-password", "--password-stdin"], "a brand new passphrase\n")

    with _service(data_dir) as session:
        assert AuthService(session).resolve_session(token) is None


def test_create_user_refuses_when_an_account_exists(data_dir, monkeypatch, capsys):
    _run(monkeypatch, ["create-user", "admin", "--password-stdin"], GOOD + "\n")

    assert _run(monkeypatch, ["create-user", "other", "--password-stdin"], GOOD + "\n") == 1
    assert "reset-password" in capsys.readouterr().err


def test_a_weak_password_is_refused_with_the_reason(data_dir, monkeypatch, capsys):
    assert _run(monkeypatch, ["create-user", "admin", "--password-stdin"], "short\n") == 1
    assert "at least" in capsys.readouterr().err


def test_reset_with_no_account_says_what_to_do(data_dir, monkeypatch, capsys):
    assert _run(monkeypatch, ["reset-password", "--password-stdin"], GOOD + "\n") == 1
    assert "no account" in capsys.readouterr().err.lower()


def test_refresh_feeds_reports_each_feed_and_fails_when_one_does(data_dir, monkeypatch, capsys):
    """The systemd timer uses this, so a failure must reach its exit status."""
    from app.services import enrichment

    class Outcome:
        def __init__(self, name, ok):
            self.feed_name, self.ok = name, ok
            self.status = "ok" if ok else "failed"
            self.record_count = 10 if ok else 0
            self.error_detail = None if ok else "upstream down"
            self.unchanged = False

    monkeypatch.setattr(
        enrichment.FeedRefreshService,
        "refresh_all",
        lambda self: [Outcome("kev", True), Outcome("epss", False)],
    )

    assert cli.main(["refresh-feeds"]) == 1
    out = capsys.readouterr().out
    assert "kev: ok, 10 records" in out
    assert "epss: failed, 0 records (upstream down)" in out


def test_refresh_feeds_in_demo_mode_refuses_and_says_so(data_dir, monkeypatch, capsys):
    """The one refresh path a demo leaves reachable (Req 15.6).

    ``cvedeck-admin refresh-feeds`` runs against the database inside the
    container, where no HTTP guard applies, and DEPLOYMENT.md tells operators
    to install it on a timer. Until 0.8.10 it downloaded both feeds and
    replaced the demo's seeded catalogue, then printed an ordinary success --
    so nothing told the operator the fixture was gone.

    Exit status is 0, deliberately: a timer that reports failure every hour on
    a healthy demo trains its operator to stop reading it.
    """
    from app.services import enrichment

    monkeypatch.setenv("CVEDECK_DEMO_MODE", "true")
    monkeypatch.setattr(
        enrichment.FeedRefreshService,
        "refresh_all",
        lambda self: pytest.fail("demo mode refreshed a feed"),
    )

    assert cli.main(["refresh-feeds"]) == 0
    out = capsys.readouterr().out.lower()
    assert "demo mode" in out
    assert "no feed was refreshed" in out
    assert "records" not in out, "the ordinary success line must not appear"
