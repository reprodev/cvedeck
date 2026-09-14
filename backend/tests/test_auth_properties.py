"""Property tests for credentials: only the real thing is ever accepted.

Validates Req 16.2, 16.5, 16.7.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.auth import passwords
from app.auth.service import AuthService
from app.data.schema import Base

_STORED = passwords.hash_password("the one true passphrase")


@pytest.fixture(scope="module")
def service_with_credentials():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    service = AuthService(session)
    user = service.create_user("admin", "the one true passphrase")
    session_token = service.start_session(user)
    _, api_token = service.create_api_token("script")
    session.commit()
    yield service, session_token, api_token
    session.close()


@given(st.text(max_size=64))
def test_only_the_original_password_verifies(candidate):
    assert passwords.verify_password(candidate, _STORED) is (
        candidate == "the one true passphrase"
    )


@given(st.text(max_size=128))
def test_no_string_but_a_current_session_token_resolves(service_with_credentials, candidate):
    service, session_token, _ = service_with_credentials
    resolved = service.resolve_session(candidate)
    assert (resolved is not None) is (candidate == session_token)


@given(st.text(max_size=128))
def test_no_string_but_a_current_api_token_resolves(service_with_credentials, candidate):
    service, _, api_token = service_with_credentials
    resolved = service.resolve_api_token(candidate)
    assert (resolved is not None) is (candidate == api_token)
