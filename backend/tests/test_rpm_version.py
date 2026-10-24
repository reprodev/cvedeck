"""RPM version ordering (Req 2.11).

Feature: cvedeck, Property 20.

The vectors are rpm's own: ``rpmvercmp`` cases from rpm's test suite
(``tests/rpmvercmp.at``), plus the epoch and release handling rpm applies
around it, and the Rocky case that prompted this.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.scanner.rpm_version import compare

_CASES = [
    # (a, b, expected sign of compare(a, b)) -- from rpm's rpmvercmp.at
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("5.5p1", "5.5p2", -1),
    ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10.1", -1),
    ("xyz.4", "8", -1),
    ("8", "xyz.4", 1),
    ("5.5p1", "5.5.p1", 0),
    ("5.5p10", "5.5.p10", 0),
    ("10b2", "10a1", 1),
    ("10a2", "10b2", -1),
    ("1.0aa", "1.0a", 1),
    ("10.0001", "10.1", 0),
    ("10.0001", "10.0039", -1),
    ("4.999.9", "5.0", -1),
    ("20101121", "20101122", -1),
    ("2_0", "2_0", 0),
    ("2.0", "2_0", 0),
    ("a", "b", -1),
    ("a+", "a_", 0),
    ("+", "_", 0),
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0^", "1.0", 1),
    ("1.0^", "1.0^", 0),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git1", "1.01", -1),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
    # Epoch and release, around rpmvercmp.
    ("1:1.0-1", "2.0-1", 1),
    ("0:1.0-1", "1.0-1", 0),
    ("1.0-1", "1.0-2", -1),
    ("1.0", "1.0-1", -1),
    # The Rocky case, and the one text order gets wrong.
    ("1.21.1-1.el9", "1.21.1-10.el9_8", -1),
    ("1.9-1.el9", "1.10-1.el9", -1),
    ("3.0.7-27.el9", "3.0.7-27.el9_5", -1),
]


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


@pytest.mark.parametrize("a, b, expected", _CASES)
def test_rpm_orders_these_versions_as_rpm_does(a, b, expected):
    assert _sign(compare(a, b)) == expected
    assert _sign(compare(b, a)) == -expected


versions = st.text(alphabet="0123456789abz.-:~^_", min_size=0, max_size=10)


@given(versions)
def test_a_version_equals_itself(v):
    """Property 20: reflexive."""
    assert compare(v, v) == 0


@given(versions, versions)
def test_the_order_is_antisymmetric(a, b):
    """Property 20: swapping the arguments flips the answer."""
    assert _sign(compare(a, b)) == -_sign(compare(b, a))


@given(versions, versions, versions)
def test_the_order_is_transitive(a, b, c):
    """Property 20: a total preorder, so taking the earliest is well defined."""
    ab, bc = _sign(compare(a, b)), _sign(compare(b, c))
    if ab <= 0 and bc <= 0:
        assert compare(a, c) <= 0
    if ab >= 0 and bc >= 0:
        assert compare(a, c) >= 0
