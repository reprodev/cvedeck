"""dpkg's version ordering (Req 12.11).

Cases are dpkg's own documented orderings plus the kernel versions the Ubuntu
feed compares; each pair is asserted in both directions.
"""

from __future__ import annotations

import pytest

from app.scanner.debian_version import compare


@pytest.mark.parametrize(
    "older, newer",
    [
        ("1.0", "1.1"),
        ("1.0", "1.0-1"),
        ("1.0~rc1", "1.0"),
        ("1.0~rc1-1", "1.0-1"),
        ("1.0~~", "1.0~"),
        ("1.0a", "1.0b"),
        ("1.0a", "1.0+"),
        ("1.9", "1.10"),
        ("0:2.0", "1:1.0"),
        ("5.15.0-25", "5.15.0-101.111"),
        ("0:5.15.0-100", "5.15.0-101.111"),
        ("5.15.0-101", "5.15.0-101.111"),
        ("6.8.0-40", "6.8.0-51.52"),
        ("2.36-9", "2.36-9+deb12u1"),
    ],
)
def test_order(older, newer):
    assert compare(older, newer) < 0
    assert compare(newer, older) > 0


@pytest.mark.parametrize("a, b", [("1.0", "1.0"), ("0:1.0", "1.0"), ("1.00", "1.0"), ("5.15.0-101.111", "0:5.15.0-101.111")])
def test_equal(a, b):
    assert compare(a, b) == 0
