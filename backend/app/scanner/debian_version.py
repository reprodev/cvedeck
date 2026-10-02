"""Debian package version ordering, as dpkg defines it.

Needed only where CveDeck compares versions itself rather than asking OSV to:
the Ubuntu kernel feed (Req 12.11) states each fix as a version, and whether
the running kernel is older is a comparison made here.

Implements dpkg's ``verrevcmp`` over ``[epoch:]upstream[-revision]``: runs of
non-digits compare character by character with letters before non-letters and
``~`` before everything, including the end of the string; runs of digits
compare numerically.
"""

from __future__ import annotations


def _order(char: str) -> int:
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    upstream, _, revision = version.rpartition("-")
    if not upstream:
        upstream, revision = revision, ""
    return epoch, upstream, revision


def compare(a: str, b: str) -> int:
    """Negative, zero or positive as ``a`` sorts before, equal to or after ``b``."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
