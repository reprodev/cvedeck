"""RPM package version ordering, as rpm defines it.

Needed only where CveDeck compares versions itself rather than asking OSV to:
when several OSV records for one CVE and package name different fixes, the
finding shows the earliest (Req 2.11). Compared as text, ``1.21.1-1.el9``
happened to come before ``1.21.1-10.el9_8``, but ``1.9-1.el9`` would come after
``1.10-1.el9`` -- text order is not version order.

Implements rpm's ``rpmvercmp`` over ``[epoch:]version[-release]``: the string is
cut into runs of digits and runs of letters, anything else only separating
them; digit runs compare numerically and beat letter runs; ``~`` sorts before
everything, including the end of the string, and ``^`` after the end but
before any further run. A missing epoch is 0, and a missing release sorts
before any release, which keeps the order total.
"""

from __future__ import annotations


def _isalpha(char: str) -> bool:
    return "a" <= char <= "z" or "A" <= char <= "Z"


def _isdigit(char: str) -> bool:
    return "0" <= char <= "9"


def _isalnum(char: str) -> bool:
    return _isalpha(char) or _isdigit(char)


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1

        # A tilde sorts before everything, even the end of the string.
        one_tilde = i < len(a) and a[i] == "~"
        two_tilde = j < len(b) and b[j] == "~"
        if one_tilde or two_tilde:
            if not one_tilde:
                return 1
            if not two_tilde:
                return -1
            i += 1
            j += 1
            continue

        # A caret sorts after the end of the string, before anything else.
        one_caret = i < len(a) and a[i] == "^"
        two_caret = j < len(b) and b[j] == "^"
        if one_caret or two_caret:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not one_caret:
                return 1
            if not two_caret:
                return -1
            i += 1
            j += 1
            continue

        if i >= len(a) or j >= len(b):
            break

        numeric = _isdigit(a[i])
        kind = _isdigit if numeric else _isalpha
        start_a, start_b = i, j
        while i < len(a) and kind(a[i]):
            i += 1
        while j < len(b) and kind(b[j]):
            j += 1
        run_a, run_b = a[start_a:i], b[start_b:j]

        # Runs of different kinds: a number is newer than letters.
        if not run_b:
            return 1 if numeric else -1

        if numeric:
            run_a, run_b = run_a.lstrip("0"), run_b.lstrip("0")
            if len(run_a) != len(run_b):
                return 1 if len(run_a) > len(run_b) else -1
        if run_a != run_b:
            return 1 if run_a > run_b else -1

    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


def _split(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    head, colon, rest = version.partition(":")
    if colon and head.isdigit():
        epoch, version = int(head), rest
    upstream, dash, release = version.rpartition("-")
    if not dash:
        upstream, release = version, ""
    return epoch, upstream, release


def compare(a: str, b: str) -> int:
    """Negative, zero or positive as ``a`` sorts before, equal to or after ``b``."""
    ea, va, ra = _split(a)
    eb, vb, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpmvercmp(va, vb) or _rpmvercmp(ra, rb)
