"""The backend and frontend must agree on the severity bands, and their order.

``SEVERITY_RANK`` in ``app/enums.py`` calls itself "the single definition of the
order" and names ``frontend/src/lib/severity.ts`` as its mirror. Nothing enforced
that. Reorder one side, or add a band to one side, and every suite stayed green
while the dashboard ranked findings differently from the API that served them
(Req 10.11).

This is a backend test reading TypeScript rather than a vitest file reading
Python, for three reasons: the definition of record lives here, so its guard
belongs here; ``scripts/check_spec_citations.py`` already establishes the house
precedent for Python parsing ``.ts``/``.tsx`` by regex; and the Dockerfile builds
``frontend/`` in isolation, so a frontend test reaching into ``backend/`` could
not run in the one context that proves the dashboard stands alone.

It parses rather than executes. Importing the TypeScript would mean a Node
round-trip in a Python suite, and the thing being guarded is a literal list that
a regex reads perfectly well.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.enums import SEVERITY_RANK, Severity

_FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "src"
_TYPES_TS = _FRONTEND / "types.ts"
_SEVERITY_TS = _FRONTEND / "lib" / "severity.ts"


def _backend_order() -> list[str]:
    """Severity values, lowest rank number first."""
    return [s.value for s, _ in sorted(SEVERITY_RANK.items(), key=lambda kv: kv[1])]


def _parse_severities_array(text: str) -> list[str]:
    """The string literals of ``export const SEVERITIES: ... = [ ... ];``."""
    match = re.search(
        r"export const SEVERITIES\s*:[^=]*=\s*\[(.*?)\]\s*;", text, re.DOTALL
    )
    assert match, "SEVERITIES array not found in types.ts"
    return re.findall(r'"([^"]+)"', match.group(1))


def _parse_severity_union(text: str) -> list[str]:
    """The members of ``export type Severity = "a" | "b" | ...;``."""
    match = re.search(r"export type Severity\s*=\s*([^;]+);", text, re.DOTALL)
    assert match, "Severity union type not found in types.ts"
    return re.findall(r'"([^"]+)"', match.group(1))


@pytest.fixture(scope="module")
def types_ts() -> str:
    assert _TYPES_TS.is_file(), f"expected {_TYPES_TS} to exist"
    return _TYPES_TS.read_text(encoding="utf-8")


def test_the_severity_union_matches_the_backend_enum(types_ts):
    """Same members, in the same order, with the same string values."""
    assert _parse_severity_union(types_ts) == _backend_order()


def test_the_severities_array_matches_the_backend_rank_order(types_ts):
    """SEVERITIES is the frontend's ranking, so its order is load-bearing.

    Column order in the fleet table and chip order in the filters both come
    from this array, and the backend orders SQL by SEVERITY_RANK.
    """
    assert _parse_severities_array(types_ts) == _backend_order()


def test_no_severity_is_missing_from_either_side(types_ts):
    """Stated separately from order, because the failure reads differently.

    A missing member is a band the dashboard cannot render at all; a reordered
    one is a band it renders in the wrong place.
    """
    frontend = set(_parse_severities_array(types_ts))
    backend = {s.value for s in Severity}
    assert frontend == backend, (
        f"only in the frontend: {sorted(frontend - backend)}; "
        f"only in the backend: {sorted(backend - frontend)}"
    )


def test_the_frontend_derives_its_rank_from_that_one_array():
    """`SEVERITY_RANK` in severity.ts must not be a second hand-written list.

    It is built from SEVERITIES, so the order is defined once on that side too.
    A literal object there would be a fourth place to keep in step.
    """
    text = _SEVERITY_TS.read_text(encoding="utf-8")
    match = re.search(
        r"export const SEVERITY_RANK[^=]*=\s*(.*?);", text, re.DOTALL
    )
    assert match, "SEVERITY_RANK not found in lib/severity.ts"
    body = match.group(1)
    assert "SEVERITIES" in body, (
        "SEVERITY_RANK should be derived from SEVERITIES, not written out again"
    )
    # No hand-written band names, which would drift independently.
    assert not re.search(r'"(critical|high|medium|low|unscored)"', body)


def test_unscored_ranks_between_critical_and_high(types_ts):
    """The one ordering decision worth pinning by name (Req 10.11).

    An unmeasured finding could be either, so ranking it with the least severe
    would be the same quiet all-clear that a substituted score of 5.0 was.
    """
    order = _parse_severities_array(types_ts)
    assert order.index("critical") < order.index("unscored") < order.index("high")
    assert order == _backend_order()
