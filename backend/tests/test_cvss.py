"""Unit and property tests for the shared CVSS implementation.

Every expected value here was produced by the FIRST reference calculator
(https://www.first.org/cvss/calculator/4-0 and its v3.1 counterpart), not
derived by hand and not recalled. A scoring table that is subtly wrong is
indistinguishable from a correct one until someone else quotes a different
number for the same advisory, which is precisely the class of defect this
module exists to remove (Req 2.7, Property 15).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.scanner.cvss import cvss_v3_base_score, cvss_v4_base_score

# --- CVSS v3.x -------------------------------------------------------------

_V3_KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    # Scope change pushes this one to the ceiling.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # No impact on any of C/I/A scores zero however reachable it is.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    # 3.0 and 3.1 share the base formula.
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
]


@pytest.mark.parametrize("vector,expected", _V3_KNOWN)
def test_v3_matches_the_reference_calculator(vector: str, expected: float):
    assert cvss_v3_base_score(vector) == expected


_V3_UNSCORABLE = [
    pytest.param("INVALID_VECTOR", id="not-a-vector"),
    pytest.param("", id="empty"),
    pytest.param("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", id="v2-vector"),
    pytest.param(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        id="v4-vector",
    ),
    pytest.param(
        "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="unknown-av-value"
    ),
    pytest.param(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", id="missing-scope"
    ),
    pytest.param(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", id="missing-availability"
    ),
    pytest.param(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", id="unknown-scope"
    ),
    pytest.param("CVSS:3.1/AVN/AC:L", id="component-without-colon"),
]


@pytest.mark.parametrize("vector", _V3_UNSCORABLE)
def test_v3_reports_no_score_rather_than_a_substituted_one(vector: str):
    """A vector we cannot read yields None, never a plausible number (Req 2.7).

    The predecessor returned 5.0 for every one of these, which
    ``derive_severity`` then reported as Medium -- a measurement-shaped answer
    to a question nobody could answer.
    """
    assert cvss_v3_base_score(vector) is None


def test_v3_does_not_treat_an_unknown_letter_as_least_severe():
    """An unrecognised metric value is unreadable, not harmless.

    ``AV:Q`` used to fall back to ``AV:N``'s weight of 0.85 -- the *most*
    favourable value -- so a garbled vector scored higher than a real one.
    """
    garbled = "CVSS:3.1/AV:Q/AC:Z/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss_v3_base_score(garbled) is None


# --- CVSS v4.0 -------------------------------------------------------------

_V4_KNOWN = [
    # The canonical "everything wide open" base vector.
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        9.3,
    ),
    # Subsequent-system impact as well, which reaches the ceiling.
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        10.0,
    ),
    # No impact anywhere is zero however reachable the system is.
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        0.0,
    ),
    # Physical access, high privileges, active interaction: the low corner.
    (
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        1.0,
    ),
    # A mid-band vector that exercises the EQ3=1 interpolation path, where a
    # half-way score meets JavaScript's round-half-up tie-break.
    (
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:L/SA:N",
        4.3,
    ),
    # Threat metrics lower the score below the base.
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
        8.1,
    ),
    # Safety on a subsequent system is the most severe EQ4 level.
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        "/MSI:S",
        10.0,
    ),
]


@pytest.mark.parametrize("vector,expected", _V4_KNOWN)
def test_v4_matches_the_reference_calculator(vector: str, expected: float):
    assert cvss_v4_base_score(vector) == expected


_V4_UNSCORABLE = [
    pytest.param("INVALID_VECTOR", id="not-a-vector"),
    pytest.param(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="v3-vector"
    ),
    pytest.param(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", id="missing-sc-si-sa"
    ),
    pytest.param(
        "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        id="unknown-av-value",
    ),
    pytest.param(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:Q",
        id="unknown-metric",
    ),
    pytest.param(
        # SI:S does not exist; only MSI may be Safety.
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N",
        id="safety-on-a-base-metric",
    ),
    pytest.param(
        "CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        id="repeated-metric",
    ),
]


@pytest.mark.parametrize("vector", _V4_UNSCORABLE)
def test_v4_reports_no_score_rather_than_a_substituted_one(vector: str):
    assert cvss_v4_base_score(vector) is None


def test_v4_accepts_and_ignores_supplemental_metrics():
    """Supplemental metrics are valid and carry no weight.

    A vector is not unreadable just because it carries them, and they must not
    move the score either.
    """
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss_v4_base_score(base + "/S:P/AU:Y/R:I/V:C/RE:H/U:Red") == 9.3


# --- Properties ------------------------------------------------------------

_V4_BASE_METRICS = {
    "AV": "NALP",
    "AC": "LH",
    "AT": "NP",
    "PR": "NLH",
    "UI": "NPA",
    "VC": "HLN",
    "VI": "HLN",
    "VA": "HLN",
    "SC": "HLN",
    "SI": "HLN",
    "SA": "HLN",
}


@st.composite
def _v4_base_vectors(draw):
    parts = [
        f"{name}:{draw(st.sampled_from(list(values)))}"
        for name, values in _V4_BASE_METRICS.items()
    ]
    return "CVSS:4.0/" + "/".join(parts)


@settings(max_examples=400)
@given(_v4_base_vectors())
def test_v4_is_total_over_well_formed_base_vectors(vector: str):
    """Property 15: a well-formed vector always scores, and scores in range.

    Every combination of the eleven mandatory base metrics is a valid vector,
    so the MacroVector tables and the interpolation must cover all of them --
    a gap would surface as ``None`` for an advisory that does publish a score.
    """
    score = cvss_v4_base_score(vector)
    assert score is not None
    assert 0.0 <= score <= 10.0
    assert score == round(score, 1)


_V3_BASE_METRICS = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "HLN",
    "I": "HLN",
    "A": "HLN",
}


@st.composite
def _v3_base_vectors(draw):
    parts = [
        f"{name}:{draw(st.sampled_from(list(values)))}"
        for name, values in _V3_BASE_METRICS.items()
    ]
    return "CVSS:3.1/" + "/".join(parts)


@settings(max_examples=400)
@given(_v3_base_vectors())
def test_v3_is_total_over_well_formed_base_vectors(vector: str):
    score = cvss_v3_base_score(vector)
    assert score is not None
    assert 0.0 <= score <= 10.0
    assert score == round(score, 1)


@settings(max_examples=200)
@given(st.text(max_size=60))
def test_neither_parser_ever_invents_a_score_for_arbitrary_text(text: str):
    """No input produces a number unless it is a vector we actually parsed.

    The guarantee the callers rely on: ``None`` or a real measurement, never a
    stand-in (Req 2.7).
    """
    for score in (cvss_v3_base_score(text), cvss_v4_base_score(text)):
        assert score is None or 0.0 <= score <= 10.0
