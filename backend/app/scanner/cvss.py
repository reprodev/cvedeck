"""CVSS base-score computation for v3.x and v4.0 vector strings.

One CVSS implementation, shared by every data-source client, so that NVD and
OSV cannot disagree about what a vector is worth.

Both entry points return ``None`` rather than a number when the vector cannot
be scored -- a wrong prefix, a missing mandatory metric, an unrecognised metric
value, or any arithmetic that fails. That is the whole point of this module's
contract: an unparseable vector is an *absence of a score*, and substituting a
plausible mid-range number for it produces a finding that competes for
attention with measured ones while carrying no measurement at all. The callers
turn ``None`` into an absent score and an ``UNSCORED`` severity (Req 2.7);
nothing in this module may invent a value on their behalf.

The v4.0 implementation is a port of the FIRST reference calculator
(https://github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause), which is
normative where the specification's prose is ambiguous. Its structure is kept
deliberately close to the JavaScript original -- including the
next-lower-MacroVector quirks in :func:`_eq3eq6_next_lower_score` -- so the two
can be diffed by eye when the reference is revised.
"""

from __future__ import annotations

import math
from typing import Final

__all__ = ["cvss_v3_base_score", "cvss_v4_base_score"]


class _UnscorableVector(Exception):
    """A vector that cannot be scored: bad syntax, or an unknown metric value.

    Raised internally and converted to ``None`` at the module boundary. It
    exists so that a missing metric and an unrecognised letter fail the same
    way as a syntax error, rather than quietly taking a default (Req 2.7).
    """


def _parse_vector(vector: str) -> dict[str, str]:
    """Split a ``A:B/C:D`` vector string into a metric map.

    Rejects an empty component or one without a colon. A repeated metric is
    also rejected: the specification allows each metric at most once, and
    silently keeping the last occurrence would score a malformed vector.
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if not part:
            raise _UnscorableVector(f"empty component in {vector!r}")
        name, separator, value = part.partition(":")
        if not separator or not name or not value:
            raise _UnscorableVector(f"malformed component {part!r}")
        if name in metrics:
            raise _UnscorableVector(f"repeated metric {name!r}")
        metrics[name] = value
    return metrics


def _level(table: dict[str, float], metrics: dict[str, str], name: str) -> float:
    """Look up one metric's numeric level, raising if it is missing or unknown.

    The predecessor of this function used ``dict.get(name, default)`` twice
    over, so both an absent metric and an unrecognised letter silently took the
    most favourable value -- an unknown ``AV`` scored as ``AV:N``. A vector we
    cannot read is not a vector that reads as least severe.
    """
    try:
        value = metrics[name]
    except KeyError:
        raise _UnscorableVector(f"missing metric {name!r}") from None
    try:
        return table[value]
    except KeyError:
        raise _UnscorableVector(f"unknown value {value!r} for {name!r}") from None


# --- CVSS v3.x -------------------------------------------------------------

_V3_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
_V3_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
_V3_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.50}
_V3_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}


def _round_half_up(value: float) -> int:
    """Round to the nearest integer, halves away from zero.

    Python's built-in ``round`` rounds halves to even, so ``round(42.5)`` is
    42 while every other CVSS implementation -- the reference calculator
    included, via JavaScript's ``Math.round`` -- yields 43. Scoring a vector
    0.1 below everyone else is a disagreement about a published number, so the
    tie-break is spelled out here rather than inherited.
    """
    return math.floor(value + 0.5) if value >= 0 else math.ceil(value - 0.5)


def _roundup(value: float) -> float:
    """The CVSS v3.1 Roundup function (specification section 7.1).

    Not ``math.ceil(value * 10) / 10``: that rounds 4.02 up to 4.1 when the
    binary representation of an intermediate product lands a hair above 4.0.
    The specification defines Roundup over an integer scaled by 100000 for
    exactly this reason.
    """
    scaled = _round_half_up(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_v3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string.

    Implements the v3.1 base formula (specification section 7.1) over the eight
    mandatory base metrics. Temporal and environmental metrics, if present, are
    ignored -- this is the *base* score.

    Args:
        vector: A vector such as ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``.

    Returns:
        The base score rounded to one decimal, or ``None`` if the vector does
        not carry a ``CVSS:3.`` prefix, omits a mandatory base metric, or names
        a value the specification does not define (Req 2.7).
    """
    if not vector.startswith("CVSS:3."):
        return None

    try:
        metrics = _parse_vector(vector)

        scope = metrics.get("S")
        if scope not in ("U", "C"):
            raise _UnscorableVector(f"unknown or missing scope {scope!r}")

        av = _level(_V3_AV, metrics, "AV")
        ac = _level(_V3_AC, metrics, "AC")
        ui = _level(_V3_UI, metrics, "UI")
        pr = _level(
            _V3_PR_CHANGED if scope == "C" else _V3_PR_UNCHANGED, metrics, "PR"
        )
        conf = _level(_V3_CIA, metrics, "C")
        integ = _level(_V3_CIA, metrics, "I")
        avail = _level(_V3_CIA, metrics, "A")

        iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui
        if scope == "U":
            return _roundup(min(impact + exploitability, 10.0))
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    except _UnscorableVector:
        return None
    except (ArithmeticError, ValueError):
        return None


# --- CVSS v4.0 -------------------------------------------------------------
#
# v4.0 base scoring is not a closed-form formula. The vector is reduced to a
# six-digit "MacroVector" (one digit per equivalence set), the MacroVector's
# score is read from a published table of 270 values, and the result is then
# interpolated downwards by how far the vector sits from the most severe vector
# its MacroVector can contain. See specification sections 8.1-8.2.

# Accepted values per metric. A metric absent from this map is not a v4.0
# metric and makes the vector unscorable; a value absent from its set does the
# same. Supplemental metrics (S, AU, R, V, RE, U) are accepted and ignored:
# they carry no weight in any score.
_V4_VALUES: Final[dict[str, frozenset[str]]] = {
    # Base: exploitability
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "AT": frozenset("NP"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NPA"),
    # Base: vulnerable-system and subsequent-system impact
    "VC": frozenset("HLN"),
    "VI": frozenset("HLN"),
    "VA": frozenset("HLN"),
    "SC": frozenset("HLN"),
    "SI": frozenset("HLN"),
    "SA": frozenset("HLN"),
    # Threat
    "E": frozenset({"X", "A", "P", "U"}),
    # Environmental: security requirements
    "CR": frozenset({"X", "H", "M", "L"}),
    "IR": frozenset({"X", "H", "M", "L"}),
    "AR": frozenset({"X", "H", "M", "L"}),
    # Environmental: modified base
    "MAV": frozenset({"X", "N", "A", "L", "P"}),
    "MAC": frozenset({"X", "L", "H"}),
    "MAT": frozenset({"X", "N", "P"}),
    "MPR": frozenset({"X", "N", "L", "H"}),
    "MUI": frozenset({"X", "N", "P", "A"}),
    "MVC": frozenset({"X", "H", "L", "N"}),
    "MVI": frozenset({"X", "H", "L", "N"}),
    "MVA": frozenset({"X", "H", "L", "N"}),
    "MSC": frozenset({"X", "H", "L", "N"}),
    # MSI and MSA alone may be "S" (Safety); there is no base SI:S or SA:S.
    "MSI": frozenset({"X", "S", "H", "L", "N"}),
    "MSA": frozenset({"X", "S", "H", "L", "N"}),
    # Supplemental: parsed, validated, and deliberately unused.
    "S": frozenset({"X", "N", "P"}),
    "AU": frozenset({"X", "N", "Y"}),
    "R": frozenset({"X", "A", "U", "I"}),
    "V": frozenset({"X", "D", "C"}),
    "RE": frozenset({"X", "L", "M", "H"}),
    "U": frozenset({"X", "Clear", "Green", "Amber", "Red"}),
}

_V4_MANDATORY: Final[tuple[str, ...]] = (
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
)

# Severity-distance levels: the ordinal position of each value within its
# metric, scaled by 0.1. Used only for the interpolation in _v4_score.
_V4_LEVELS: Final[dict[str, dict[str, float]]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

# The most severe vector(s) each equivalence-set level can contain, from the
# reference calculator's max_composed.js. eq3 is keyed by eq6 as well, because
# the two sets are not independent.
_V4_MAX_COMPOSED_EQ1: Final[dict[int, tuple[str, ...]]] = {
    0: ("AV:N/PR:N/UI:N/",),
    1: ("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"),
    2: ("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"),
}
_V4_MAX_COMPOSED_EQ2: Final[dict[int, tuple[str, ...]]] = {
    0: ("AC:L/AT:N/",),
    1: ("AC:H/AT:N/", "AC:L/AT:P/"),
}
_V4_MAX_COMPOSED_EQ3EQ6: Final[dict[int, dict[int, tuple[str, ...]]]] = {
    0: {
        0: ("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",),
        1: (
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ),
    },
    1: {
        0: (
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ),
        1: (
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ),
    },
    2: {1: ("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",)},
}
_V4_MAX_COMPOSED_EQ4: Final[dict[int, tuple[str, ...]]] = {
    0: ("SC:H/SI:S/SA:S/",),
    1: ("SC:H/SI:H/SA:H/",),
    2: ("SC:L/SI:L/SA:L/",),
}
_V4_MAX_COMPOSED_EQ5: Final[dict[int, tuple[str, ...]]] = {
    0: ("E:A/",),
    1: ("E:P/",),
    2: ("E:U/",),
}

# Maximum severity distance within each equivalence-set level, from the
# reference calculator's max_severity.js. Multiplied by 0.1 in use.
_V4_MAX_SEVERITY_EQ1: Final[dict[int, int]] = {0: 1, 1: 4, 2: 5}
_V4_MAX_SEVERITY_EQ2: Final[dict[int, int]] = {0: 1, 1: 2}
_V4_MAX_SEVERITY_EQ3EQ6: Final[dict[int, dict[int, int]]] = {
    0: {0: 7, 1: 6},
    1: {0: 8, 1: 8},
    2: {1: 10},
}
_V4_MAX_SEVERITY_EQ4: Final[dict[int, int]] = {0: 6, 1: 5, 2: 4}

# The published MacroVector scores (specification section 8.2), transcribed
# from the reference calculator's cvss_lookup.js. 270 entries; a MacroVector
# absent from this table does not exist.
_V4_MACROVECTOR_SCORES: Final[dict[str, float]] = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8,
    "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5,
    "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
    "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
    "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
    "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4,
    "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
    "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
    "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
    "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
    "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
    "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
    "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4,
    "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
    "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1,
    "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5,
    "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1,
    "212211": 0.3, "212221": 0.1,
}


def _v4_metric(metrics: dict[str, str], name: str) -> str:
    """Resolve one metric's effective value, applying the v4.0 defaults.

    ``E:X`` means "not defined", which the specification scores as the worst
    case ``E:A``; likewise ``CR:X``/``IR:X``/``AR:X`` score as ``H``. Every
    other environmental metric overrides its base counterpart when it is set to
    something other than ``X``.
    """
    if name == "E":
        value = metrics.get("E", "X")
        return "A" if value == "X" else value
    if name in ("CR", "IR", "AR"):
        value = metrics.get(name, "X")
        return "H" if value == "X" else value
    modified = metrics.get("M" + name, "X")
    if modified != "X":
        return modified
    return metrics.get(name, "X")


def _v4_macrovector(metrics: dict[str, str]) -> str:
    """Reduce a v4.0 vector to its six-digit MacroVector (section 8.1)."""
    av = _v4_metric(metrics, "AV")
    pr = _v4_metric(metrics, "PR")
    ui = _v4_metric(metrics, "UI")

    # EQ1: how reachable the vulnerable system is.
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    # EQ2: how much has to go right for the attack to work.
    eq2 = 0 if (_v4_metric(metrics, "AC") == "L"
                and _v4_metric(metrics, "AT") == "N") else 1

    # EQ3: impact on the vulnerable system.
    vc = _v4_metric(metrics, "VC")
    vi = _v4_metric(metrics, "VI")
    va = _v4_metric(metrics, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    # EQ4: impact on subsequent systems, with Safety outranking everything.
    sc = _v4_metric(metrics, "SC")
    si = _v4_metric(metrics, "SI")
    sa = _v4_metric(metrics, "SA")
    if metrics.get("MSI") == "S" or metrics.get("MSA") == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    # EQ5: exploit maturity.
    exploit_maturity = _v4_metric(metrics, "E")
    eq5 = {"A": 0, "P": 1, "U": 2}[exploit_maturity]

    # EQ6: whether a high security requirement lands on a high impact.
    if (
        (_v4_metric(metrics, "CR") == "H" and vc == "H")
        or (_v4_metric(metrics, "IR") == "H" and vi == "H")
        or (_v4_metric(metrics, "AR") == "H" and va == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _eq3eq6_next_lower_score(eq: tuple[int, int, int, int, int, int]) -> float | None:
    """Score of the next lower MacroVector along the joined EQ3/EQ6 axis.

    EQ3 and EQ6 are not independent, so stepping "one down" from 00 can go two
    ways and the specification takes whichever scores higher. The comparison
    below reproduces the reference implementation exactly, including its
    behaviour when one branch does not exist: JavaScript's ``undefined > x`` is
    false, so a missing left branch yields the right one and a missing *right*
    branch yields ``undefined`` even when the left exists. Faithfulness beats
    tidiness here -- this module's output has to agree with the calculator
    everyone else checks against.
    """
    eq1, eq2, eq3, eq4, eq5, eq6 = eq
    lookup = _V4_MACROVECTOR_SCORES

    if eq3 == 0 and eq6 == 0:
        left = lookup.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = lookup.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        if left is not None and right is not None and left > right:
            return left
        return right
    if eq3 == 1 and eq6 == 0:
        return lookup.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    if (eq3, eq6) in ((0, 1), (1, 1)):
        return lookup.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    # eq3 == 2: stepping down would need 3x, which does not exist.
    return lookup.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")


def _severity_distance(
    metrics: dict[str, str], max_metrics: dict[str, str], names: tuple[str, ...]
) -> float | None:
    """Distance from a vector to one candidate most-severe vector.

    Returns ``None`` if the candidate is more severe than the vector in any
    metric, which means it is the wrong candidate and the caller should try the
    next one.
    """
    total = 0.0
    for name in names:
        levels = _V4_LEVELS[name]
        try:
            distance = levels[_v4_metric(metrics, name)] - levels[max_metrics[name]]
        except KeyError:
            return None
        if distance < 0:
            return None
        total += distance
    return total


_EQ1_METRICS: Final[tuple[str, ...]] = ("AV", "PR", "UI")
_EQ2_METRICS: Final[tuple[str, ...]] = ("AC", "AT")
_EQ3EQ6_METRICS: Final[tuple[str, ...]] = ("VC", "VI", "VA", "CR", "IR", "AR")
_EQ4_METRICS: Final[tuple[str, ...]] = ("SC", "SI", "SA")


def cvss_v4_base_score(vector: str) -> float | None:
    """Compute the CVSS v4.0 score from a vector string.

    Honours threat and environmental metrics when the vector carries them, so
    a CVSS-BTE vector scores as its author intended; a bare CVSS-B vector
    scores as the base score, since the v4.0 defaults for the metrics it omits
    are the base-score assumptions.

    Args:
        vector: A vector such as
            ``CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N``.

    Returns:
        The score rounded to one decimal, or ``None`` if the vector does not
        carry a ``CVSS:4.0`` prefix, omits a mandatory base metric, or names a
        metric or value the specification does not define (Req 2.7).
    """
    if not vector.startswith("CVSS:4.0"):
        return None

    try:
        metrics = _parse_vector(vector)
    except _UnscorableVector:
        return None

    # The prefix component is not a metric.
    metrics.pop("CVSS", None)

    for name, value in metrics.items():
        allowed = _V4_VALUES.get(name)
        if allowed is None or value not in allowed:
            return None
    for name in _V4_MANDATORY:
        if name not in metrics:
            return None

    # A vulnerability with no impact anywhere scores zero, whatever else the
    # vector says about how easy it is to reach (specification section 8.2).
    if all(
        _v4_metric(metrics, name) == "N"
        for name in ("VC", "VI", "VA", "SC", "SI", "SA")
    ):
        return 0.0

    macrovector = _v4_macrovector(metrics)
    value = _V4_MACROVECTOR_SCORES.get(macrovector)
    if value is None:
        return None

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macrovector)
    lookup = _V4_MACROVECTOR_SCORES

    # The maximal scoring difference along each axis: how far this MacroVector
    # sits above the next lower one. An axis with no lower MacroVector does not
    # contribute, and is excluded from the mean rather than counted as zero.
    available = {
        "eq1": lookup.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"),
        "eq2": lookup.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"),
        "eq3eq6": _eq3eq6_next_lower_score((eq1, eq2, eq3, eq4, eq5, eq6)),
        "eq4": lookup.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"),
        "eq5": lookup.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"),
    }

    # Find the first most-severe vector in this MacroVector that the scored
    # vector does not exceed in any metric, and measure the distance to it.
    distances: dict[str, float] | None = None
    for eq1_max in _V4_MAX_COMPOSED_EQ1[eq1]:
        for eq2_max in _V4_MAX_COMPOSED_EQ2[eq2]:
            for eq3eq6_max in _V4_MAX_COMPOSED_EQ3EQ6[eq3][eq6]:
                for eq4_max in _V4_MAX_COMPOSED_EQ4[eq4]:
                    for eq5_max in _V4_MAX_COMPOSED_EQ5[eq5]:
                        composed = _parse_vector(
                            (eq1_max + eq2_max + eq3eq6_max + eq4_max + eq5_max)
                            .rstrip("/")
                        )
                        candidate = {
                            "eq1": _severity_distance(
                                metrics, composed, _EQ1_METRICS
                            ),
                            "eq2": _severity_distance(
                                metrics, composed, _EQ2_METRICS
                            ),
                            "eq3eq6": _severity_distance(
                                metrics, composed, _EQ3EQ6_METRICS
                            ),
                            "eq4": _severity_distance(
                                metrics, composed, _EQ4_METRICS
                            ),
                        }
                        if all(d is not None for d in candidate.values()):
                            distances = {
                                key: d
                                for key, d in candidate.items()
                                if d is not None
                            }
                            break
                    if distances is not None:
                        break
                if distances is not None:
                    break
            if distances is not None:
                break
        if distances is not None:
            break

    if distances is None:
        # No most-severe vector dominates this one, which means the tables and
        # the MacroVector derivation disagree. Report no score rather than an
        # arbitrary one.
        return None

    step = 0.1
    max_severity = {
        "eq1": _V4_MAX_SEVERITY_EQ1[eq1] * step,
        "eq2": _V4_MAX_SEVERITY_EQ2[eq2] * step,
        "eq3eq6": _V4_MAX_SEVERITY_EQ3EQ6[eq3][eq6] * step,
        "eq4": _V4_MAX_SEVERITY_EQ4[eq4] * step,
    }

    normalized = 0.0
    existing_lower = 0
    for axis in ("eq1", "eq2", "eq3eq6", "eq4"):
        if available[axis] is None:
            continue
        existing_lower += 1
        proportion = distances[axis] / max_severity[axis]
        normalized += (value - available[axis]) * proportion
    if available["eq5"] is not None:
        # EQ5's proportion is always zero, so it contributes nothing but still
        # counts towards the mean -- which is what pulls the mean down.
        existing_lower += 1

    mean_distance = 0.0 if existing_lower == 0 else normalized / existing_lower

    score = value - mean_distance
    score = min(10.0, max(0.0, score))
    return _round_half_up(score * 10) / 10
