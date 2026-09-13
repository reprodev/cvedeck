"""Scaffold verification: the package imports and the tooling is wired up.

This confirms task 1.1 acceptance: the backend package layout imports cleanly,
pytest collects, and the Hypothesis min-100-iterations profile is active.
"""

from hypothesis import settings, strategies as st, given

import app
from app import api, data, scanner


def test_package_layout_imports():
    """Every top-level backend package imports without error."""
    assert app.__version__ == "0.1.0"
    assert api is not None
    assert data is not None
    assert scanner is not None


def test_hypothesis_profile_enforces_min_100_iterations():
    """The active Hypothesis profile runs at least 100 examples."""
    assert settings().max_examples >= 100


@given(st.integers())
def test_property_scaffold_runs(value):
    """A trivial property test collects and executes under the profile."""
    assert value == value
