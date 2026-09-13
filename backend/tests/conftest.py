"""Shared pytest fixtures and Hypothesis configuration.

Property-based tests for this feature run a minimum of 100 iterations each,
per the design's testing strategy. Hypothesis settings live in code (rather
than pyproject.toml) because Hypothesis reads registered profiles, not the
`[tool.hypothesis]` table.
"""

from hypothesis import HealthCheck, settings

# Feature-wide profile: enforce the minimum 100 iterations for property tests.
settings.register_profile(
    "cvedeck",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

# Activate the feature profile by default for the whole test run.
settings.load_profile("cvedeck")
