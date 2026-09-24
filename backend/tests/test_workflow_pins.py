"""The release pipeline trusts nothing that can be moved under it.

Every action a workflow runs is pinned to a full commit SHA. A tag such as
``@v7`` can be re-pointed by whoever controls the action's repository, and the
release job holds the token that publishes the image every user installs; a
SHA cannot be re-pointed. Checkouts do not leave the job's token in the
working tree, and the release builds without the cache CI writes.

A test rather than a comment, because a pin is exactly the kind of thing a
well-meaning edit -- "bump checkout to v8" -- quietly undoes. Read line by line
rather than with a YAML parser, which the project does not otherwise need; the
workflow files keep one step key per line, which is all this relies on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)")
_SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert files, f"no workflows found under {WORKFLOWS}"
    return files


def _steps(path: Path) -> list[str]:
    """Each step's text, split at every line that starts a list item."""
    steps: list[list[str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\s*-\s+(uses|name|run|id|if|with|env):", line):
            steps.append([line])
        elif steps:
            steps[-1].append(line)
    return ["\n".join(s) for s in steps]


def _uses(step: str) -> str | None:
    for line in step.splitlines():
        match = _USES.match(line)
        if match:
            return match.group(1)
    return None


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    used = [u for u in map(_uses, _steps(path)) if u and not u.startswith("./")]
    loose = [u for u in used if not _SHA_PIN.match(u)]

    assert used, f"{path.name}: found no actions -- is the parser still right?"
    assert not loose, f"{path.name}: pin these to a full commit SHA: {loose}"


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_checkout_does_not_keep_the_token(path):
    kept = [
        step.splitlines()[0].strip()
        for step in _steps(path)
        if (_uses(step) or "").startswith("actions/checkout@")
        and not re.search(r"^\s*persist-credentials:\s*false\s*$", step, re.M)
    ]
    assert not kept, f"{path.name}: set persist-credentials: false on {kept}"


def test_the_release_builds_cold_scans_and_attests():
    steps = _steps(WORKFLOWS / "release.yml")
    builds = [s for s in steps if (_uses(s) or "").startswith("docker/build-push-action@")]

    assert builds
    for build in builds:
        # The keys, not the words: the step's own comment names them.
        assert not re.search(r"^\s*cache-(from|to):", build, re.M), build
    assert any((_uses(s) or "").startswith("aquasecurity/trivy-action@") for s in steps)
    assert any((_uses(s) or "").startswith("actions/attest-build-provenance@") for s in steps)


def test_the_tag_input_never_reaches_a_shell_by_expansion():
    """A dispatch input is free text; ``${{ }}`` in a run block is code."""
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    run_blocks = re.findall(r"run: \|\n((?:\s{10,}.*\n?)+)", text)

    assert run_blocks
    for block in run_blocks:
        assert "${{" not in block, block
