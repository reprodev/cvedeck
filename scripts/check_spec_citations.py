#!/usr/bin/env python3
"""Verify the spec-citation invariant that AGENTS.md section 0 claims.

Two directions, both mechanically checkable, which is the whole point:

  * Every ``Req X.Y`` and ``Property N`` reference in the source resolves to
    something that exists in the spec. A citation pointing at nothing is worse
    than no citation: a reader who follows one and finds a dead end stops
    trusting all of them.

  * Every acceptance criterion is cited somewhere. This is the direction that
    quietly failed for a long time -- Requirements 1 to 7 carried all 240
    citations while the eight added later carried none, so the convention
    looked complete while covering less than half the spec.

Two parsing subtleties worth keeping, because getting either wrong produces a
confidently wrong answer:

  * Citations are written in groups: ``(Req 4.1, 4.3, 5.1)`` is three
    references, not one. A regex requiring a ``Req`` prefix per pair reads it as
    one and undercounts by roughly half.

  * A bare ``Req N`` with no sub-number is also a reference. Missing that form
    is how a renumbering once broke Requirement 15.6's cross-reference without
    anything noticing.

Exit status is 0 when the invariant holds, 1 when it does not, so this is
usable from a hook.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REQUIREMENTS = REPO / ".kiro" / "specs" / "cvedeck" / "requirements.md"
DESIGN = REPO / ".kiro" / "specs" / "cvedeck" / "design.md"

SOURCE_SUFFIXES = {".py", ".ts", ".tsx"}
SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".hypothesis", "dist", "dist-ssr", ".git", ".vite",
}

# A whole citation group: "Req 4.1, 4.3, 5.1", "Req 5.2-5.4", "Req 2", "Req 10".
GROUP_RE = re.compile(
    r"Req\.?\s*((?:\d+(?:\.\d+)?)(?:\s*[,–-]\s*\d+(?:\.\d+)?)*)"
)
PROPERTY_RE = re.compile(r"Property\s+(\d+)")


def parse_criteria(text: str) -> dict[int, int]:
    """Map each requirement number to its highest acceptance-criterion number."""
    criteria: dict[int, int] = {}
    current: int | None = None
    for line in text.splitlines():
        heading = re.match(r"^###\s+Requirement\s+(\d+)\b", line)
        if heading:
            current = int(heading.group(1))
            criteria[current] = 0
            continue
        if current is not None:
            item = re.match(r"^\s*(\d+)\.\s", line)
            if item:
                criteria[current] = max(criteria[current], int(item.group(1)))
    return criteria


def parse_properties(text: str) -> set[int]:
    return {int(n) for n in re.findall(r"^###\s+Property\s+(\d+)", text, re.M)}


def expand(group: str) -> list[tuple[int, int | None]]:
    """Expand one citation group into (requirement, criterion) pairs.

    A token without a dot is a whole-requirement reference and yields
    ``(n, None)``.
    """
    pairs: list[tuple[int, int | None]] = []
    for token in re.split(r"\s*[,–-]\s*", group.strip()):
        if not token:
            continue
        if "." in token:
            req, crit = token.split(".", 1)
            pairs.append((int(req), int(crit)))
        else:
            pairs.append((int(token), None))
    return pairs


def source_files() -> list[Path]:
    """Source and test files, plus the spec documents themselves.

    The spec is included because its own cross-references are citations too,
    and one of them has been wrong before.
    """
    found: list[Path] = []
    for path in REPO.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in SOURCE_SUFFIXES:
            found.append(path)
        elif path.suffix == ".md" and ".kiro" in path.parts:
            found.append(path)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet", action="store_true",
        help="print nothing unless the invariant is broken",
    )
    args = parser.parse_args()

    if not REQUIREMENTS.exists() or not DESIGN.exists():
        print(f"spec not found at {REQUIREMENTS.parent}", file=sys.stderr)
        return 1

    criteria = parse_criteria(REQUIREMENTS.read_text(encoding="utf-8"))
    properties = parse_properties(DESIGN.read_text(encoding="utf-8"))

    cited: set[tuple[int, int | None]] = set()
    dangling: list[str] = []
    references = 0
    per_requirement: Counter[int] = Counter()

    for path in source_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(REPO).as_posix()
        in_spec = ".kiro" in path.parts

        for group in GROUP_RE.findall(text):
            for req, crit in expand(group):
                references += 1
                if not in_spec:
                    cited.add((req, crit))
                    per_requirement[req] += 1
                if req not in criteria:
                    dangling.append(
                        f"{rel}: 'Req {group}' -- there is no Requirement {req}"
                    )
                elif crit is not None and crit > criteria[req]:
                    dangling.append(
                        f"{rel}: 'Req {req}.{crit}' -- Requirement {req} has only "
                        f"{criteria[req]} acceptance criteria"
                    )

        for n in PROPERTY_RE.findall(text):
            if int(n) not in properties:
                dangling.append(f"{rel}: 'Property {n}' -- no such property")

    uncited: list[str] = []
    for req in sorted(criteria):
        whole = (req, None) in cited
        if whole:
            continue
        have = {c for (r, c) in cited if r == req and c is not None}
        missing = [c for c in range(1, criteria[req] + 1) if c not in have]
        if missing:
            uncited.append(
                f"Requirement {req}: " + ", ".join(f"{req}.{c}" for c in missing)
            )

    broken = bool(dangling or uncited)

    if broken:
        if dangling:
            print(f"\n{len(dangling)} citation(s) point at nothing:\n", file=sys.stderr)
            for line in dangling:
                print(f"  {line}", file=sys.stderr)
        if uncited:
            print(
                f"\n{len(uncited)} requirement(s) have criteria cited nowhere in "
                "the code:\n", file=sys.stderr,
            )
            for line in uncited:
                print(f"  {line}", file=sys.stderr)
            print(
                "\n  Cite each at the place that implements it, or remove it from\n"
                "  the spec. AGENTS.md section 0 claims this holds.\n",
                file=sys.stderr,
            )
        return 1

    if not args.quiet:
        total_criteria = sum(criteria.values())
        print(
            f"Spec citations OK: {references} references, "
            f"{total_criteria} criteria across {len(criteria)} requirements, "
            f"{len(properties)} properties. Nothing dangling, nothing uncited."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
