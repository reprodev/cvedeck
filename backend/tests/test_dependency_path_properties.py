"""Property-based tests for the dependency-path association persistence.

Feature: cvedeck
Property 11: Dependency-path association round-trip
Validates: Requirements 5.5, 7.2

For any CVE finding that carries a dependency-path association, persisting and
reading it back preserves the association linking the CVE to its software
dependencies (package_identifier) and application path (path_expression),
including the parent-path chain, on the target machine.
"""

from datetime import datetime, timezone

from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.schema import (
    Base,
    CveFinding,
    DependencyPath,
    TargetMachine,
)
from app.enums import Platform, ScanStatus, Severity, SyncStatus

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Non-empty printable text for identifiers / expressions (avoid surrogates and
# control characters that SQLite text columns cannot round-trip cleanly).
_text = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x10FFFF, blacklist_categories=("Cs",)),
    min_size=1,
    max_size=40,
)

_optional_text = st.one_of(st.none(), _text)

_severity = st.sampled_from(list(Severity))
_sync_status = st.sampled_from(list(SyncStatus))
_platform = st.sampled_from(list(Platform))
_scan_status = st.sampled_from(list(ScanStatus))


@st.composite
def dependency_path_finding(draw):
    """An arbitrary CveFinding linked to an arbitrary dependency-path chain.

    The chain is a leaf DependencyPath that optionally has a parent
    DependencyPath (modeling e.g. app -> libA). The finding's
    dependency_path_id points at the leaf.
    """
    has_parent = draw(st.booleans())

    parent = None
    if has_parent:
        parent = {
            "id": "dp_parent",
            "package_identifier": draw(_optional_text),
            "path_expression": draw(_optional_text),
            "parent_path_id": None,
            "sync_status": draw(_sync_status),
        }

    leaf = {
        "id": "dp_leaf",
        "package_identifier": draw(_optional_text),
        "path_expression": draw(_optional_text),
        "parent_path_id": "dp_parent" if has_parent else None,
        "sync_status": draw(_sync_status),
    }

    finding = {
        "id": "f1",
        "cve_id": draw(_text),
        "cvss_score": draw(
            st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)
        ),
        "severity": draw(_severity),
        "source": draw(st.sampled_from(["nvd", "osv"])),
        "package_identifier": draw(_optional_text),
        "dependency_path_id": "dp_leaf",
        "sync_status": draw(_sync_status),
    }

    machine = {
        "id": "m1",
        "hostname": draw(_text),
        "platform": draw(_platform),
        "last_scan_status": draw(_scan_status),
        "sync_status": draw(_sync_status),
    }

    return {"machine": machine, "parent": parent, "leaf": leaf, "finding": finding}


# ---------------------------------------------------------------------------
# Property 11
# ---------------------------------------------------------------------------


@given(data=dependency_path_finding())
def test_property_11_dependency_path_association_round_trip(data):
    """Property 11 (Requirements 5.5, 7.2): a CVE finding's dependency-path
    association survives a persist -> read-back cycle unchanged.
    """
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)

    # Fresh isolated in-memory database per example.
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    m = data["machine"]
    leaf = data["leaf"]
    parent = data["parent"]
    f = data["finding"]

    with Session(engine) as session:
        session.add(
            TargetMachine(
                id=m["id"],
                hostname=m["hostname"],
                platform=m["platform"],
                last_scan_status=m["last_scan_status"],
                last_scanned_at=now,
                sync_status=m["sync_status"],
            )
        )
        if parent is not None:
            session.add(
                DependencyPath(
                    id=parent["id"],
                    machine_id=m["id"],
                    package_identifier=parent["package_identifier"],
                    path_expression=parent["path_expression"],
                    parent_path_id=parent["parent_path_id"],
                    sync_status=parent["sync_status"],
                )
            )
        session.add(
            DependencyPath(
                id=leaf["id"],
                machine_id=m["id"],
                package_identifier=leaf["package_identifier"],
                path_expression=leaf["path_expression"],
                parent_path_id=leaf["parent_path_id"],
                sync_status=leaf["sync_status"],
            )
        )
        session.add(
            CveFinding(
                id=f["id"],
                machine_id=m["id"],
                cve_id=f["cve_id"],
                cvss_score=f["cvss_score"],
                severity=f["severity"],
                source=f["source"],
                package_identifier=f["package_identifier"],
                dependency_path_id=f["dependency_path_id"],
                sync_status=f["sync_status"],
            )
        )
        session.commit()

    with Session(engine) as session:
        loaded = session.get(CveFinding, f["id"])

        # The association FK linking the CVE to its dependency path is preserved.
        assert loaded is not None
        assert loaded.dependency_path_id == leaf["id"]

        # The linked DependencyPath resolves and its identifying fields survive.
        dp = loaded.dependency_path
        assert dp is not None
        assert dp.id == leaf["id"]
        assert dp.package_identifier == leaf["package_identifier"]
        assert dp.path_expression == leaf["path_expression"]
        assert dp.parent_path_id == leaf["parent_path_id"]

        # The parent chain (application path linkage) is preserved when present.
        if parent is None:
            assert dp.parent_path is None
        else:
            assert dp.parent_path is not None
            assert dp.parent_path.id == parent["id"]
            assert dp.parent_path.package_identifier == parent["package_identifier"]
            assert dp.parent_path.path_expression == parent["path_expression"]
            assert dp.parent_path.parent_path_id is None
