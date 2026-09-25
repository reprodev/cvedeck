"""HTTP client for matching package inventory against the OSV.dev API.

Implements the :class:`~app.scanner.matcher.OsvClient` protocol. Connects to the
public OSV.dev REST API (https://api.osv.dev/v1), performs fast batch lookups to
identify vulnerable packages, queries full advisory details, and normalizes
records into :class:`~app.scanner.matcher.RawAdvisory` instances with resolved
CVE IDs, CVSS base scores, and package identifiers (Req 2.2, 2.3, 7.1).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from app.models import Package
from app.package_identifier import is_kernel_package, parse_package_name
from app.enums import SEVERITY_RANK, Severity
from app.scanner.cvss import (
    cvss_v3_base_score,
    cvss_v4_base_score,
)
from app.scanner.matcher import RawAdvisory, derive_severity
from app.scanner.releases import (
    Release,
    host_releases,
    in_family,
    parse_release,
    release_query_ecosystems,
)
from app.scanner.http_bounds import MIB, request_limited

_DEFAULT_OSV_API_URL = "https://api.osv.dev/v1"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_MAX_WORKERS = 25
_BATCH_CHUNK_SIZE = 500
# HTTP connection pool sizing for the live client (AGENTS.md matcher invariant:
# 50 keepalive / 100 max connections), sized to sustain _DEFAULT_MAX_WORKERS.
_DEFAULT_POOL_SIZE = 50

#: One OSV answer. The largest measured was 61 MB -- the kernel on Ubuntu 22.04
#: -- so this is a ceiling against an unbounded body, not a budget for honest
#: ones; see app/scanner/http_bounds.py (Req 10.18).
_MAX_OSV_RESPONSE = 256 * MIB


#: Qualitative severity words, longest-distinguishing substring first, mapped
#: to the band they name. These are what a feed publishes when it has an
#: opinion but no vector -- several distribution trackers never publish one.
_QUALITATIVE_BANDS: tuple[tuple[str, Severity], ...] = (
    ("CRIT", Severity.CRITICAL),
    ("HIGH", Severity.HIGH),
    ("MOD", Severity.MEDIUM),
    ("MED", Severity.MEDIUM),
    ("LOW", Severity.LOW),
)


def _qualitative_band(text: object) -> Severity | None:
    """The band a feed's severity word names, or ``None`` if it names none."""
    word = str(text or "").upper()
    for needle, band in _QUALITATIVE_BANDS:
        if needle in word:
            return band
    return None


def parse_cvss(vuln: dict[str, Any]) -> tuple[float | None, Severity | None]:
    """What an OSV record actually says about how bad a vulnerability is.

    Returns the published CVSS score and the published qualitative band, each
    ``None`` when the record does not carry it. The three shapes that come back
    are the three that exist in the data (Req 2.6, 2.7):

    - ``(score, None)`` -- a vector or numeric score was published.
    - ``(None, band)`` -- only a word: "HIGH", "Moderate". The band is real and
      is passed through; the number is *not* reconstructed from it. This branch
      used to return 8.0 for "HIGH", a figure no one published and which was
      then indistinguishable from a measured 8.0.
    - ``(None, None)`` -- the record says nothing about severity. Previously
      5.0, which read back as Medium.

    A vector that does not parse is skipped rather than substituted, so a
    record carrying both an unreadable vector and a usable word still yields
    the word.
    """
    # 1. Structured severity entries: a vector, or a bare number.
    severities = vuln.get("severity") or []
    if isinstance(severities, list):
        for sev in severities:
            if not isinstance(sev, dict):
                continue
            score_str = sev.get("score", "")
            if not isinstance(score_str, str):
                continue
            if score_str.startswith("CVSS:4."):
                parsed = cvss_v4_base_score(score_str)
                if parsed is not None:
                    return parsed, None
                continue
            if score_str.startswith("CVSS:3."):
                parsed = cvss_v3_base_score(score_str)
                if parsed is not None:
                    return parsed, None
                continue
            try:
                val = float(score_str)
            except (TypeError, ValueError):
                continue
            if 0.0 <= val <= 10.0:
                return val, None

    # 2. A qualitative severity, from the database-specific block or from the
    #    per-ecosystem block several distribution feeds use instead.
    db_spec = vuln.get("database_specific")
    if isinstance(db_spec, dict):
        band = _qualitative_band(db_spec.get("severity"))
        if band is not None:
            return None, band

    affected = vuln.get("affected") or []
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            eco_spec = entry.get("ecosystem_specific")
            if not isinstance(eco_spec, dict):
                continue
            band = _qualitative_band(eco_spec.get("severity"))
            if band is not None:
                return None, band

    # 3. The record says nothing. That is the answer (Req 2.7).
    return None, None


def _severity_rank(advisory: RawAdvisory) -> tuple[int, float]:
    """Order two advisories for the same CVE and package, worst first.

    Total, which is the point. The comparison this replaced was
    ``adv.cvss_score > existing.cvss_score``, and once a score may be absent
    that raises ``TypeError`` -- which ``Matcher`` classes as a defect rather
    than an outage and re-raises, so ``ScannerEngine``'s per-target fault
    isolation would report the host as a connection failure. A single
    CVSS:4.0-only advisory would have made a reachable host look unreachable.

    Ranks by band first so an unscored advisory is not silently outranked by
    any record that happens to carry a number (Req 10.11).
    """
    band = advisory.severity
    if band is None:
        band = (
            Severity.UNSCORED
            if advisory.cvss_score is None
            else derive_severity(advisory.cvss_score)
        )
    return SEVERITY_RANK[band], -(advisory.cvss_score or 0.0)


def _resolve_cve_id(vuln: dict[str, Any]) -> str:
    """Extract standard CVE identifier from OSV vuln ID, aliases, or upstream."""
    vid = str(vuln.get("id", ""))
    if vid.startswith("CVE-"):
        return vid

    # Check aliases
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias

    # Check upstream
    for upstream in vuln.get("upstream") or []:
        if isinstance(upstream, str) and upstream.startswith("CVE-"):
            return upstream

    # Match embedded CVE pattern (e.g. UBUNTU-CVE-2024-11053)
    match = re.search(r"CVE-\d{4}-\d+", vid)
    if match:
        return match.group(0)

    return vid


def _query_package(pkg: Package) -> Package:
    """The package to ask OSV about: the binary's source, at the source's version.

    The binary itself when no source was reported (an inventory from before
    0.8.15), and for the kernel, which is not yet looked up by source (Req 12.5).
    """
    if not pkg.source_name or is_kernel_package(pkg.name, pkg.source_name):
        return pkg
    return pkg.model_copy(
        update={"name": pkg.source_name, "version": pkg.source_version or pkg.version}
    )


def _representative(source: str, binaries: list[Package]) -> Package:
    """The binary a source's findings are reported against.

    The one named like the source, when installed -- so a finding that was
    already matched through it (the ``openssl`` CLI) keeps its identity, its
    first-seen date and its history. Otherwise the first by name, so the choice
    is the same on every scan.
    """
    for binary in binaries:
        if binary.name == source:
            return binary
    return min(binaries, key=lambda b: b.name)


def _name_at_version(pkg: Package) -> str:
    return f"{pkg.name}@{pkg.version}"


def _reattribute(advisory: RawAdvisory, remap: dict[str, str]) -> RawAdvisory:
    """Move an advisory from the source it was asked under to its binary.

    Rewrites only the ``name@version`` after the ecosystem -- which is itself
    ``Debian:12`` or ``Ubuntu:22.04:LTS``, colons and all -- and keeps the fix
    note after it untouched.
    """
    identifier = advisory.package_identifier
    if not identifier:
        return advisory
    note = identifier.find(" (")
    base, suffix = (identifier, "") if note == -1 else (identifier[:note], identifier[note:])
    at = base.rfind("@")
    colon = base.rfind(":", 0, at) if at != -1 else -1
    prefix, tail = base[: colon + 1], base[colon + 1 :]
    if tail not in remap:
        return advisory
    return advisory.model_copy(update={"package_identifier": prefix + remap[tail] + suffix})


def _fixed_from_ranges(ranges: list[Any]) -> str | None:
    for rng in ranges:
        if isinstance(rng, dict):
            events = rng.get("events") or []
            for ev in events:
                if isinstance(ev, dict) and "fixed" in ev:
                    return str(ev["fixed"])
    return None


_parse_pkg_name = parse_package_name


def _package_blocks(vuln: dict[str, Any], package: Package) -> list[dict[str, Any]]:
    """The advisory's affected entries for this package, whatever the release."""
    name = package.name.lower()
    blocks = []
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        aff_name = str((aff.get("package") or {}).get("name", "")).lower()
        if aff_name and aff_name != name:
            continue
        blocks.append(aff)
    return blocks


def _block_ecosystem(block: dict[str, Any]) -> str:
    return str((block.get("package") or {}).get("ecosystem", ""))


def describes_release(
    vuln: dict[str, Any], package: Package, release_ecosystems: set[str]
) -> bool:
    """Whether the advisory has an entry for one of the host's queried releases."""
    return any(
        _block_ecosystem(b).lower() in release_ecosystems for b in _package_blocks(vuln, package)
    )


def _covers_family_but_not_release(
    vuln: dict[str, Any], package: Package, host: list[Release]
) -> bool:
    """Whether the advisory names the host's distribution but none of its releases."""
    blocks = [_block_ecosystem(b) for b in _package_blocks(vuln, package)]
    families = {h.family for h in host}
    covers = any(in_family(eco, family) for eco in blocks for family in families)
    if not covers:
        return False
    for eco in blocks:
        release = parse_release(eco)
        if release and any(release.family == h.family and release.key == h.key for h in host):
            return False
    return True


# Marker text written after a package identifier. None of the three "elsewhere"
# forms contain the words "fixed in", which older dashboards still search for to
# decide that a fix is available. Parsed back by app/package_identifier.py.
ELSEWHERE_MARKER = "; fixed only in "
UPSTREAM_MARKER = "(not confirmed for this release; upstream fix in "


def fix_suffix(
    vuln: dict[str, Any],
    package: Package,
    queried_ecosystem: str,
    release_ecosystems: set[str],
) -> str:
    """What to say about a fix for this package on this host (Req 14.7, 14.8).

    - `` (fixed in V)`` -- the host's own release has a fix. Only this form is
      offered as an upgrade command.
    - `` (no fix in Debian 13; fixed only in Debian 14: V)`` -- the host's
      release is tracked and has no fix, but a newer release (or Ubuntu Pro)
      does. Upgrading the distribution, or waiting, is the only way to clear it.
    - `` (not confirmed for this release; upstream fix in RHEL 9: V)`` -- the
      host's release cannot be matched to the advisory (Fedora, Amazon Linux,
      SUSE, a derivative), so a fix exists somewhere but may not be available.
    - nothing -- no fix is published anywhere.

    A fix from a release other than the host's own is never presented as
    installable: that is what put Debian 14 fixes into a Debian 13 host's plan.
    """
    blocks = _package_blocks(vuln, package)
    fixes = [(b, _fixed_from_ranges(b.get("ranges") or [])) for b in blocks]
    host = host_releases(package.ecosystem or "")

    def same_release(block_eco: str) -> bool:
        if block_eco.lower() in release_ecosystems:
            return True
        release = parse_release(block_eco)
        return bool(
            release
            and not release.subscription
            and any(release.family == h.family and release.key == h.key for h in host)
        )

    own = [(b, f) for b, f in fixes if same_release(_block_ecosystem(b))]
    if own:
        for _b, fixed in own:
            if fixed:
                return f" (fixed in {fixed})"
        # The host's release is described and unfixed. A newer release, or a
        # subscription stream for the same release, may still have the fix.
        newer = []
        for b, fixed in fixes:
            release = parse_release(_block_ecosystem(b))
            if not (fixed and release):
                continue
            for h in host:
                if release.family != h.family:
                    continue
                if release.subscription and release.key == h.key:
                    newer.append(((1, release.key), release.label, fixed))
                elif not release.subscription and release.key > h.key:
                    newer.append(((0, release.key), release.label, fixed))
        if newer:
            _order, label, fixed = min(newer)
            return f" (no fix in {host[0].label}{ELSEWHERE_MARKER}{label}: {fixed})"
        return ""

    if not host:
        # No release to reason about. A rolling distribution's entry names the
        # ecosystem exactly ("Wolfi"), and its fix is the host's fix.
        for b, fixed in fixes:
            if fixed and _block_ecosystem(b).lower() == queried_ecosystem.lower():
                return f" (fixed in {fixed})"

    for b, fixed in fixes:
        if fixed:
            eco = _block_ecosystem(b)
            release = parse_release(eco)
            label = release.label if release else (eco or queried_ecosystem)
            return f" {UPSTREAM_MARKER}{label}: {fixed})"
    return ""


# Ecosystem names OSV.dev actually accepts. Verified against the live API:
# a name OSV does not recognize is rejected with HTTP 400, and because
# /querybatch fails the WHOLE batch on a single bad entry ("error in query at
# index N: invalid ecosystem"), one invalid name here silently defeats batching
# for every package that reaches the universal fallback and degrades the scan to
# one HTTP request per package per ecosystem.
#
# "Arch Linux" and "Fedora" were previously in this list and are NOT valid OSV
# ecosystems, so the universal fallback never batched successfully.
#
# Distributions without their own OSV ecosystem (Oracle Linux, Amazon Linux,
# Fedora, Arch) are mapped onto the closest upstream tracker rather than being
# queried under a name OSV will reject -- see _resolve_ecosystems.
_ALL_LINUX_ECOSYSTEMS: list[str] = [
    "Ubuntu",
    "Debian",
    "Red Hat",
    "Alpine",
    "openSUSE",
    "SUSE",
    "AlmaLinux",
    "Rocky Linux",
    "Chainguard",
    "Wolfi",
]


def _cache_key(pkg: Package) -> str:
    return f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"


def _pair_key(item: tuple[Package, str]) -> tuple[str, str]:
    return (_cache_key(item[0]), item[1])


def _release_ids(
    packages: list[Package],
    items: list[tuple[Package, str]],
    matched: dict[tuple[str, str], set[str] | None],
) -> dict[str, tuple[set[str], set[str] | None]]:
    """Per package: its release-specific ecosystems, and the ids matched there.

    A query ecosystem counts as release-specific when it names a release
    (``Debian:13``, ``AlmaLinux:9``, ``Alpine:v3.20``). If any of those queries
    failed, the matched ids are ``None``, so nothing is dropped for that package.
    """
    out: dict[str, tuple[set[str], set[str] | None]] = {}
    by_key = {_cache_key(p): p for p in packages}
    for pkg_key in by_key:
        ecos: set[str] = set()
        ids: set[str] | None = set()
        for pkg, eco in items:
            if _cache_key(pkg) != pkg_key or parse_release(eco) is None:
                continue
            ecos.add(eco.lower())
            found = matched.get((pkg_key, eco))
            if found is None or ids is None:
                ids = None
            else:
                ids |= found
        out[pkg_key] = (ecos, ids if ecos else None)
    return out


class OsvUnavailableError(RuntimeError):
    """OSV could not answer for one or more of the queried packages.

    Raised rather than returning an empty result. The matcher maps any
    non-programming exception from a data source to DATA_SOURCE_UNAVAILABLE,
    which is what marks a scan partial instead of clean (Req 10.1, Property 5).

    This exists because the client used to catch every failure per query and
    return no advisories, so an OSV outage -- or a query OSV rejects, such as an
    ecosystem it does not have -- produced a scan with zero findings that was
    reported as complete. The matcher's own degradation test passed throughout,
    because it drove the matcher with a fake client that raised; the real client
    never did. Returning "nothing found" for "could not ask" is the silent false
    negative this project exists to prevent.
    """


class OsvHttpClient:
    """Concrete OSV.dev client querying the live OSV API."""

    def __init__(
        self,
        base_url: str = _DEFAULT_OSV_API_URL,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_workers = max_workers
        self._http_client = http_client
        self._advisory_cache: dict[str, list[RawAdvisory]] = {}

    def match_packages(self, packages: list[Package]) -> list[RawAdvisory]:
        """Query OSV for vulnerabilities affecting the supplied packages.

        Asked under the *source* package as well as the binary, because the
        distributions disagree about which one they publish under (Req 2.8).
        Debian, Ubuntu, Alpine, Rocky and SUSE key their advisories by source:
        Debian 12's ``glibc`` has dozens and the installed ``libc6`` none.
        AlmaLinux keys some by binary: its ``vim-minimal`` advisories are not
        found by asking about ``vim``. Asking under both means neither kind is
        missed, and the extra names ride in the same batch requests.

        Every answer is then reported against one representative binary per
        source and de-duplicated, so a CVE in glibc is one finding however many
        binaries glibc ships as, and however many of the names asked found it
        (Property 17).

        Everything below this method works on the query packages as named, so
        an advisory's ``affected`` entries are compared with the name OSV was
        actually asked about; comparing them with a different name would
        silently discard every entry, and with them the release filter and the
        fix.
        """
        queries: dict[tuple[str, str, str], Package] = {}
        remap: dict[str, str] = {}
        groups: dict[tuple[str, str, str], tuple[Package, list[Package]]] = {}
        for pkg in packages:
            if not (pkg.name and pkg.version):
                continue
            source = _query_package(pkg)
            key = (source.ecosystem or "", source.name, source.version)
            groups.setdefault(key, (source, []))[1].append(pkg)

        for source, binaries in groups.values():
            reported = _name_at_version(_representative(source.name, binaries))
            for query in [source, *binaries]:
                key = (query.ecosystem or "", query.name, query.version)
                if key in queries:
                    continue
                queries[key] = query
                asked = _name_at_version(query)
                if asked != reported:
                    remap.setdefault(asked, reported)

        advisories = self._match_query_packages(list(queries.values()))
        if not remap:
            return advisories
        return self._deduplicate_findings([_reattribute(a, remap) for a in advisories])

    def _match_query_packages(self, packages: list[Package]) -> list[RawAdvisory]:
        """Query OSV for the given packages, exactly as named."""
        valid_packages = [p for p in packages if p.name and p.version]
        if not valid_packages:
            return []

        # Check in-memory cache first to eliminate redundant round trips
        cached_results: list[RawAdvisory] = []
        uncached_packages: list[Package] = []
        for pkg in valid_packages:
            cache_key = f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"
            if cache_key in self._advisory_cache:
                cached_results.extend(self._advisory_cache[cache_key])
            else:
                uncached_packages.append(pkg)

        if not uncached_packages:
            return self._deduplicate_findings(cached_results)

        # Build candidate queries for uncached packages. Each package is asked
        # about its distribution as a whole (the superset, which never misses a
        # vulnerability) and, where its release is known, about that release
        # alone. The second answer is what removes advisories the host's own
        # release already fixed (Req 14.7).
        query_items: list[tuple[Package, str]] = []
        release_items: list[tuple[Package, str]] = []
        for pkg in uncached_packages:
            ecosystems = self._resolve_ecosystems(pkg)
            for eco in ecosystems:
                query_items.append((pkg, eco))
            for eco in release_query_ecosystems(pkg.ecosystem or ""):
                if eco not in ecosystems:
                    release_items.append((pkg, eco))

        if not query_items:
            return self._deduplicate_findings(cached_results)

        # Execute concurrent batched requests
        should_close = False
        if self._http_client is not None:
            client = self._http_client
        else:
            client = httpx.Client(
                timeout=self._timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=_DEFAULT_POOL_SIZE,
                    max_connections=_DEFAULT_POOL_SIZE * 2,
                ),
            )
            should_close = True

        try:
            vulnerable_all, matched_ids = self._filter_vulnerable_queries(
                client, query_items + release_items
            )
            release_pairs = set(map(_pair_key, release_items))
            vulnerable_queries = [
                item for item in vulnerable_all if _pair_key(item) not in release_pairs
            ]
            release_ids = _release_ids(uncached_packages, query_items + release_items, matched_ids)
            if not vulnerable_queries:
                # Cache negative matches to avoid re-querying safe packages
                for p in uncached_packages:
                    self._advisory_cache[f"{p.ecosystem}:{p.name}:{p.version}"] = []
                return self._deduplicate_findings(cached_results)

            fetched = self._fetch_advisories(
                client, vulnerable_queries, uncached_packages, release_ids
            )
            all_results = cached_results + fetched
            return self._deduplicate_findings(all_results)
        finally:
            if should_close:
                client.close()

    def _resolve_ecosystems(self, package: Package) -> list[str]:
        """Determine candidate OSV ecosystems to query for a given package."""
        eco = (package.ecosystem or "").strip()
        version = package.version.lower()

        # 1. Exact or recognized distribution ecosystem matches
        if eco.startswith("Ubuntu") or (eco.lower() == "ubuntu" or "ubuntu" in version):
            return ["Ubuntu"]
        if eco.startswith("Debian") or (eco.lower() == "debian" or ("+deb" in version or "~deb" in version)):
            return ["Debian"]
        if eco.startswith("Alpine") or (eco.lower() == "alpine" or ("-r" in version and version.split("-r")[-1].isdigit())):
            return [eco] if ":" in eco else ["Alpine", "Wolfi"]
        # AlmaLinux and Rocky Linux have their own OSV trackers and also
        # inherit upstream Red Hat fixes, so query both.
        if eco.startswith(("AlmaLinux", "Rocky Linux")):
            return [eco, "Red Hat"]
        # Red Hat's OSV ecosystem is unversioned: "Red Hat:9" is accepted but
        # returns nothing, so a version suffix here silently loses every finding.
        if eco.startswith("Red Hat"):
            return ["Red Hat"]
        # Oracle Linux and Amazon Linux have no OSV ecosystem of their own.
        # Querying them by name is rejected with HTTP 400, so they resolve onto
        # the Enterprise Linux trackers they actually derive from.
        if eco.startswith(("Oracle Linux", "Amazon Linux")):
            return ["Red Hat", "AlmaLinux", "Rocky Linux"]
        # Fedora and Arch are not OSV ecosystems either. Fedora's packages track
        # Red Hat closely enough to be worth querying; Arch has no upstream
        # tracker, so it takes the universal fallback.
        if eco.startswith("Fedora"):
            return ["Red Hat"]
        if eco.startswith("Arch"):
            return _ALL_LINUX_ECOSYSTEMS
        if eco.startswith("SUSE"):
            return ["SUSE", "openSUSE"]
        if eco.startswith("openSUSE"):
            # Tumbleweed is rolling: its own entries are the host's. Leap is
            # queried family-wide, with the release added by app.scanner.releases.
            return [eco] if eco == "openSUSE:Tumbleweed" else ["openSUSE"]
        if eco in ("Wolfi", "Chainguard"):
            return [eco]
        if eco.lower() == "windows":
            return ["Windows"]

        # 2. Package format family heuristics
        if eco.lower() in ("deb",):
            return ["Ubuntu", "Debian"]
        if eco.lower() in ("rpm", "rhel", "centos", "fedora", "oracle", "amazon"):
            return ["Red Hat", "AlmaLinux", "Rocky Linux", "openSUSE"]
        if eco.lower() in ("apk",):
            return ["Alpine", "Wolfi"]
        if eco.lower() in ("pacman", "arch"):
            # Arch has no OSV ecosystem; fall back rather than send a name that
            # would be rejected and fail the whole batch.
            return _ALL_LINUX_ECOSYSTEMS
        if eco.lower() in ("zypper", "suse", "opensuse"):
            return ["openSUSE", "Red Hat"]

        # 3. Version string release tag hints for generic/untagged packages
        if (
            "el8" in version
            or "el9" in version
            or "el7" in version
            or "centos" in version
            or "rhel" in version
            or "amzn" in version
        ):
            return ["Red Hat", "AlmaLinux", "Rocky Linux"]
        if "fc3" in version or "fc4" in version or "fedora" in version:
            return ["Red Hat"]
        if "suse" in version:
            return ["SUSE", "openSUSE"]

        # 4. Known custom ecosystem string
        if eco and eco.lower() not in ("linux", "unknown", "generic"):
            return [eco]

        # 5. Universal Total Linux Fallback: query all canonical Linux ecosystems
        return _ALL_LINUX_ECOSYSTEMS

    def _filter_vulnerable_queries(
        self,
        client: httpx.Client,
        query_items: list[tuple[Package, str]],
    ) -> tuple[list[tuple[Package, str]], dict[tuple[str, str], set[str] | None]]:
        """Batch query OSV to find which (package, ecosystem) pairs have findings.

        Also returns the advisory ids each pair matched, keyed by
        ``(package cache key, ecosystem)``. ``None`` means the batch failed and
        the ids are unknown -- which must never be read as "matched nothing".
        """
        vulnerable: list[tuple[Package, str]] = []
        ids: dict[tuple[str, str], set[str] | None] = {}
        batch_url = f"{self._base_url}/querybatch"

        for i in range(0, len(query_items), _BATCH_CHUNK_SIZE):
            chunk = query_items[i : i + _BATCH_CHUNK_SIZE]
            payload = {
                "queries": [
                    {
                        "package": {"name": pkg.name, "ecosystem": eco},
                        "version": pkg.version,
                    }
                    for pkg, eco in chunk
                ]
            }
            try:
                resp = request_limited(
                    client, "POST", batch_url, limit=_MAX_OSV_RESPONSE, json=payload
                )
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", [])
                for idx, item in enumerate(chunk):
                    result = results[idx] if idx < len(results) else {}
                    found = {
                        str(v.get("id")) for v in (result or {}).get("vulns") or [] if v.get("id")
                    }
                    # A paged answer lists only some ids; treat the rest as
                    # unknown rather than as "not matched".
                    complete = not (result or {}).get("next_page_token")
                    ids[(_cache_key(item[0]), item[1])] = found if complete else None
                    if found:
                        vulnerable.append(item)
            except Exception:
                # If batch endpoint fails, fallback to querying the chunk items directly
                for item in chunk:
                    ids[(_cache_key(item[0]), item[1])] = None
                    vulnerable.append(item)

        return vulnerable, ids

    def _fetch_advisories(
        self,
        client: httpx.Client,
        vulnerable_queries: list[tuple[Package, str]],
        uncached_packages: list[Package],
        release_ids: dict[str, tuple[set[str], set[str] | None]] | None = None,
    ) -> list[RawAdvisory]:
        """Fetch full advisory details for vulnerable packages and populate cache.

        ``release_ids`` maps a package to the release-specific ecosystems it was
        asked about and the advisory ids OSV matched there (``None`` if unknown).
        An advisory that describes one of those releases but was not matched in
        it does not affect this host, and is dropped.
        """
        query_url = f"{self._base_url}/query"
        package_advisories_map: dict[str, list[RawAdvisory]] = {
            f"{p.ecosystem}:{p.name}:{p.version}": [] for p in uncached_packages
        }

        def _fetch_one(item: tuple[Package, str]) -> tuple[tuple[Package, str], Any]:
            pkg, eco = item
            payload = {
                "package": {"name": pkg.name, "ecosystem": eco},
                "version": pkg.version,
            }
            try:
                # ResponseTooLargeError is a ValueError, so an oversized answer
                # is reported as unanswered below, never as no vulnerabilities.
                resp = request_limited(
                    client, "POST", query_url, limit=_MAX_OSV_RESPONSE, json=payload
                )
                resp.raise_for_status()
                data = resp.json()
                return item, data.get("vulns", [])
            except (httpx.HTTPError, ValueError) as exc:
                # Transport failures, non-2xx responses (including OSV's 400 for
                # an ecosystem it does not recognise) and unparseable bodies.
                # Reported, never converted into "no vulnerabilities".
                return item, exc

        failures: list[tuple[str, BaseException]] = []
        answered: list[tuple[Package, str, list[dict[str, Any]]]] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            for (pkg, eco), result in pool.map(_fetch_one, vulnerable_queries):
                if isinstance(result, BaseException):
                    failures.append((_cache_key(pkg), result))
                else:
                    answered.append((pkg, eco, result))

        # Which releases OSV describes anywhere in this scan's advisories. A
        # release that appears nowhere (an end-of-life Ubuntu interim) is one OSV
        # does not track, and silence about it must not read as "not affected".
        described: set[tuple[str, tuple[int, ...]]] = set()
        for _pkg, _eco, vulns in answered:
            for vuln in vulns:
                for aff in vuln.get("affected") or []:
                    if isinstance(aff, dict):
                        release = parse_release(_block_ecosystem(aff))
                        if release:
                            described.add((release.family, release.key))

        for pkg, eco, vulns in answered:
            cache_key = _cache_key(pkg)
            advisories = self._advisories_for_host(
                pkg, eco, vulns, (release_ids or {}).get(cache_key, (set(), None)), described
            )
            package_advisories_map.setdefault(cache_key, []).extend(advisories)

        if failures:
            # Nothing from this call is cached: a package whose lookup failed
            # must be asked again next time, not remembered as clean.
            key, first = failures[0]
            raise OsvUnavailableError(
                f"OSV did not answer for {len(failures)} of "
                f"{len(vulnerable_queries)} queries (first: {key}: "
                f"{type(first).__name__}: {first})"
            ) from first

        # Commit to client cache -- only reached when every query answered.
        for cache_key, adv_list in package_advisories_map.items():
            self._advisory_cache[cache_key] = adv_list

        all_fetched: list[RawAdvisory] = []
        for adv_list in package_advisories_map.values():
            all_fetched.extend(adv_list)

        return all_fetched

    @staticmethod
    def _advisories_for_host(
        pkg: Package,
        eco: str,
        vulns: list[dict[str, Any]],
        release_match: tuple[set[str], set[str] | None],
        described: set[tuple[str, tuple[int, ...]]],
    ) -> list[RawAdvisory]:
        """Keep the advisories that affect this host's release, and label their fix.

        Two kinds of advisory are dropped, both only when OSV demonstrably tracks
        the host's release (Req 14.7):

        - it has an entry for the host's release, and OSV did not match the
          installed version there -- the release already fixed it, or was never
          affected;
        - it covers the host's distribution but has no entry for the host's
          release at all. Distribution trackers list every release a
          vulnerability affects, so a Debian advisory naming only Debian 14 does
          not affect Debian 13, and a Red Hat advisory for another product does
          not affect RHEL 9.
        """
        release_ecos, matched = release_match
        host = host_releases(pkg.ecosystem or "")
        tracked = [h for h in host if (h.family, h.key) in described]
        base_pkg_id = f"{pkg.ecosystem or eco}:{pkg.name}@{pkg.version}"
        advisories: list[RawAdvisory] = []
        for vuln in vulns:
            if matched is not None and str(vuln.get("id")) not in matched:
                if describes_release(vuln, pkg, release_ecos):
                    continue
            if tracked and _covers_family_but_not_release(vuln, pkg, tracked):
                continue
            score, band = parse_cvss(vuln)
            advisories.append(
                RawAdvisory(
                    cve_id=_resolve_cve_id(vuln),
                    cvss_score=score,
                    severity=band,
                    package_identifier=base_pkg_id + fix_suffix(vuln, pkg, eco, release_ecos),
                )
            )
        return advisories

    def _deduplicate_findings(self, advisories: list[RawAdvisory]) -> list[RawAdvisory]:
        """Deduplicate findings by (cve_id, pkg_name), prioritizing records with fix versions."""
        dedup_map: dict[tuple[str, str], RawAdvisory] = {}
        for adv in advisories:
            pkg_name = _parse_pkg_name(adv.package_identifier) or ""
            key = (adv.cve_id, pkg_name)
            if key not in dedup_map:
                dedup_map[key] = adv
            else:
                existing = dedup_map[key]
                if (
                    adv.package_identifier
                    and "fixed in" in adv.package_identifier
                    and (not existing.package_identifier or "fixed in" not in existing.package_identifier)
                ):
                    dedup_map[key] = adv
                elif _severity_rank(adv) < _severity_rank(existing):
                    dedup_map[key] = adv

        return list(dedup_map.values())
