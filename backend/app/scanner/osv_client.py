"""HTTP client for matching package inventory against the OSV.dev API.

Implements the :class:`~app.scanner.matcher.OsvClient` protocol. Connects to the
public OSV.dev REST API (https://api.osv.dev/v1), performs fast batch lookups to
identify vulnerable packages, queries full advisory details, and normalizes
records into :class:`~app.scanner.matcher.RawAdvisory` instances with resolved
CVE IDs, CVSS base scores, and package identifiers (Req 2.2, 2.3, 7.1).
"""

from __future__ import annotations

import math
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from app.models import Package
from app.package_identifier import parse_package_name
from app.scanner.matcher import RawAdvisory

_DEFAULT_OSV_API_URL = "https://api.osv.dev/v1"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_MAX_WORKERS = 25
_BATCH_CHUNK_SIZE = 500
# HTTP connection pool sizing for the live client (AGENTS.md matcher invariant:
# 50 keepalive / 100 max connections), sized to sustain _DEFAULT_MAX_WORKERS.
_DEFAULT_POOL_SIZE = 50


def _parse_cvss_v3_vector(vector: str) -> float:
    """Calculate the CVSS v3.x base score from a standard vector string.

    Parses vector strings such as ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``
    and implements the official CVSS v3.1 specification formula.
    """
    if not vector.startswith("CVSS:3."):
        return 5.0

    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        ui_map = {"N": 0.85, "R": 0.62}
        scope = metrics.get("S", "U")
        pr_map = {
            "N": 0.85,
            "L": 0.68 if scope == "C" else 0.62,
            "H": 0.50 if scope == "C" else 0.27,
        }
        cia_map = {"H": 0.56, "L": 0.22, "N": 0.0}

        av = av_map.get(metrics.get("AV", "N"), 0.85)
        ac = ac_map.get(metrics.get("AC", "L"), 0.77)
        pr = pr_map.get(metrics.get("PR", "N"), 0.85)
        ui = ui_map.get(metrics.get("UI", "N"), 0.85)
        c = cia_map.get(metrics.get("C", "N"), 0.0)
        i = cia_map.get(metrics.get("I", "N"), 0.0)
        a = cia_map.get(metrics.get("A", "N"), 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if iss <= 0:
            return 0.0

        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0

        if scope == "U":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)

        return round(min(10.0, max(0.0, math.ceil(base * 10.0) / 10.0)), 1)
    except Exception:
        return 5.0


def _parse_cvss_score(vuln: dict[str, Any]) -> float:
    """Extract or calculate a CVSS numeric score (0.0 to 10.0) from an OSV record."""
    # 1. Check structured severity vectors
    severities = vuln.get("severity") or []
    if isinstance(severities, list):
        for sev in severities:
            if isinstance(sev, dict):
                score_str = sev.get("score", "")
                if isinstance(score_str, str) and score_str.startswith("CVSS:3."):
                    return _parse_cvss_v3_vector(score_str)
                try:
                    val = float(score_str)
                    if 0.0 <= val <= 10.0:
                        return val
                except ValueError:
                    pass

    # 2. Check database_specific severity string
    db_spec = vuln.get("database_specific") or {}
    if isinstance(db_spec, dict):
        db_sev = str(db_spec.get("severity", "")).upper()
        if "CRIT" in db_sev:
            return 9.5
        if "HIGH" in db_sev:
            return 8.0
        if "MOD" in db_sev or "MED" in db_sev:
            return 5.5
        if "LOW" in db_sev:
            return 2.5

    # 3. Fallback default
    return 5.0


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


def _fixed_from_ranges(ranges: list[Any]) -> str | None:
    for rng in ranges:
        if isinstance(rng, dict):
            events = rng.get("events") or []
            for ev in events:
                if isinstance(ev, dict) and "fixed" in ev:
                    return str(ev["fixed"])
    return None


_parse_pkg_name = parse_package_name


def _extract_fixed_version(
    vuln: dict[str, Any], package: Package, ecosystem: str
) -> str | None:
    """Find the package fix version for the target ecosystem."""
    affected_list = vuln.get("affected") or []
    if not isinstance(affected_list, list):
        return None

    target_eco = (ecosystem or package.ecosystem or "").lower()
    pkg_name = package.name.lower()
    pkg_version = package.version

    # Filter affected records matching package name and ecosystem
    matching_affs: list[dict[str, Any]] = []
    for aff in affected_list:
        if not isinstance(aff, dict):
            continue
        aff_pkg_name = str(aff.get("package", {}).get("name", "")).lower()
        if aff_pkg_name and aff_pkg_name != pkg_name:
            continue
        aff_eco = str(aff.get("package", {}).get("ecosystem", "")).lower()
        if (
            not target_eco
            or not aff_eco
            or target_eco in aff_eco
            or aff_eco in target_eco
            or (target_eco.startswith("deb") and ("ubuntu" in aff_eco or "debian" in aff_eco))
            or (target_eco.startswith("ubuntu") and "ubuntu" in aff_eco)
            or (target_eco.startswith("debian") and "debian" in aff_eco)
            or (target_eco.startswith("alpine") and "alpine" in aff_eco)
            or (target_eco.startswith("almalinux") and ("almalinux" in aff_eco or "red hat" in aff_eco or "rhel" in aff_eco))
            or (target_eco.startswith("rocky") and ("rocky" in aff_eco or "red hat" in aff_eco or "rhel" in aff_eco))
            or (target_eco.startswith("oracle") and ("oracle" in aff_eco or "red hat" in aff_eco or "rhel" in aff_eco))
            or (target_eco.startswith("amazon") and ("amazon" in aff_eco or "red hat" in aff_eco or "rhel" in aff_eco))
            or (target_eco.startswith("suse") and ("suse" in aff_eco or "opensuse" in aff_eco))
            or (target_eco.startswith("red hat") and ("red hat" in aff_eco or "almalinux" in aff_eco or "rocky" in aff_eco or "oracle" in aff_eco or "rhel" in aff_eco))
            or (target_eco.startswith("fedora") and ("fedora" in aff_eco or "red hat" in aff_eco))
            or (target_eco.startswith("opensuse") and ("opensuse" in aff_eco or "suse" in aff_eco))
        ):
            matching_affs.append(aff)

    # 1. Best match: where installed version is explicitly in versions
    for aff in matching_affs:
        versions = aff.get("versions") or []
        if pkg_version in versions:
            fixed = _fixed_from_ranges(aff.get("ranges") or [])
            if fixed:
                return fixed
            # If the matching version block has no fixed event, no fix has been released
            return None

    # 2. Match first matching package block with a fix
    for aff in matching_affs:
        fixed = _fixed_from_ranges(aff.get("ranges") or [])
        if fixed:
            return fixed

    return None


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
        """Query OSV for vulnerabilities affecting the supplied packages."""
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

        # Build candidate queries for uncached packages
        query_items: list[tuple[Package, str]] = []
        for pkg in uncached_packages:
            ecosystems = self._resolve_ecosystems(pkg)
            for eco in ecosystems:
                query_items.append((pkg, eco))

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
            vulnerable_queries = self._filter_vulnerable_queries(client, query_items)
            if not vulnerable_queries:
                # Cache negative matches to avoid re-querying safe packages
                for p in uncached_packages:
                    self._advisory_cache[f"{p.ecosystem}:{p.name}:{p.version}"] = []
                return self._deduplicate_findings(cached_results)

            fetched = self._fetch_advisories(client, vulnerable_queries, uncached_packages)
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
        if eco in ("openSUSE", "Wolfi", "Chainguard"):
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
    ) -> list[tuple[Package, str]]:
        """Batch query OSV to find which (package, ecosystem) pairs have findings."""
        vulnerable: list[tuple[Package, str]] = []
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
                resp = client.post(batch_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", [])
                for idx, result in enumerate(results):
                    if idx < len(chunk) and result.get("vulns"):
                        vulnerable.append(chunk[idx])
            except Exception:
                # If batch endpoint fails, fallback to querying the chunk items directly
                for item in chunk:
                    vulnerable.append(item)

        return vulnerable

    def _fetch_advisories(
        self,
        client: httpx.Client,
        vulnerable_queries: list[tuple[Package, str]],
        uncached_packages: list[Package],
    ) -> list[RawAdvisory]:
        """Fetch full advisory details for vulnerable packages and populate cache."""
        query_url = f"{self._base_url}/query"
        package_advisories_map: dict[str, list[RawAdvisory]] = {
            f"{p.ecosystem}:{p.name}:{p.version}": [] for p in uncached_packages
        }

        def _fetch_one(item: tuple[Package, str]) -> tuple[str, list[RawAdvisory]]:
            pkg, eco = item
            cache_key = f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"
            payload = {
                "package": {"name": pkg.name, "ecosystem": eco},
                "version": pkg.version,
            }
            try:
                resp = client.post(query_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulns", [])
            except (httpx.HTTPError, ValueError) as exc:
                # Transport failures, non-2xx responses (including OSV's 400 for
                # an ecosystem it does not recognise) and unparseable bodies.
                # Reported, never converted into "no vulnerabilities".
                return cache_key, exc

            base_pkg_id = f"{pkg.ecosystem or eco}:{pkg.name}@{pkg.version}"
            advisories: list[RawAdvisory] = []
            for vuln in vulns:
                cve_id = _resolve_cve_id(vuln)
                score = _parse_cvss_score(vuln)
                fixed_ver = _extract_fixed_version(vuln, pkg, eco)
                pkg_id = (
                    f"{base_pkg_id} (fixed in {fixed_ver})"
                    if fixed_ver
                    else base_pkg_id
                )
                advisories.append(
                    RawAdvisory(
                        cve_id=cve_id,
                        cvss_score=score,
                        package_identifier=pkg_id,
                    )
                )
            return cache_key, advisories

        failures: list[tuple[str, BaseException]] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            chunk_results = pool.map(_fetch_one, vulnerable_queries)
            for cache_key, result in chunk_results:
                if isinstance(result, BaseException):
                    failures.append((cache_key, result))
                    continue
                if cache_key in package_advisories_map:
                    package_advisories_map[cache_key].extend(result)
                else:
                    package_advisories_map[cache_key] = result

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
                elif adv.cvss_score > existing.cvss_score:
                    dedup_map[key] = adv

        return list(dedup_map.values())
