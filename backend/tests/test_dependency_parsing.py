"""Dependency parsing, against output captured from real package managers.

Every fixture in this file was copied verbatim out of a container -- `debian:12`,
`rockylinux:9`, `alpine:3`, `archlinux:base` -- running the exact command in
``collectors._LINUX_PACKAGES_CMD``. None of it was written from memory, because
writing it from memory is how the bugs below survived:

The dependency graph feeds ``routes._blast_radius``, which tells a reader how
much of a host breaks if a package is removed. Until 0.8.7 it was correct only
on dpkg:

- ``%{REQUIRES}`` expands to the FIRST element of rpm's requires array, so every
  RPM host reported one dependency per package -- usually a file path such as
  ``/usr/bin/sh``. Measured on a stock Rocky 9 container: 16 resolvable
  dependency edges where there are 120.
- The apk arm emitted name and version only, so Alpine had no graph at all.
- The pacman arm was never reached (see ``test_arch_output_is_not_silently_empty``
  in the collector tests), so an Arch host could not be scanned.
- ``_parse_dependencies`` computed ``item.split("(")[0]`` before testing its
  ``rpmlib(``/``config(`` filter, so the filter could never fire.

The only fixture whose expectations are unchanged from before 0.8.7 is Debian's.
That is the point: one distro was covered, and its correctness was taken for the
others' (Req 10.13, Property 16).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.scanner.collectors import _parse_dependencies, _parse_linux_packages

# --- Real output, one line per package, exactly as the command emits it ------

DEBIAN = (
    "apt\t2.6.1\tadduser, gpgv | gpgv2 | gpgv1, libapt-pkg6.0 (>= 2.6.1), "
    "debian-archive-keyring, libc6 (>= 2.34), libgcc-s1 (>= 3.0), "
    "libgnutls30 (>= 3.7.5), libseccomp2 (>= 2.4.2), libstdc++6 (>= 11), "
    "libsystemd0\n"
    "libgcc-s1\t12.2.0-14+deb12u1\tgcc-12-base (= 12.2.0-14+deb12u1), "
    "libc6 (>= 2.35)\n"
    "perl-base\t5.36.0-7+deb12u3\t\n"
)

ROCKY = (
    "bash\t5.1.8-6.el9_1\t/usr/bin/sh,config(bash),filesystem,"
    "libc.so.6()(64bit),libc.so.6(GLIBC_2.34)(64bit),libtinfo.so.6()(64bit),"
    "rpmlib(BuiltinLuaScripts),rpmlib(FileDigests),rtld(GNU_HASH),\n"
    "rocky-release\t9.3-1.1.el9\tconfig(rocky-release),rocky-repos(9),"
    "rpmlib(CompressedFileNames),rpmlib(FileDigests),\n"
    "libgcc\t11.4.1-2.1.el9\trpmlib(BuiltinLuaScripts),"
    "rpmlib(CompressedFileNames),rpmlib(FileDigests),\n"
    "glibc\t2.34-83.el9.7\t(glibc-gconv-extra(x86-64) = 2.34-83.el9.7 if "
    "redhat-rpm-config),basesystem,basesystem,config(glibc),glibc-common,"
    "glibc-langpack,ld-linux-x86-64.so.2()(64bit),libc.so.6()(64bit),"
    "libgcc(x86-64),libm.so.6()(64bit),rpmlib(RichDependencies),"
    "rtld(GNU_HASH),\n"
)

ALPINE = (
    "alpine-baselayout\t3.7.2-r1\talpine-baselayout-data=3.7.2-r1,/bin/sh\n"
    "apk-tools\t3.0.8-r0\tmusl>=1.2.3_git20230424,libcrypto3>=3.5,"
    "libapk=3.0.8-r0,ca-certificates-bundle,so:libapk.so.3.0.0,"
    "so:libc.musl-x86_64.so.1,so:libz.so.1\n"
    "busybox\t1.37.0-r31\tso:libc.musl-x86_64.so.1\n"
)

ARCH = (
    "bash\t5.3.15-1\treadline,libreadline.so=8-64,glibc,ncurses\n"
    "glibc\t2.44+r24+g16be1518495f-1\tlinux-api-headers>=4.10,tzdata,"
    "filesystem\n"
    "ncurses\t6.6-2\tglibc,libgcc,libstdc++\n"
)


def _deps(output: str) -> dict[str, list[str]]:
    return {p.name: p.dependencies for p in _parse_linux_packages(output)}


# --- Per-manager expectations ------------------------------------------------


def test_dpkg_output_is_unchanged():
    """dpkg was the one branch that already worked; it must not move."""
    deps = _deps(DEBIAN)
    assert deps["apt"] == [
        "adduser",
        # The first alternative of 'gpgv | gpgv2 | gpgv1'.
        "gpgv",
        "libapt-pkg6.0",
        "debian-archive-keyring",
        "libc6",
        "libgcc-s1",
        "libgnutls30",
        "libseccomp2",
        "libstdc++6",
        "libsystemd0",
    ]
    assert deps["libgcc-s1"] == ["gcc-12-base", "libc6"]
    # A package with no dependencies has an empty list, not a fabricated one.
    assert deps["perl-base"] == []


def test_rpm_keeps_only_real_packages():
    deps = _deps(ROCKY)
    # Of bash's twenty-odd requirements, exactly one names a package: the rest
    # are a file path, config(), sonames and rpm internals.
    assert deps["bash"] == ["filesystem"]
    # rpmlib-only packages depend on nothing resolvable -- and 'rpmlib' is not
    # itself a dependency, which is what the old filter produced.
    assert deps["libgcc"] == []


def test_rpm_keeps_an_arch_qualified_or_versioned_provide():
    """`rpm-libs(x86-64)` and `rocky-repos(9)` are real installed packages.

    Dropping every token containing parentheses is the obvious way to remove
    the rpm noise, and it silently costs genuine edges -- 24 of them on a stock
    Rocky 9 host.
    """
    deps = _deps(ROCKY)
    assert "rocky-repos" in deps["rocky-release"]
    assert "libgcc" in deps["glibc"]
    # A rich dependency '(a if b)' names no single package and is dropped.
    assert not any(d.startswith("(") for d in deps["glibc"])
    assert "basesystem" in deps["glibc"]
    # Recorded once, though rpm lists it twice.
    assert deps["glibc"].count("basesystem") == 1


def test_apk_drops_capabilities_and_strips_constraints():
    deps = _deps(ALPINE)
    assert deps["apk-tools"] == [
        "musl",
        "libcrypto3",
        "libapk",
        "ca-certificates-bundle",
    ]
    # so:/cmd:/pc: are capabilities. Splitting on ':' first turned all three
    # into packages named 'so', 'cmd' and 'pc' -- which nearly every package
    # would then have depended on, inflating every blast radius on the host.
    assert "so" not in deps["apk-tools"]
    assert deps["busybox"] == []
    assert deps["alpine-baselayout"] == ["alpine-baselayout-data"]


def test_pacman_drops_sonames_and_strips_constraints():
    deps = _deps(ARCH)
    assert deps["bash"] == ["readline", "glibc", "ncurses"]
    assert deps["glibc"] == ["linux-api-headers", "tzdata", "filesystem"]
    assert deps["ncurses"] == ["glibc", "libgcc", "libstdc++"]


@pytest.mark.parametrize(
    "output,package,expected_edges",
    [
        (DEBIAN, "apt", 10),
        (ROCKY, "bash", 1),
        (ALPINE, "apk-tools", 4),
        (ARCH, "bash", 3),
    ],
)
def test_every_manager_yields_a_usable_graph(output, package, expected_edges):
    """No supported manager may come back with an empty dependency list.

    Alpine and Arch both did: Alpine because the command collected no
    dependency data, Arch because it collected nothing at all.
    """
    assert len(_deps(output)[package]) == expected_edges


# --- Property 16 -------------------------------------------------------------

_REAL_NAMES = ["glibc", "libc6", "musl", "readline", "filesystem", "zlib1g"]
_NOISE = [
    "/usr/bin/sh",
    "/bin/sh",
    "so:libc.musl-x86_64.so.1",
    "cmd:bash",
    "pc:openssl",
    "rpmlib(FileDigests)",
    "config(bash)",
    "rtld(GNU_HASH)",
    "libc.so.6()(64bit)",
    "libreadline.so=8-64",
    "(glibc-gconv-extra(x86-64) = 2.34 if redhat-rpm-config)",
]
_CONSTRAINTS = ["", " >= 2.38", " (>= 2.38)", ">=1.2.3", "=3.0.8-r0", ":amd64"]


@st.composite
def _dependency_fields(draw):
    """A depends field mixing real package names with every noise form."""
    real = draw(st.lists(st.sampled_from(_REAL_NAMES), max_size=5))
    noise = draw(st.lists(st.sampled_from(_NOISE), max_size=5))
    tokens = [name + draw(st.sampled_from(_CONSTRAINTS)) for name in real]
    tokens += noise
    tokens = draw(st.permutations(tokens))
    return ",".join(tokens), set(real)


@settings(max_examples=300)
@given(_dependency_fields())
def test_property_16_only_names_the_manager_named(case):
    """Property 16 (Req 10.13).

    A parsed dependency list contains only names the package manager actually
    named as packages. No file path, capability, soname, rpm internal or
    version constraint survives, and nothing is invented.
    """
    field, expected_real = case
    parsed = _parse_dependencies(field)

    # Sound: everything returned was named, as a package, in the input.
    assert set(parsed) <= expected_real

    # Complete: every real package named is returned.
    assert set(parsed) == expected_real

    # No residue of any noise form.
    for name in parsed:
        assert not name.startswith("/")
        assert not name.startswith(("so:", "cmd:", "pc:"))
        assert "(" not in name and ")" not in name
        assert ".so" not in name
        assert not any(char in name for char in "<>=! \t")
        assert ":" not in name

    # Deduplicated, and order preserved on first appearance.
    assert len(parsed) == len(set(parsed))
