"""Parse a finding's ``package_identifier`` back into its package name (Req 14.5).

The matcher writes identifiers as ``<ecosystem>:<name>@<version>``, optionally
followed by `` (fixed in <version>)``. Every one of those parts except the name
can itself contain a colon:

- the ecosystem is often versioned -- ``Debian:13``, ``Ubuntu:22.04:LTS``;
- a Debian or RPM version can carry an epoch -- ``@1:2.38-4``;
- and one ecosystem name contains a space -- ``Red Hat:openssl@...``.

So the name is found from the right, not the left: drop the ``(fixed in ...)``
note, drop everything from the last ``@``, then take what follows the last
``:``. The note is cut at its own marker rather than at the first space, which
would have reduced every Red Hat identifier to ``Red``. Splitting on the first colon,
as this used to, turned ``Debian:13:openssl@3.5.1`` into ``13:openssl``, and the
host's fix plan then asked apt to upgrade forty-two packages that do not exist.

A package name contains no ``@`` except as an npm scope's leading character, and
no ``:`` in the OS ecosystems CveDeck matches, so reading from the right is
unambiguous for every identifier the matcher produces.
"""

from __future__ import annotations

import re


def parse_package_name(package_identifier: str | None) -> str | None:
    """The bare package name, or ``None`` when there is none to extract."""
    if not package_identifier or not package_identifier.strip():
        return None
    token = package_identifier.strip()
    note = token.find(" (")
    if note != -1:
        token = token[:note]
    at = token.rfind("@")
    # An "@" at the start of the name part is an npm scope, not a version.
    if at > 0 and token[at - 1] != ":":
        token = token[:at]
    name = token.rsplit(":", 1)[-1].strip()
    return name or None


_ELSEWHERE = re.compile(r"\(no fix in (?P<host>.+?); fixed only in (?P<label>.+): (?P<version>\S+)\)\s*$")
_UPSTREAM = re.compile(r"\(not confirmed for this release; upstream fix in (?P<label>.+): (?P<version>\S+)\)\s*$")
_AVAILABLE = re.compile(r"\(fixed in (?P<version>[^)\s]+)\)\s*$")


def parse_fix(package_identifier: str | None) -> tuple[str, str | None, str | None]:
    """How a finding can be fixed, from the note the matcher wrote (Req 14.7, 14.8).

    Returns ``(status, release, version)``:

    - ``("available", None, V)`` -- the host's own release ships V.
    - ``("newer_release", "Debian 14", V)`` -- only a newer release (or a
      subscription stream such as Ubuntu Pro) ships a fix. Upgrading packages
      cannot clear it.
    - ``("upstream", "RHEL 9", V)`` -- a fix exists, but the host's release could
      not be matched to the advisory, so whether it is available is unconfirmed.
    - ``("none", None, None)`` -- no fix is published.
    """
    text = (package_identifier or "").strip()
    if m := _AVAILABLE.search(text):
        return "available", None, m.group("version")
    if m := _ELSEWHERE.search(text):
        return "newer_release", m.group("label"), m.group("version")
    if m := _UPSTREAM.search(text):
        return "upstream", m.group("label"), m.group("version")
    return "none", None, None
