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
