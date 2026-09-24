"""Bounded reads from the data sources (Req 10.18).

0.8.13 bounded what a scanned host may send back. The intel feeds were the
other way in: every client read its whole response into memory, and the EPSS
client then gunzipped it with no limit at all -- so one compromised mirror, a
misconfigured ``CVEDECK_*_FEED_URL`` or anything in the middle of the
connection could hand the process a small file that expands until it dies.

Each limit here is a ceiling far above anything the real sources send, so it
never trips on honest data; it exists to turn "unbounded" into "bounded".
Measured on 2026-09-24:

- OSV ``/query`` for ``linux`` on ``Ubuntu:22.04:LTS``: 61 MB, the largest
  single answer found. Debian 12's kernel is 9.6 MB and Chromium 12.5 MB.
- CISA KEV catalogue: 1.75 MB.
- FIRST EPSS: 2.7 MB gzipped, 11.5 MB of CSV once decompressed.

A breach raises :class:`ResponseTooLargeError`, a ``ValueError``, so it takes
the path every other unreadable answer already takes: a failed feed refresh
keeps the previous cache, and a failed OSV query marks the scan's sources as
unavailable. Never an empty answer (Req 10.1).
"""

from __future__ import annotations

import zlib
from urllib.parse import urlsplit

import httpx

MIB = 1024 * 1024

#: The most redirects a feed may take. EPSS's "current" URL redirects once, to
#: the dated file on the same host.
MAX_REDIRECTS = 3


class ResponseTooLargeError(ValueError):
    """A data source sent more than its limit, compressed or decompressed."""


class UnexpectedRedirectError(ValueError):
    """A redirect took a feed request to a host, or a scheme, nobody asked for."""


def request_limited(
    client: httpx.Client, method: str, url: str, *, limit: int, **kwargs
) -> httpx.Response:
    """Send a request and read at most ``limit`` bytes of its body.

    The limit applies to the body as decoded -- after any ``Content-Encoding``
    -- so a compressed transfer cannot expand past it either. A declared
    ``Content-Length`` over the limit is refused before reading; one that lies
    is caught by the count.

    Returns a response whose content is already read, so callers keep using
    ``raise_for_status()``, ``status_code`` and ``json()`` as before.
    """
    with client.stream(method, url, **kwargs) as response:
        declared = response.headers.get("content-length", "")
        if (
            declared.isdigit()
            and int(declared) > limit
            and "content-encoding" not in response.headers
        ):
            raise ResponseTooLargeError(_too_large(url, limit))
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(_too_large(url, limit))
            chunks.append(chunk)
        # Already decoded: drop the headers that would make httpx decode again.
        headers = [
            (k, v)
            for k, v in response.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")
        ]
        return httpx.Response(
            status_code=response.status_code,
            headers=headers,
            content=b"".join(chunks),
            request=response.request,
            history=response.history,
        )


def require_same_host(original_url: str, response: httpx.Response) -> None:
    """Refuse an answer that a redirect fetched from somewhere else.

    Redirects stay on for the feeds that need them, but only within the host
    that was asked, and only over HTTPS when it was asked over HTTPS -- a
    redirect elsewhere would let whoever controls one hop choose the data.
    """
    asked = urlsplit(original_url)
    got = response.url
    if got.host != (asked.hostname or "") or (asked.scheme == "https" and got.scheme != "https"):
        raise UnexpectedRedirectError(
            f"{original_url} redirected to {got.scheme}://{got.host}, which was not asked"
        )


def gunzip_limited(payload: bytes, *, limit: int) -> bytes:
    """Decompress gzip ``payload``, refusing to produce more than ``limit`` bytes.

    ``gzip.decompress`` has no limit, which is what makes a gzip bomb work: a
    megabyte in, gigabytes out. Asking zlib for at most ``limit + 1`` bytes
    detects the overrun without ever holding it.
    """
    out = bytearray()
    rest = payload
    # A gzip file may hold several members back to back, which gzip.decompress
    # reads as one; a single decompressobj stops after the first.
    while rest:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out += decoder.decompress(rest, limit + 1 - len(out))
        if len(out) > limit or decoder.unconsumed_tail:
            raise ResponseTooLargeError(f"gzip body expands past {limit // MIB} MiB")
        out += decoder.flush()
        if len(out) > limit:
            raise ResponseTooLargeError(f"gzip body expands past {limit // MIB} MiB")
        if not decoder.eof:
            raise zlib.error("truncated gzip body")
        rest = decoder.unused_data
    return bytes(out)


def _too_large(url: str, limit: int) -> str:
    return f"{url} sent more than {limit // MIB} MiB"
