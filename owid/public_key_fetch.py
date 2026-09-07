# ****************************************************************************
# Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# ****************************************************************************
"""Fetches the signing public key of a creator from the well known end point
on the domain the OWID carries, asking for the key that was in force on the
date the OWID carries.

The end point is /owid/api/v{n}/public-key?date={minutes}&format=pkcs, where
the version in the path is the version byte of the OWID being checked rather
than a constant, and the minutes are counted from 2020-01-01 in the same way
the OWID stores the date. Creators rotate weekly, so without the date only
identifiers signed since the most recent rotation can be verified and every
older one reads as not matching. A creator that ignores the parameter returns
its current key, so every identifier it signed under an earlier key reads as
not matching, which is why a creator that rotates its key has to honour the
date.

Every function in this module that reaches the network is a coroutine, so a
caller awaits it, and there is no synchronous form of any of them. The
default transport runs the standard library urllib on a worker thread through
asyncio.to_thread, which is blocking I/O on a worker thread rather than a
non-blocking request, so the event loop is free for the length of the request
but a thread is not. Supply an aiohttp or httpx based transport for a fully
non-blocking one. Only the standard library is used here, so the package
keeps its promise of no dependency beyond cryptography. This module is the
one place in the package that reaches the network, and it is imported only
when a caller asks for it.

Keys already fetched are held by creator, each against the span of minutes
the creator has confirmed it for, so an identifier dated inside a confirmed
span is verified without a request whichever minute it carries. Two callers
who await the same key at the same moment share one request rather than
making two.

The Java port answers the same question with PublicKeyFetch, the Rust port
with Owid::verify_status and the Go port with SignatureStatusFromDomain.
"""

from __future__ import annotations

import asyncio
import http.client
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from . import endpoints, io
from .error import OwidError, PublicKeyFetchError
from .owid import Owid
from .status import SignatureStatus

#: How long to wait for the connection and then for the response, in seconds.
TIMEOUT_SECONDS = 10.0

#: The most keys held before the cache is emptied and filled again, across
#: every creator. A bound is needed because a verifier sees identifiers from
#: many domains and many weeks, and an unbounded store would grow for as long
#: as the process runs.
MAXIMUM_CACHED_KEYS = 1024

#: The most bytes accepted from a response. A public key PEM is a few hundred
#: bytes, so a body beyond this is not a key and is not held or decoded.
MAXIMUM_RESPONSE_BYTES = 65536

#: A transport is an async callable that takes the URL and the timeout in
#: seconds and returns the response code and the body. It raises OSError
#: where no response could be obtained at all, which is what urllib raises
#: for a refused connection, a name that does not resolve and a timeout.
#: Supply one where urllib on a worker thread is not the right client, for
#: example an aiohttp or httpx based transport for a fully non-blocking
#: request, or behind a proxy that needs its own set up.
Transport = Callable[[str, float], Awaitable[Tuple[int, bytes]]]

#: The schemes that make an HTTP request. A caller chooses the scheme, and one
#: that reads something other than a creator, such as file, is refused rather
#: than opened.
_ACCEPTED_SCHEMES = ("http", "https")

class _HeldKey:
    """One key a creator has answered with, and the span of minutes the
    creator has confirmed it was in force for.

    A creator's key is in force from the start of its period until the next
    key starts, so a key the creator confirms at two minutes was in force at
    every minute between them. The span grows as the creator confirms the
    same key for more minutes, and an identifier dated inside it is verified
    without a request.
    """

    __slots__ = ("pem", "first", "last")

    def __init__(self, pem: str, minute: int) -> None:
        #: The key in PEM form, as the creator served it.
        self.pem = pem
        #: The earliest minute the creator has confirmed the key for.
        self.first = minute
        #: The latest minute the creator has confirmed the key for.
        self.last = minute

    def covers(self, minute: int) -> bool:
        """Whether the minute lies within the confirmed span."""
        return self.first <= minute <= self.last


#: Keys already fetched, by the creator's key end point, which is the key URL
#: without its date. Each end point holds the keys the creator has answered
#: with, each with the span of minutes the creator has confirmed it for.
#:
#: The specification asks implementations to cache so that verifying many
#: identifiers does not mean repeating requests to another processor. The key
#: URL carries the date of the identifier being verified, in minutes, and a
#: creator's key changes on the order of a week. Keyed by the whole URL, as
#: this cache once was, two identifiers signed a minute apart never shared an
#: entry, so a hundred identifiers over a hundred minutes made a hundred
#: requests for one key. Keyed by end point and span, an identifier dated
#: between two minutes the creator has already answered for is verified
#: without a request.
_cache: Dict[str, List[_HeldKey]] = {}
#: How many keys are held across every end point.
_held_keys = 0
#: Fetches still running, held against the URL, so that a caller who asks for
#: a key while the request for it is in flight awaits that request rather
#: than making another. An entry is removed when its fetch finishes, whatever
#: the outcome. A task belongs to the event loop that created it, so a caller
#: on a different loop, which only happens where two loops run in two
#: threads, cannot await it and starts a fetch of its own.
_in_flight: Dict[str, "asyncio.Task[str]"] = {}
#: Guards all three stores. An event loop runs one coroutine at a time, but
#: the stores are shared by every loop in the process, and the lock is only
#: ever held across a few dictionary operations and never across an await.
_lock = threading.Lock()


def public_key_url(owid: Owid, scheme: str) -> str:
    """Returns the URL of the public key end point for the OWID, using the
    scheme provided, which is normally https.

    The date the OWID carries is sent as the date parameter, counted in whole
    minutes from 2020-01-01, so that a creator which rotates its key returns
    the key that was in force when this OWID was signed. The parameter is left
    out where the date cannot be counted, which no OWID this package reads can
    be, because the wire format cannot hold such a date.

    Raises OwidError if the OWID or the scheme is missing, or the domain the
    OWID carries is not a domain name this package will put in a URL.
    """
    if owid is None:
        raise OwidError("the OWID is missing")
    if scheme is None or not scheme.strip():
        raise OwidError("the scheme is missing")
    if scheme.strip().lower() not in _ACCEPTED_SCHEMES:
        # Checked here as well as before the request, so a caller who
        # only wants the URL cannot be handed one that names some other
        # host through a scheme that is really a prefix.
        raise OwidError(
            "the scheme must be http or https, received {0}".format(
                _quoted(scheme)
            )
        )
    domain = owid.domain
    _check_domain(domain)
    minutes = io.minutes_since_base(owid.date)
    if minutes >= 0:
        query = "date={0}&format=pkcs".format(minutes)
    else:
        query = "format=pkcs"
    return "{0}://{1}{2}?{3}".format(
        scheme, domain, endpoints.public_key_path(owid.version), query
    )


async def public_key_pem(
    owid: Owid, scheme: str, transport: Optional[Transport] = None
) -> str:
    """Returns the public key PEM of the creator of the OWID, for the date the
    OWID carries.

    Raises PublicKeyFetchError if the key could not be obtained, carrying the
    status to report for the identifier, and OwidError if the OWID, the scheme
    or the domain is not usable.
    """
    return await _public_key_pem_at_url(
        public_key_url(owid, scheme), owid.domain, transport
    )


async def signature_status(
    owid: Owid,
    scheme: str,
    others: Optional[Sequence[Owid]] = None,
    transport: Optional[Transport] = None,
) -> SignatureStatus:
    """Says whether the signature on the OWID is genuine, fetching the key
    that was in force when the OWID was signed from the creator domain.

    A key that cannot be fetched is SignatureStatus.KEY_UNAVAILABLE and one
    that arrives in a form this package cannot read is
    SignatureStatus.INVALID_KEY. Neither is SignatureStatus.SIGNATURE_INVALID,
    because an outage or a badly served key leaves the signature unjudged, and
    reporting either as invalid would read as an attack.

    Pass the other OWIDs that were signed together with this one, in the same
    order as when signed, or nothing when it was signed on its own.
    """
    try:
        url = public_key_url(owid, scheme)
    except OwidError:
        return SignatureStatus.KEY_UNAVAILABLE
    return await _signature_status_at_url(owid, url, others, transport)


async def verify(
    owid: Owid,
    scheme: str,
    others: Optional[Sequence[Owid]] = None,
    transport: Optional[Transport] = None,
) -> bool:
    """Returns True only when the signature verifies under the key the
    creator served for the date the OWID carries. Every other outcome, a
    signature that does not match included, is False, so ask
    signature_status where the difference changes what the caller does."""
    status = await signature_status(owid, scheme, others, transport)
    return status is SignatureStatus.SIGNATURE_VALID


def clear_cache() -> None:
    """Empties the cache of keys already fetched, and forgets the fetches
    still in flight so that the next caller for any key starts a request of
    its own. A fetch already running is not stopped, and the callers awaiting
    it still receive its answer. This is how a long running process drops a
    key it has learned it should no longer trust, after a creator rotates its
    key following a compromise, and how a test starts from a known state."""
    global _held_keys
    with _lock:
        _cache.clear()
        _held_keys = 0
        _in_flight.clear()


def _cached_key_count() -> int:
    """How many keys the cache holds, for the tests."""
    with _lock:
        return _held_keys


async def _signature_status_at_url(
    owid: Owid,
    url: str,
    others: Optional[Sequence[Owid]] = None,
    transport: Optional[Transport] = None,
) -> SignatureStatus:
    """The work signature_status does once the URL is known, kept apart so
    that the tests drive the real fetch against a key end point the tests can
    stand up locally rather than against a near copy of the fetch."""
    try:
        pem = await _public_key_pem_at_url(url, owid.domain, transport)
    except PublicKeyFetchError as failed:
        return failed.status
    except OwidError:
        return SignatureStatus.KEY_UNAVAILABLE
    return owid.signature_status(pem, others)


async def _public_key_pem_at_url(
    url: str, domain: str, transport: Optional[Transport] = None
) -> str:
    """Fetches the PEM at the URL. Answered from the cache where the creator
    has already confirmed a key for the minute the URL names, from the
    request already in flight where another caller on this event loop is
    fetching the same URL now, and otherwise by asking the creator."""
    loop = asyncio.get_running_loop()
    end_point = _end_point_of(url)
    minute = _minute_of(url)
    with _lock:
        held = _held_pem(end_point, minute)
        if held is not None:
            return held
        fetch = _in_flight.get(url)
        if fetch is None or fetch.get_loop() is not loop:
            fetch = loop.create_task(
                _fetch_and_hold(url, end_point, minute, domain, transport)
            )
            fetch.add_done_callback(_mark_observed)
            _in_flight[url] = fetch
    # Shielded, because cancelling one caller must not cancel the request
    # that other callers are waiting on, and a request on a worker thread
    # cannot be stopped part way in any case. The answer still lands in the
    # cache for the next caller.
    return await asyncio.shield(fetch)


async def _fetch_and_hold(
    url: str,
    end_point: str,
    minute: int,
    domain: str,
    transport: Optional[Transport],
) -> str:
    """The one request for a URL, run as a task that every caller waiting for
    that URL awaits. Holds the answer against the minute asked about, and
    forgets the task whatever the outcome so that a failed fetch is tried
    again by the next caller."""
    task = asyncio.current_task()
    pem: Optional[str] = None
    try:
        pem = await _read(url, domain, transport)
        return pem
    finally:
        with _lock:
            if pem is not None:
                _hold(end_point, minute, pem)
            if _in_flight.get(url) is task:
                del _in_flight[url]


def _end_point_of(url: str) -> str:
    """The key URL without its query, which names the scheme, the creator and
    the version, and so the key end point being asked."""
    return url.split("?", 1)[0]


def _minute_of(url: str) -> int:
    """The minute the cache reads the URL as asking about.

    The date parameter where the URL carries one, and otherwise now, because
    a creator answers a request without a date with the key in force now. A
    date later than now is read as now as well, because that is how a creator
    reads it. A schedule is published ahead of time and a key that has not
    started has signed nothing, so the creator answers a future date with the
    key in force now, and that answer must be held against now rather than
    against a minute the creator has not spoken for. Held against the future
    minute, the key would still be served for that minute after the creator
    had rotated, and a genuine identifier signed then would read as not
    matching.
    """
    now = io.minutes_since_base(datetime.now(timezone.utc))
    query = urllib.parse.urlsplit(url).query
    for name, value in urllib.parse.parse_qsl(query):
        if name == "date":
            try:
                return min(int(value), now)
            except ValueError:
                return now
    return now


def _held_pem(end_point: str, minute: int) -> Optional[str]:
    """The key held for the end point whose confirmed span covers the minute,
    or None where no held key does. Called under the lock."""
    for key in _cache.get(end_point, ()):
        if key.covers(minute):
            return key.pem
    return None


def _hold(end_point: str, minute: int, pem: str) -> None:
    """Records that the creator answered the minute with the key. Called
    under the lock.

    A key already held for the end point has its span widened to take in the
    minute. A key not held before is added, emptying the cache first when it
    is full, because the domains and dates asked about come from the
    identifiers presented to this process and the cache must not grow on
    their input.
    """
    global _held_keys
    keys = _cache.get(end_point)
    if keys is not None:
        for key in keys:
            if key.pem == pem and _widen(keys, key, minute):
                return
    if _held_keys >= MAXIMUM_CACHED_KEYS:
        _cache.clear()
        _held_keys = 0
        keys = None
    if keys is None:
        keys = []
        _cache[end_point] = keys
    keys.append(_HeldKey(pem, minute))
    _held_keys += 1


def _widen(keys: List[_HeldKey], key: _HeldKey, minute: int) -> bool:
    """Widens the span of a held key to take in the minute, and says whether
    the minute is now within it.

    The span is not widened across a minute the creator has answered with
    another key for, because that would mean the creator had gone back to a
    key it had left, and the minutes between the two spans are then not this
    key's to claim. The key is held again as a separate span instead.
    """
    if key.covers(minute):
        return True
    start = min(minute, key.first)
    end = max(minute, key.last)
    for other in keys:
        if other is not key and other.last > start and other.first < end:
            return False
    if minute < key.first:
        key.first = minute
    else:
        key.last = minute
    return True


def _mark_observed(task: "asyncio.Task[str]") -> None:
    """Reads the outcome of a finished fetch, so that a failure nobody was
    left waiting for, because every caller was cancelled, is not reported by
    asyncio as an exception that was never retrieved."""
    if not task.cancelled():
        task.exception()


async def _read(
    url: str, domain: str, transport: Optional[Transport]
) -> str:
    """Performs the request and returns the body as text."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ACCEPTED_SCHEMES:
        # A scheme the caller chose that does not make an HTTP request, such
        # as file. Refused before anything is opened, because every route
        # into this module promises to ask a creator and nothing else.
        raise PublicKeyFetchError(
            "the scheme used for domain {0} does not make an HTTP "
            "request".format(_quoted(domain)),
            SignatureStatus.KEY_UNAVAILABLE,
            domain,
        )
    try:
        code, body = await (transport or _urllib_transport)(
            url, TIMEOUT_SECONDS
        )
    except (OSError, ValueError, http.client.HTTPException) as failed:
        # A refused connection, a name that does not resolve and a timeout
        # all arrive here, and all of them mean the signature was never
        # examined.
        raise PublicKeyFetchError(
            "the public key could not be fetched from domain {0}".format(
                _quoted(domain)
            ),
            SignatureStatus.KEY_UNAVAILABLE,
            domain,
        ) from failed
    if code != 200:
        raise PublicKeyFetchError(
            "domain {0} returned code '{1}' for the public key".format(
                _quoted(domain), code
            ),
            SignatureStatus.KEY_UNAVAILABLE,
            domain,
            code,
        )
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise PublicKeyFetchError(
            "domain {0} returned more than a key for the public key".format(
                _quoted(domain)
            ),
            SignatureStatus.KEY_UNAVAILABLE,
            domain,
            code,
        )
    return body.decode("utf-8", errors="replace")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect, so the key is only ever read from the
    creator domain the OWID names and over the scheme the caller chose.

    urllib follows a redirect to any host and any of http, https or ftp,
    so without this a creator whose domain answered 302 to some other
    host, or to plain http, would have that other place's key trusted
    as its own, and a network attacker could put a key there. Returning
    None makes urlopen raise the 3xx as an HTTPError, which the transport
    hands back as the response code and the caller reads as the key
    being unavailable, which is what it is."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirects())


async def _urllib_transport(url: str, timeout: float) -> Tuple[int, bytes]:
    """The transport used unless the caller supplies one. It runs urllib on
    a worker thread, which is blocking I/O on a worker thread rather than a
    non-blocking request, so the event loop is free during the request but a
    thread is not. Supply an aiohttp or httpx based transport for a fully
    non-blocking one. Redirects are not followed (see _NoRedirects)."""
    return await asyncio.to_thread(_urllib_request, url, timeout)


def _urllib_request(url: str, timeout: float) -> Tuple[int, bytes]:
    """The blocking request behind the default transport, run on a worker
    thread and never on the event loop. A refusal carrying a response code
    is returned as that code, and only the failure to obtain any response at
    all is raised."""
    request = urllib.request.Request(
        url, headers={"Accept": "text/plain"}, method="GET"
    )
    try:
        with _opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as refused:
        # A response arrived, so the code is the answer. The body of a
        # refusal is not a key and is not read.
        refused.close()
        return refused.code, b""


def _check_domain(domain: str) -> None:
    """Refuses a domain that would change the shape of the URL rather than
    name a host in it.

    The domain arrives inside an OWID, which came from outside, so the text is
    not the package's own. Letters, digits, dots and hyphens are all a domain
    name needs, and anything else could add a query, a fragment, a port,
    credentials or a path and send the request somewhere other than the
    creator.
    """
    if not domain:
        raise OwidError("the OWID carries no domain")
    for character in domain:
        allowed = (
            "a" <= character <= "z"
            or "A" <= character <= "Z"
            or "0" <= character <= "9"
            or character in ".-"
        )
        if not allowed:
            # The domain is not repeated back, because the text arrived from
            # outside and a refusal is often logged.
            raise OwidError(
                "the domain in the OWID is not a domain name this package "
                "will request a key from"
            )


def _quoted(value: str) -> str:
    """The value in single quotes, for a message."""
    return "'" + value + "'"
