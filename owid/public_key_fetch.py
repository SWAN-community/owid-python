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

The end point is /owid/api/v{n}/public-key?date={minutes}&format=spki, where
the version in the path is the version byte of the OWID being checked rather
than a constant, the minutes are counted from 2020-01-01 in the same way the
OWID stores the date, and the format names the one encoding of the key this
package reads. Creators rotate weekly, so without the date only
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

The creator answers with the key and the moments it is valid from and to, and
the key is held by creator for that whole span, so an identifier dated inside
it is verified without a request whichever minute it carries. A creator that
states no span has its key held against the minutes it confirms. A signature
that fails under the key selected, where the identifier is dated within the
clock drift allowance of an edge of the span the creator stated for that key,
is checked against the key for the minute just beyond that edge before it is
reported as not matching. Where the creator's own statement puts the
identifier's date outside the span of the key it answered with and nothing
verifies, the key is reported as unavailable rather than the signature as not
matching, because a key that was not in force proves nothing about the
identifier. Two callers who await the same key at the same moment share one
request rather than making two.

The Java port answers the same question with PublicKeyFetch, the Rust port
with Owid::verify_status and the Go port with SignatureStatusFromDomain.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import http.client
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from . import endpoints, io
from .endpoints import validate_public_key_answer
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
#: How far a creator's clock may run ahead of or behind this one's, in
#: minutes.
#:
#: It is used in two places. A creator that does not state the end of the span
#: of the key it answers with reads a date later than its own now as now, so
#: within this window of now this process cannot tell whether the creator read
#: the minute as its past or as its present, and nothing learned from such an
#: answer is held or served. And a creator's signing machines may not agree
#: with the creator's own schedule to the minute, so an identifier dated within
#: this window of an edge of the span the creator stated for a key that does
#: not verify under that key is checked against the key for the minute just
#: beyond that edge before it is reported as not matching.
CLOCK_DRIFT_ALLOWANCE_MINUTES = 15

#: The last minute the date field of an OWID can hold, which is where a span
#: stated with a start and no end runs to.
_LAST_MINUTE = 0xFFFFFFFF

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
    """One key a creator has answered with, and the span of minutes the key
    is known to cover.

    A creator's key is in force from the start of its period until the next
    key starts, so a key the creator confirms at two minutes was in force at
    every minute between them. Where the creator stated the span in its
    answer the span is explicit and complete, and an identifier dated
    anywhere inside it is verified without a request. Otherwise the span
    grows as the creator confirms the same key for more minutes.
    """

    __slots__ = ("pem", "first", "last", "explicit", "open_ended")

    def __init__(
        self, pem: str, first: int, last: int, explicit: bool, open_ended: bool
    ) -> None:
        #: The key in PEM form, as the creator served it.
        self.pem = pem
        #: The earliest minute the key is known to cover.
        self.first = first
        #: The latest minute the key is known to cover.
        self.last = last
        #: Whether the creator stated the whole span itself.
        self.explicit = explicit
        #: Whether the creator stated the start of the span and no end, so
        #: that as far as the creator has said the key is in force until
        #: further notice, whatever this cache holds it for.
        self.open_ended = open_ended

    def covers(self, minute: int) -> bool:
        """Whether the minute lies within the known span."""
        return self.first <= minute <= self.last


class _KeyAnswer:
    """What the cache or a fetch answers with. The key, and where the creator
    stated one, the span of minutes the creator says the key covers, so that
    a caller can tell whether the identifier it is checking sits near an edge
    of the span, or outside it altogether. A span stated with a start and no
    end runs to the last minute there is."""

    __slots__ = ("pem", "first", "last", "known")

    def __init__(
        self, pem: str, first: int = 0, last: int = 0, known: bool = False
    ) -> None:
        #: The key in PEM form.
        self.pem = pem
        #: The first minute the creator says the key covers.
        self.first = first
        #: The last minute the creator says the key covers.
        self.last = last
        #: Whether the creator stated a span at all.
        self.known = known

    def covers(self, minute: int) -> bool:
        """Whether the minute lies within the stated span."""
        return self.known and self.first <= minute <= self.last


#: Keys already fetched, by the creator's key end point, which is the key URL
#: without its date. Each end point holds the keys the creator has answered
#: with, each with the span of minutes the creator has confirmed it for.
#:
#: The specification asks implementations to cache so that verifying many
#: identifiers does not mean repeating requests to another processor. The key
#: URL carries the date of the identifier being verified, in minutes, and a
#: creator's key changes on the order of a week. Keyed by end point and span rather than by the whole URL, an identifier dated
#: between two minutes the creator has already answered for is verified
#: without a request.
_cache: Dict[str, List[_HeldKey]] = {}
#: How many keys are held across every end point.
_held_keys = 0
#: Fetches still running, held against the URL, so that a caller who asks for
#: a key while the request for it is in flight awaits that request rather
#: than making another. Each is a future any thread can wait on, so callers
#: on different event loops in different threads share one request as well.
#: An entry is removed when its fetch finishes, whatever the outcome.
_in_flight: Dict[str, "concurrent.futures.Future[_KeyAnswer]"] = {}
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
        query = "date={0}&format={1}".format(minutes, endpoints.SPKI_FORMAT)
    else:
        query = "format={0}".format(endpoints.SPKI_FORMAT)
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
    transport: Optional[Transport] = None,
) -> SignatureStatus:
    """Says whether the signature on the OWID is genuine, fetching the key
    that was in force when the OWID was signed from the creator domain.

    A key that cannot be fetched is SignatureStatus.KEY_UNAVAILABLE, as is
    one the creator says was not in force at the OWID's date, and one that
    arrives in a form this package cannot read is SignatureStatus.INVALID_KEY.
    None of these is SignatureStatus.SIGNATURE_INVALID, because an outage or a
    badly served key leaves the signature unjudged, and reporting either as
    invalid would read as an attack.
    """
    try:
        url = public_key_url(owid, scheme)
    except OwidError:
        return SignatureStatus.KEY_UNAVAILABLE
    return await _signature_status_at_url(owid, url, transport)


async def verify(
    owid: Owid,
    scheme: str,
    transport: Optional[Transport] = None,
) -> bool:
    """Returns True only when the signature verifies under the key the
    creator served for the date the OWID carries. Every other outcome, a
    signature that does not match included, is False, so ask
    signature_status where the difference changes what the caller does."""
    status = await signature_status(owid, scheme, transport)
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
    transport: Optional[Transport] = None,
) -> SignatureStatus:
    """The work signature_status does once the URL is known, kept apart so
    that the tests drive the real fetch against a key end point the tests can
    stand up locally rather than against a near copy of the fetch.

    The signature is checked under the key the end point serves for the
    OWID's own date, and under the neighbouring key where the date is within
    the clock drift allowance of an edge of the span the creator stated. A
    key the creator says was not in force at the OWID's date proves nothing
    about the identifier, so where nothing verifies under such a key the
    answer is that the key is unavailable and not that the signature does not
    match."""
    try:
        answer = await _key_at_url(url, owid.domain, transport)
    except PublicKeyFetchError as failed:
        return failed.status
    except OwidError:
        return SignatureStatus.KEY_UNAVAILABLE
    status = owid.signature_status(answer.pem)
    if status is not SignatureStatus.SIGNATURE_INVALID:
        return status
    minute = io.minutes_since_base(owid.date)
    if minute < 0:
        return status
    if await _neighbour_verifies(owid, minute, url, answer, transport):
        return SignatureStatus.SIGNATURE_VALID
    if answer.known and not answer.covers(minute):
        return SignatureStatus.KEY_UNAVAILABLE
    return status


async def _neighbour_verifies(
    owid: Owid,
    minute: int,
    url: str,
    tried: _KeyAnswer,
    transport: Optional[Transport],
) -> bool:
    """Whether a key neighbouring the one the OWID's own minute selected
    verifies the signature instead.

    A creator's signing machines may not agree with its own schedule to the
    minute, so an identifier dated just after a key started may have been
    signed with the key before it, and one dated just before may have been
    signed with the key after. Where the signature does not verify under the
    key selected and the OWID's minute is within the clock drift allowance of
    an edge of the span the creator stated for that key, the key for the
    minute just beyond that edge is asked for and tried. A key already held
    for that minute is not asked for again, and a neighbour that turns out to
    be the same key is not tried again. A creator that stated no span has one
    key and no schedule, so there is no neighbour to try. This costs at most
    two more requests, and only for a signature that has already failed.
    """
    if not tried.known:
        return False
    beyond: List[int] = []
    if tried.first > 0 and _near_edge(minute, tried.first):
        beyond.append(tried.first - 1)
    if tried.last < _LAST_MINUTE and _near_edge(minute, tried.last):
        beyond.append(tried.last + 1)
    for at in beyond:
        try:
            neighbour = await _key_at_url(
                "{0}?date={1}&format={2}".format(
                    _end_point_of(url), at, endpoints.SPKI_FORMAT
                ),
                owid.domain,
                transport,
            )
        except OwidError:
            # A neighbour that cannot be obtained leaves the failure under
            # the selected key standing.
            continue
        if neighbour.pem == tried.pem:
            continue
        if owid.signature_status(neighbour.pem) is SignatureStatus.SIGNATURE_VALID:
            return True
    return False


def _near_edge(minute: int, edge: int) -> bool:
    """Whether the minute is no further from the edge minute than the clocks
    of a creator's signing machines are allowed to differ from its
    schedule."""
    return abs(minute - edge) <= CLOCK_DRIFT_ALLOWANCE_MINUTES


async def _public_key_pem_at_url(
    url: str, domain: str, transport: Optional[Transport] = None
) -> str:
    """The PEM of the key the URL asks for. See _key_at_url."""
    return (await _key_at_url(url, domain, transport)).pem


async def _key_at_url(
    url: str, domain: str, transport: Optional[Transport] = None
) -> _KeyAnswer:
    """Fetches the key the URL asks for, with the span it is known to cover.
    Answered from the cache where a held key is known to cover the minute the
    URL names, from the request already in flight where another caller on this
    event loop is fetching the same URL now, and otherwise by asking the
    creator."""
    loop = asyncio.get_running_loop()
    end_point = _end_point_of(url)
    with _lock:
        held = _held_for(end_point, url)
        if held is not None:
            return held
        shared = _in_flight.get(url)
        lead = shared is None
        if shared is None:
            shared = concurrent.futures.Future()
            _in_flight[url] = shared
    if lead:
        # This caller is the one that adds the entry, so this caller is the
        # one that performs the request. Every other caller arriving before
        # it ends, on this loop or any other, waits on the future just added.
        task = loop.create_task(_fetch_and_hold(url, end_point, domain, transport, shared))
        task.add_done_callback(_mark_observed)
    # Shielded, because cancelling one caller must not cancel the request
    # that other callers are waiting on, and a request on a worker thread
    # cannot be stopped part way in any case. The answer still lands in the
    # cache for the next caller.
    return await asyncio.shield(asyncio.wrap_future(shared))


async def _fetch_and_hold(
    url: str,
    end_point: str,
    domain: str,
    transport: Optional[Transport],
    shared: "concurrent.futures.Future[_KeyAnswer]",
) -> _KeyAnswer:
    """The one request for a URL, run as a task whose outcome every caller
    waiting for that URL receives through the shared future. Holds the answer
    against the span it states, or the minute asked about where it states
    none, and forgets the request whatever the outcome so that a failed fetch
    is tried again by the next caller."""
    try:
        body = await _read(url, domain, transport)
        pem, start, end = _parse_answer(body, domain)
        with _lock:
            answer = _hold(end_point, url, pem, start, end)
            if _in_flight.get(url) is shared:
                del _in_flight[url]
        shared.set_result(answer)
        return answer
    except BaseException as failed:
        with _lock:
            if _in_flight.get(url) is shared:
                del _in_flight[url]
        shared.set_exception(failed)
        raise


def _parse_answer(body: str, domain: str) -> Tuple[str, Optional[int], Optional[int]]:
    """Reads a public key answer, returning the PEM and the span in minutes
    since the base date. The end is the minute the next key starts. Either is
    None where the answer does not state it. An answer that is not the JSON
    form the specification requires, the PEM alone among the other forms, or
    that fails the checks a creator applies before sending it, is reported as
    a key that cannot be read."""
    try:
        answer = json.loads(body)
    except ValueError as failed:
        raise PublicKeyFetchError(
            "domain {0} did not answer with the JSON form the specification "
            "requires for the public key".format(_quoted(domain)),
            SignatureStatus.INVALID_KEY,
            domain,
        ) from failed
    try:
        pem, valid_from, valid_to = validate_public_key_answer(answer, None)
    except OwidError as failed:
        raise PublicKeyFetchError(
            "domain {0} answered with a public key answer that is not valid: "
            "{1}".format(_quoted(domain), failed),
            SignatureStatus.INVALID_KEY,
            domain,
        ) from failed
    return pem, _minutes_or_none(valid_from), _minutes_or_none(valid_to)


def _minutes_or_none(moment: Optional[datetime]) -> Optional[int]:
    """The moment as minutes since the base date, or None where there is no
    moment or it is before the count begins."""
    if moment is None:
        return None
    minutes = io.minutes_since_base(moment)
    return minutes if minutes >= 0 else None


def _end_point_of(url: str) -> str:
    """The key URL without its query, which names the scheme, the creator and
    the version, and so the key end point being asked."""
    return url.split("?", 1)[0]


def _minute_and_recency(url: str) -> Tuple[Optional[int], bool]:
    """The minute the URL asks about, or None where it names none, and whether
    it lies within the clock drift allowance of now or later, which is a
    minute a creator that does not state its spans may have read as its
    present rather than as the minute named."""
    now = io.minutes_since_base(datetime.now(timezone.utc))
    query = urllib.parse.urlsplit(url).query
    for name, value in urllib.parse.parse_qsl(query):
        if name == "date":
            try:
                minute = int(value)
            except ValueError:
                return None, False
            return minute, minute > now - CLOCK_DRIFT_ALLOWANCE_MINUTES
    return None, False


def _held_for(end_point: str, url: str) -> Optional[_KeyAnswer]:
    """The key held for the end point that is known to cover the minute the
    URL asks about, or None where none is. Called under the lock.

    A minute within the drift allowance of now is only served where the
    creator itself stated the span, because a span confirmed minute by minute
    says nothing certain about such a minute."""
    minute, recent = _minute_and_recency(url)
    if minute is None:
        return None
    for key in _cache.get(end_point, ()):
        if key.covers(minute) and (key.explicit or not recent):
            return _stated_for(key)
    return None


def _stated_for(key: _HeldKey) -> _KeyAnswer:
    """The span the creator stated for a held key, which is the whole held
    span where the creator stated it, runs to the last minute there is where
    the creator stated a start and no end, and is nothing where the creator
    stated no span."""
    if key.explicit:
        return _KeyAnswer(key.pem, key.first, key.last, True)
    if key.open_ended:
        return _KeyAnswer(key.pem, key.first, _LAST_MINUTE, True)
    return _KeyAnswer(key.pem)


def _stated(pem: str, start: Optional[int], end: Optional[int]) -> _KeyAnswer:
    """The span the creator stated in its answer. See _stated_for."""
    if start is None:
        return _KeyAnswer(pem)
    if end is not None and end > start:
        return _KeyAnswer(pem, start, end - 1, True)
    return _KeyAnswer(pem, start, _LAST_MINUTE, True)


def _hold(
    end_point: str, url: str, pem: str, start: Optional[int], end: Optional[int]
) -> _KeyAnswer:
    """Records the creator's answer to the URL, being the key and, where the
    creator stated it, the span the key covers as the minute it came into
    force and the minute the next key starts. Returns the key with the span
    the creator stated for it. Called under the lock.

    With both the start and the end the whole span is held as the creator's
    own statement. With the start alone the key is held from the start up to
    the drift allowance behind now, because no later key can have started
    before then. With neither the minute asked about is held on its own, as
    long as it is not within the drift allowance of now. A key already held
    for the end point has its span widened to take in the new one. A key not
    held before is added, emptying the cache first when it is full, because
    the cache must not grow on the input of whoever presents the identifiers.
    """
    global _held_keys
    stated = _stated(pem, start, end)
    minute, recent = _minute_and_recency(url)
    explicit = False
    open_ended = False
    if start is not None and end is not None and end > start:
        first, last, explicit = start, end - 1, True
    elif start is not None:
        now = io.minutes_since_base(datetime.now(timezone.utc))
        first = start
        last = max(start, now - CLOCK_DRIFT_ALLOWANCE_MINUTES)
        open_ended = True
    elif minute is not None and not recent:
        first = last = minute
    else:
        return stated
    keys = _cache.get(end_point)
    if keys is not None:
        for key in keys:
            if key.pem == pem:
                if _widen(keys, key, first, last):
                    key.explicit = key.explicit or explicit
                    key.open_ended = not key.explicit and (
                        key.open_ended or open_ended
                    )
                # Where the span was not widened the creator has answered
                # with another key inside it before, which it does not do
                # unless it went back to a key it had left, and nothing more
                # is held about this key.
                return stated
        for other in keys:
            if other.last >= first and other.first <= last:
                return stated
    if _held_keys >= MAXIMUM_CACHED_KEYS:
        _cache.clear()
        _held_keys = 0
        keys = None
    if keys is None:
        keys = []
        _cache[end_point] = keys
    keys.append(_HeldKey(pem, first, last, explicit, open_ended))
    _held_keys += 1
    return stated


def _widen(keys: List[_HeldKey], key: _HeldKey, first: int, last: int) -> bool:
    """Widens the span of a held key to take in the span given, and says
    whether it did.

    The span is not widened across a minute the creator has answered with
    another key for, because that would mean the creator had gone back to a
    key it had left, and the minutes between the two spans are then not this
    key's to claim.
    """
    first = min(first, key.first)
    last = max(last, key.last)
    for other in keys:
        if other is not key and other.last >= first and other.first <= last:
            return False
    key.first = first
    key.last = last
    return True


def _mark_observed(task: "asyncio.Task[_KeyAnswer]") -> None:
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
        url, headers={"Accept": "application/json"}, method="GET"
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
