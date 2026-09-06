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

Only the standard library is used, through urllib, so the package keeps its
promise of no dependency beyond cryptography. This module is the one place in
the package that reaches the network. It is imported only when a caller asks
for it, and every function takes a transport of the caller's own for an
environment where urllib is not the right client.

The Java port answers the same question with PublicKeyFetch, the Rust port
with Owid::verify_status and the Go port with SignatureStatusFromDomain.
"""

from __future__ import annotations

import http.client
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, Optional, Sequence, Tuple

from . import endpoints, io
from .error import OwidError, PublicKeyFetchError
from .owid import Owid
from .status import SignatureStatus

#: How long to wait for the connection and then for the response, in seconds.
TIMEOUT_SECONDS = 10.0

#: The most keys held before the cache is emptied and filled again. A bound is
#: needed because a verifier sees identifiers from many domains and many
#: weeks, and an unbounded store would grow for as long as the process runs.
MAXIMUM_CACHED_KEYS = 1024

#: The most bytes accepted from a response. A public key PEM is a few hundred
#: bytes, so a body beyond this is not a key and is not held or decoded.
MAXIMUM_RESPONSE_BYTES = 65536

#: A transport takes the URL and the timeout in seconds and returns the
#: response code and the body. It raises OSError where no response could be
#: obtained at all, which is what urllib raises for a refused connection, a
#: name that does not resolve and a timeout. Supply one where urllib is not
#: the right client, for example behind a proxy that needs its own set up.
Transport = Callable[[str, float], Tuple[int, bytes]]

#: The schemes that make an HTTP request. A caller chooses the scheme, and one
#: that reads something other than a creator, such as file, is refused rather
#: than opened.
_ACCEPTED_SCHEMES = ("http", "https")

#: Keys already fetched, held against the URL they were fetched from.
#:
#: The specification asks implementations to cache so that verifying many
#: identifiers does not mean repeating requests to another processor. Holding
#: the key against the whole URL is safe because the URL names the domain,
#: the version and the minute, and the key a creator published for a minute
#: in the past does not change.
_cache: Dict[str, str] = {}
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


def public_key_pem(
    owid: Owid, scheme: str, transport: Optional[Transport] = None
) -> str:
    """Returns the public key PEM of the creator of the OWID, for the date the
    OWID carries.

    Raises PublicKeyFetchError if the key could not be obtained, carrying the
    status to report for the identifier, and OwidError if the OWID, the scheme
    or the domain is not usable.
    """
    return _public_key_pem_at_url(
        public_key_url(owid, scheme), owid.domain, transport
    )


def signature_status(
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
    return _signature_status_at_url(owid, url, others, transport)


def verify(
    owid: Owid,
    scheme: str,
    others: Optional[Sequence[Owid]] = None,
    transport: Optional[Transport] = None,
) -> bool:
    """Returns True only when the signature verifies under the key the
    creator served for the date the OWID carries. Every other outcome, a
    signature that does not match included, is False, so ask
    signature_status where the difference changes what the caller does."""
    status = signature_status(owid, scheme, others, transport)
    return status is SignatureStatus.SIGNATURE_VALID


def clear_cache() -> None:
    """Empties the cache of keys already fetched. Provided so that a long
    running process can release the memory, and so that a test can start from
    a known state."""
    with _lock:
        _cache.clear()


def _signature_status_at_url(
    owid: Owid,
    url: str,
    others: Optional[Sequence[Owid]] = None,
    transport: Optional[Transport] = None,
) -> SignatureStatus:
    """The work signature_status does once the URL is known, kept apart so
    that the tests drive the real fetch against a key end point the tests can
    stand up locally rather than against a near copy of the fetch."""
    try:
        pem = _public_key_pem_at_url(url, owid.domain, transport)
    except PublicKeyFetchError as failed:
        return failed.status
    except OwidError:
        return SignatureStatus.KEY_UNAVAILABLE
    return owid.signature_status(pem, others)


def _public_key_pem_at_url(
    url: str, domain: str, transport: Optional[Transport] = None
) -> str:
    """Fetches the PEM at the URL, answering from the cache where the same URL
    has already been fetched."""
    with _lock:
        cached = _cache.get(url)
    if cached is not None:
        return cached
    pem = _read(url, domain, transport)
    with _lock:
        if len(_cache) >= MAXIMUM_CACHED_KEYS:
            _cache.clear()
        _cache[url] = pem
    return pem


def _read(url: str, domain: str, transport: Optional[Transport]) -> str:
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
        code, body = (transport or _urllib_transport)(url, TIMEOUT_SECONDS)
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


def _urllib_transport(url: str, timeout: float) -> Tuple[int, bytes]:
    """The transport used unless the caller supplies one. A refusal carrying
    a response code is returned as that code, and only the failure to obtain
    any response at all is raised. Redirects are not followed (see
    _NoRedirects)."""
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
