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

"""Reading an OWID from bytes without raising for malformed input."""

import base64
import binascii
from datetime import timedelta
from typing import NamedTuple, Optional

from .io import BASE_DATE, MAXIMUM_DOMAIN_LENGTH, SIGNATURE_LENGTH
from .status import ParseStatus
from .version import Version


class ParseResult(NamedTuple):
    """What a parse produced, and why.

    Truthy on success, so ``if result:`` reads naturally, while the value and
    the reason stay available for code that needs to say which of the expected
    problems it was.
    """

    #: True when the bytes were a complete, structurally valid OWID.
    ok: bool

    #: The OWID on success, otherwise None.
    owid: Optional[object]

    #: PARSED on success, otherwise the specific reason.
    status: ParseStatus

    #: How many bytes the envelope occupied. Only meaningful for a framed
    #: read, where a caller advances by this much to reach the next one.
    consumed: int = 0

    def __bool__(self) -> bool:
        return self.ok


def _failed(status: ParseStatus) -> ParseResult:
    return ParseResult(False, None, status, 0)


def parse_base64(value) -> ParseResult:
    """Reads a complete OWID from its base 64 form.

    The value may be anything at all: this is external data, and failing to be
    an OWID is an ordinary outcome rather than an error.
    """
    if value is None or value == "":
        return _failed(ParseStatus.MISSING_INPUT)
    if not isinstance(value, str):
        return _failed(ParseStatus.INVALID_INPUT_TYPE)
    # Encoded OWIDs occur both with and without padding, so reading accepts
    # both. Missing padding is added rather than the value being refused,
    # because an unpadded encoding is a normal way to carry one, not a fault.
    cleaned = value.strip()
    remainder = len(cleaned) % 4
    if remainder == 1:
        return _failed(ParseStatus.INVALID_BASE64)
    if remainder == 2:
        cleaned += "=="
    elif remainder == 3:
        cleaned += "="
    try:
        buffer = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return _failed(ParseStatus.INVALID_BASE64)
    return parse_bytes(buffer)


def parse_prefix(buffer) -> ParseResult:
    """Reads one OWID from the start of a buffer that may hold more after it.

    This is the framed contract. It differs from parse_bytes in exactly one
    place: a whole buffer knows where the envelope ends, so the declared
    payload must leave exactly the signature, while here what follows may be
    the next envelope rather than rubbish, so the declaration and the
    signature need only be present.

    The result carries how many bytes the envelope occupied, so a caller walks
    a run of them by slicing:

        while data:
            result = Owid.parse_prefix(data)
            if not result:
                break
            use(result.owid)
            data = data[result.consumed:]

    Nothing is consumed when an envelope is refused, because a half read one
    leaves a caller somewhere it cannot reason about.
    """
    return _parse(buffer, exact=False)


def parse_bytes(buffer) -> ParseResult:
    """Reads a complete OWID from a buffer holding exactly one.

    The buffer must be one whole OWID and nothing else. Data after the
    envelope is rejected, because on this surface there is nothing else it
    could belong to.

    The buffer is walked by index and every read is checked against what is
    left, so a malformed envelope is a comparison that fails rather than an
    exception that unwinds. That matters because whoever is sending the data
    chooses how often this fails and how large each attempt is.
    """
    return _parse(buffer, exact=True)


def _parse(buffer, exact: bool) -> ParseResult:
    """The one walk both reads share."""
    if buffer is None:
        return _failed(ParseStatus.MISSING_INPUT)
    if not isinstance(buffer, (bytes, bytearray, memoryview)):
        return _failed(ParseStatus.INVALID_INPUT_TYPE)

    data = bytes(buffer)
    total = len(data)
    if total < 1:
        # Nothing was supplied, which is not the same as data that stopped
        # part way through a field.
        return _failed(ParseStatus.MISSING_INPUT)

    # Imported here rather than at module scope: owid.py imports this module
    # for its try_ surfaces, so importing it back at the top would be a cycle.
    from .owid import Owid

    at = 1
    try:
        version = Version.from_byte(data[0])
    except Exception:
        return _failed(ParseStatus.UNSUPPORTED_VERSION)

    if version == Version.EMPTY:
        # The marker stands for an absent node inside a stream. It is not an
        # OWID: it carries no domain, date, payload or signature, so it can
        # never verify. Reading one here would hand a caller the one thing the
        # construction boundary exists to prevent, an instance with no
        # signature that looks like an identifier.
        return _failed(ParseStatus.UNSUPPORTED_VERSION)

    # The domain, terminated by a zero byte and no longer than the published
    # maximum.
    start = at
    limit = min(total, start + MAXIMUM_DOMAIN_LENGTH + 1)
    domain = None
    while at < limit:
        if data[at] == 0:
            domain = data[start:at].decode("ascii", errors="replace")
            at += 1
            break
        at += 1
    if domain is None:
        # Either the buffer ended inside the domain, or the domain ran past
        # the maximum without terminating. The second is a domain that cannot
        # be valid rather than data that merely stopped.
        if at >= total and (at - start) <= MAXIMUM_DOMAIN_LENGTH:
            return _failed(ParseStatus.UNEXPECTED_END)
        return _failed(ParseStatus.INVALID_DOMAIN_ENCODING)

    # The date, whose width depends on the version.
    if version == Version.VERSION1:
        if total - at < 2:
            return _failed(ParseStatus.UNEXPECTED_END)
        hours = (data[at] << 8) | data[at + 1]
        at += 2
        date = BASE_DATE + timedelta(hours=hours)
    else:
        if total - at < 4:
            return _failed(ParseStatus.UNEXPECTED_END)
        minutes = int.from_bytes(data[at:at + 4], "little")
        at += 4
        date = BASE_DATE + timedelta(minutes=minutes)

    if total - at < 4:
        return _failed(ParseStatus.UNEXPECTED_END)
    declared = int.from_bytes(data[at:at + 4], "little")
    at += 4

    # The declaration is the sender's claim about a payload not yet read, so
    # it is compared with what is actually present before anything is sized by
    # it. The subtraction is signed, so a buffer with fewer bytes left than a
    # signature needs gives a negative count, which can never equal a
    # declaration. Reporting that as a truncation would name a different fault
    # for the same evidence: what is certain is that the declared payload
    # cannot leave exactly the signature the version requires.
    #
    # The two contracts differ here, and only here. A whole buffer knows the
    # envelope boundary, so the declaration must leave exactly the signature
    # and no more. A framed read does not: what follows may be the next
    # envelope, so it needs the declaration and the signature to be present
    # and says nothing about the rest.
    present = (total - at) - SIGNATURE_LENGTH
    if present != declared if exact else present < declared:
        return _failed(ParseStatus.BYTE_COUNT_MISMATCH)

    payload = data[at:at + declared]
    at += declared
    signature = data[at:at + SIGNATURE_LENGTH]
    at += SIGNATURE_LENGTH

    if exact and at != total:
        # Unreachable while the count check above holds, and kept so a future
        # change to that arithmetic cannot silently start accepting trailing
        # bytes.
        return _failed(ParseStatus.MALFORMED_ENVELOPE)

    return ParseResult(
        True,
        Owid._create(
            version=version,
            domain=domain,
            date=date,
            payload=payload,
            signature=signature,
        ),
        ParseStatus.PARSED,
        at,
    )
