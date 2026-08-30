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
"""Low level read and write helpers for the OWID binary format.

The format uses little endian unsigned 32 bit integers, null terminated
strings, and a fixed 64 byte signature. The date is stored as the count of
hours (version 1) or minutes (versions 2 and 3) since the base date.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from .error import OwidError
from .version import Version

#: The length of an OWID signature in bytes. The ECDSA P-256 signature is the
#: 32 byte r value followed by the 32 byte s value.
SIGNATURE_LENGTH = 64

#: The base date for OWIDs. The date and time information is stored as the
#: number of hours or minutes after this instant.
BASE_DATE = datetime(2020, 1, 1, tzinfo=timezone.utc)

#: The longest creator domain the reader will accept, in characters. RFC 1035
#: section 2.3.4, "Size limits", restricts the total length of a domain name,
#: being the label octets and the label length octets, to 255 octets or less.
#: An OWID stores the presentation form, the text "example.com", where the
#: dots stand in for the label length octets and the root label has no text at
#: all, so two of those 255 octets have no text equivalent and the limit on
#: the text is two fewer. A domain is ASCII, so a character is a byte here.
MAXIMUM_DOMAIN_LENGTH = 255 - 2


class Reader:
    """Sequential reader over a byte buffer."""

    def __init__(self, buffer: bytes) -> None:
        self._buffer = buffer
        self._position = 0

    def read_byte(self) -> int:
        """Reads a single byte."""
        if self._position >= len(self._buffer):
            raise OwidError("buffer ended before the OWID was complete")
        value = self._buffer[self._position]
        self._position += 1
        return value

    def read_bytes(self, count: int) -> bytes:
        """Reads the given number of bytes."""
        end = self._position + count
        if end > len(self._buffer):
            raise OwidError("buffer ended before the OWID was complete")
        value = self._buffer[self._position:end]
        self._position = end
        return value

    def read_string(self) -> str:
        """Reads bytes up to the null terminator and decodes them as UTF-8.

        The only null terminated string in an OWID is the creator domain, and
        a domain has a published maximum length, so the search for the
        terminator stops after MAXIMUM_DOMAIN_LENGTH bytes rather than running
        to the end of the buffer. A buffer whose terminator is missing or
        corrupted is refused as soon as that window is exhausted, so the work
        a hostile buffer can ask for is fixed by the constant rather than
        growing with the length of the input.
        """
        window_end = self._position + MAXIMUM_DOMAIN_LENGTH + 1
        terminator = self._buffer.find(b"\0", self._position, window_end)
        if terminator < 0:
            if len(self._buffer) < window_end:
                raise OwidError("buffer ended before the OWID was complete")
            raise OwidError(
                "domain is longer than the '{0}' character maximum".format(
                    MAXIMUM_DOMAIN_LENGTH
                )
            )
        try:
            value = self._buffer[self._position:terminator].decode("utf-8")
        except UnicodeDecodeError:
            raise OwidError("domain bytes are not valid UTF-8")
        self._position = terminator + 1
        return value

    def read_u32(self) -> int:
        """Reads an unsigned 32 bit little endian integer."""
        if self._position + 4 > len(self._buffer):
            raise OwidError("buffer ended before the OWID was complete")
        value = struct.unpack_from("<I", self._buffer, self._position)[0]
        self._position += 4
        return value

    def read_byte_array(self) -> bytes:
        """Reads the payload, being a byte array prefixed with its length as
        an unsigned 32 bit integer.

        The length is whatever the sender declared, so it is checked against
        the bytes actually present before anything is sized by it. A valid
        OWID is the declared payload followed by the signature and nothing
        else, so the length must equal the bytes remaining less the signature
        length, and any other length, short or long, is refused here. The
        same check refuses a signature shorter than 64 bytes and any byte
        after the signature, which until 28 August 2026 this reader ignored.
        """
        count = self.read_u32()
        remaining = len(self._buffer) - self._position
        if remaining != count + SIGNATURE_LENGTH:
            raise OwidError(
                "OWID payload length '{0}' does not match the '{1}' bytes "
                "present, of which the final '{2}' must be the "
                "signature".format(count, remaining, SIGNATURE_LENGTH)
            )
        return self.read_bytes(count)

    def read_signature(self) -> bytes:
        """Reads the fixed length signature."""
        return self.read_bytes(SIGNATURE_LENGTH)

    def read_date(self, version: Version) -> datetime:
        """Reads the date using the encoding associated with the version."""
        if version == Version.VERSION1:
            high = self.read_byte()
            low = self.read_byte()
            hours = (high << 8) | low
            return BASE_DATE + timedelta(hours=hours)
        if version in (Version.VERSION2, Version.VERSION3):
            minutes = self.read_u32()
            return BASE_DATE + timedelta(minutes=minutes)
        raise OwidError("OWID version '{0}' not supported".format(version.as_byte()))


def write_byte(buffer: bytearray, value: int) -> None:
    """Appends a single byte."""
    buffer.append(value)


def write_string(buffer: bytearray, value: str) -> None:
    """Appends the string followed by the null terminator.

    The string must not contain a null character because that would conflict
    with the terminator.

    The only string written this way is the creator domain, and the reader
    refuses a domain longer than MAXIMUM_DOMAIN_LENGTH, so a longer one is
    refused here as well and the library never emits an OWID that it would
    then refuse to read. The length compared is the encoded bytes, because
    those are what the reader walks, and for the ASCII a domain is made of
    they are the same count as the characters.
    """
    encoded = value.encode("utf-8")
    if 0 in encoded:
        raise OwidError("domain '{0}' is not valid".format(value))
    if len(encoded) > MAXIMUM_DOMAIN_LENGTH:
        raise OwidError(
            "domain is longer than the '{0}' character maximum".format(
                MAXIMUM_DOMAIN_LENGTH
            )
        )
    buffer.extend(encoded)
    buffer.append(0)


def write_u32(buffer: bytearray, value: int) -> None:
    """Appends an unsigned 32 bit little endian integer."""
    buffer.extend(struct.pack("<I", value))


def write_byte_array(buffer: bytearray, value: bytes) -> None:
    """Appends a byte array prefixed with its length as an unsigned 32 bit
    integer."""
    if len(value) > 0xFFFFFFFF:
        raise OwidError(
            "payload length '{0}' exceeds the unsigned 32 bit limit".format(len(value))
        )
    write_u32(buffer, len(value))
    buffer.extend(value)


def write_signature(buffer: bytearray, value: bytes) -> None:
    """Appends the fixed length signature, validating the length."""
    if len(value) != SIGNATURE_LENGTH:
        raise OwidError(
            "signature length '{0}' not compatible with '{1}' OWID "
            "signature length".format(len(value), SIGNATURE_LENGTH)
        )
    buffer.extend(value)


def write_date(buffer: bytearray, date: datetime, version: Version) -> None:
    """Appends the date using the encoding associated with the version."""
    delta = date - BASE_DATE
    if version == Version.VERSION1:
        hours = delta.days * 24 + delta.seconds // 3600
        if hours < 0 or hours > 0xFFFF:
            raise OwidError(
                "date can not be stored in the encoding for the OWID version"
            )
        buffer.extend(struct.pack(">H", hours))
        return
    if version in (Version.VERSION2, Version.VERSION3):
        minutes = int(delta.total_seconds() // 60)
        if minutes < 0 or minutes > 0xFFFFFFFF:
            raise OwidError(
                "date can not be stored in the encoding for the OWID version"
            )
        write_u32(buffer, minutes)
        return
    raise OwidError("OWID version '{0}' not supported".format(version.as_byte()))
