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
"""The OWID structure and the reading, writing, and verification it provides.

An OWID records that the processor operating a domain handled the payload, and
any other OWIDs covered by the signature, at the date and time given. Once
signed it is immutable. Any change to the fields will cause verification to
fail.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from . import io
from .crypto import Crypto
from .error import OwidError
from .version import DEFAULT_VERSION, Version


def _decode_base64(value: str) -> bytes:
    """Decodes a standard alphabet base 64 string with or without padding.

    The encoded OWIDs occur both with and without padding, so reading must
    accept both. Missing padding is added before decoding.
    """
    cleaned = value.strip()
    remainder = len(cleaned) % 4
    if remainder == 2:
        cleaned += "=="
    elif remainder == 3:
        cleaned += "="
    elif remainder == 1:
        raise OwidError("base 64 decoding failed because the length is invalid")
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OwidError("base 64 decoding failed because {0}".format(exc))


def _encode_base64(value: bytes) -> str:
    """Encodes bytes to a standard alphabet base 64 string with padding."""
    return base64.b64encode(value).decode("ascii")


class Owid:
    """OWID structure which can be used as a node in a tree."""

    def __init__(
        self,
        version: Version = DEFAULT_VERSION,
        domain: str = "",
        date: Optional[datetime] = None,
        payload: bytes = b"",
        signature: bytes = b"",
    ) -> None:
        #: The byte version of the OWID.
        self.version = version
        #: Domain associated with the creator.
        self.domain = domain
        #: The date and time to the nearest minute in UTC of the creation.
        self.date = date if date is not None else datetime.now(timezone.utc)
        #: Bytes that form the payload.
        self.payload = payload
        #: Signature for this OWID and any others provided when signing.
        self.signature = signature

    @classmethod
    def from_base64(cls, value: str) -> "Owid":
        """Creates an OWID from a base 64 encoded string.

        Raises OwidError if the string is not valid base 64 or the bytes do
        not form a valid OWID.
        """
        return cls.from_byte_array(_decode_base64(value))

    @classmethod
    def from_byte_array(cls, buffer: bytes) -> "Owid":
        """Creates an OWID from its binary form.

        Raises OwidError if the first byte is not a known version or the
        buffer is too short for the remaining fields.
        """
        reader = io.Reader(bytes(buffer))
        return cls._from_reader(reader)

    @classmethod
    def _from_reader(cls, reader: "io.Reader") -> "Owid":
        """Creates an OWID by reading the next fields from the reader."""
        version = Version.from_byte(reader.read_byte())
        if version == Version.EMPTY:
            return cls(version=version)
        domain = reader.read_string()
        date = reader.read_date(version)
        payload = reader.read_byte_array()
        signature = reader.read_signature()
        return cls(
            version=version,
            domain=domain,
            date=date,
            payload=payload,
            signature=signature,
        )

    def as_byte_array(self) -> bytes:
        """Returns the OWID as a byte array.

        Raises OwidError if the OWID has not been signed or the fields can not
        be encoded.
        """
        buffer = bytearray()
        self.to_buffer(buffer)
        return bytes(buffer)

    def as_base64(self) -> str:
        """Returns the OWID as a base 64 encoded string."""
        return _encode_base64(self.as_byte_array())

    def to_buffer(self, buffer: bytearray) -> None:
        """Appends the OWID, including the signature, to the buffer
        provided."""
        self._to_buffer_no_signature(buffer)
        io.write_signature(buffer, self.signature)

    @staticmethod
    def empty_to_buffer(buffer: bytearray) -> None:
        """Writes an empty OWID marker. Used to indicate optional OWIDs in
        byte arrays."""
        io.write_byte(buffer, Version.EMPTY.as_byte())

    def _to_buffer_no_signature(self, buffer: bytearray) -> None:
        """Appends the fields other than the signature to the buffer. This is
        the data over which the signature is calculated."""
        io.write_byte(buffer, self.version.as_byte())
        io.write_string(buffer, self.domain)
        io.write_date(buffer, self.date, self.version)
        io.write_byte_array(buffer, self.payload)

    def data_for_crypto(self, others: Sequence["Owid"]) -> bytes:
        """Builds the byte array used for signing and verification.

        Contains the fields of this OWID without the signature, followed by
        the complete byte form of each of the others in the order provided.
        """
        buffer = bytearray()
        self._to_buffer_no_signature(buffer)
        for other in others:
            other.to_buffer(buffer)
        return bytes(buffer)

    def payload_as_string(self) -> str:
        """The payload interpreted as a string. Bytes that are not valid
        UTF-8 are replaced with the replacement character."""
        return self.payload.decode("utf-8", errors="replace")

    def payload_as_printable(self) -> str:
        """The payload as lower case hexadecimal for display purposes."""
        return self.payload.hex()

    def payload_as_base64(self) -> str:
        """The payload as a base 64 encoded string."""
        return _encode_base64(self.payload)

    def age_minutes(self) -> int:
        """Returns the number of complete minutes that have elapsed since the
        OWID was created. The granularity is to the nearest minute."""
        delta = datetime.now(timezone.utc) - self.date
        return int(delta.total_seconds() // 60)

    def verify_with_crypto(
        self, crypto: Crypto, others: Optional[Sequence["Owid"]] = None
    ) -> bool:
        """Verifies this OWID, and any others that were included when it was
        signed, using the crypto instance provided.

        Pass an empty sequence for others when the OWID was signed on its own.
        """
        if others is None:
            others = []
        data = self.data_for_crypto(others)
        return crypto.verify_byte_array(data, self.signature)

    def verify_with_public_key(
        self, public_pem: str, others: Optional[Sequence["Owid"]] = None
    ) -> bool:
        """Verifies this OWID, and any others that were included when it was
        signed, using the public key in SPKI PEM form provided."""
        crypto = Crypto.new_verify_only(public_pem)
        return self.verify_with_crypto(crypto, others)

    def __str__(self) -> str:
        """Formats the OWID as a base 64 string."""
        return self.as_base64()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Owid):
            return NotImplemented
        return (
            self.version == other.version
            and self.domain == other.domain
            and self.date == other.date
            and self.payload == other.payload
            and self.signature == other.signature
        )

    def __repr__(self) -> str:
        return (
            "Owid(version={0!r}, domain={1!r}, date={2!r}, "
            "payload_len={3}, signature_len={4})".format(
                self.version,
                self.domain,
                self.date,
                len(self.payload),
                len(self.signature),
            )
        )
