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

An OWID records that the processor operating a domain handled the payload at
the date and time given. Once signed it is immutable. Any change to the fields
will cause verification to fail.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from . import io
from .crypto import Crypto
from .error import OwidError
from .version import DEFAULT_VERSION, Version

if TYPE_CHECKING:
    # Only for the annotations below. Importing parse here at run time would
    # be a cycle, because parse imports this module to build the OWID it hands
    # back, so both names are resolved by the type checker alone.
    from .parse import ParseResult
    from .status import SignatureStatus


def _encode_base64(value: bytes) -> str:
    """Encodes bytes to a standard alphabet base 64 string with padding."""
    return base64.b64encode(value).decode("ascii")


#: Passed to Owid.__init__ by the two paths allowed to build one. Python
#: cannot make a constructor package private, so the boundary is kept by
#: asking for something a caller outside this package has no reason to have.
_INTERNAL = object()


class Owid:
    """OWID structure which can be used as a node in a tree.

    An OWID is a claim about who created some data and when, and it is only
    worth anything because it is signed. A caller therefore cannot build one.
    An instance arrives either from parsing bytes that were already a complete
    OWID, or from a Creator that signs one into existence. There is
    deliberately no way to assemble a half made one, because an unsigned OWID
    is indistinguishable from a signed one to the code downstream of it, and
    the difference only surfaces later when a verification fails somewhere
    nobody is watching.

    The payload and signature are handed out as copies for the same reason: a
    parsed OWID's signature covers its fields as they arrived, so code that
    could change them afterwards would hold something whose signature no
    longer describes it.
    """

    def __init__(
        self,
        version: Version = DEFAULT_VERSION,
        domain: str = "",
        date: Optional[datetime] = None,
        payload: bytes = b"",
        signature: bytes = b"",
        _token: object = None,
    ) -> None:
        if _token is not _INTERNAL:
            raise OwidError(
                "an OWID cannot be constructed directly. Use "
                "Owid.parse or Owid.parse_bytes to read "
                "one, or Creator.create to sign a new one"
            )
        self._version = version
        self._domain = domain
        self._date = date if date is not None else datetime.now(timezone.utc)
        self._payload = bytes(payload)
        self._signature = bytes(signature)

    @property
    def version(self) -> Version:
        """The byte version of the OWID."""
        return self._version

    @property
    def domain(self) -> str:
        """Domain associated with the creator."""
        return self._domain

    @property
    def date(self) -> datetime:
        """The date and time to the nearest minute in UTC of the creation."""
        return self._date

    @property
    def payload(self) -> bytes:
        """Bytes that form the payload.

        Read only, and bytes rather than a mutable buffer, because the
        signature covers the payload as it arrived. Code able to change it
        would hold something whose signature no longer describes it.
        """
        return self._payload

    @property
    def signature(self) -> bytes:
        """Signature over the fields of this OWID without the signature
        field."""
        return self._signature

    @classmethod
    def _create(
        cls,
        version: Version = DEFAULT_VERSION,
        domain: str = "",
        date: Optional[datetime] = None,
        payload: bytes = b"",
        signature: bytes = b"",
    ) -> "Owid":
        """Builds an instance from fields a parser or creator has validated."""
        return cls(
            version=version,
            domain=domain,
            date=date,
            payload=payload,
            signature=signature,
            _token=_INTERNAL,
        )

    @classmethod
    def parse(cls, value) -> "ParseResult":
        """Reads a complete OWID from its base 64 form.

        Returns a result that is truthy on success and carries the OWID only
        then, with a named reason either way, so ``if result:`` reads the way
        Python reads. Malformed input is an ordinary outcome rather than an
        exception, because the data comes from outside and whoever sends it
        chooses how often it is wrong.
        """
        from .parse import parse_base64

        return parse_base64(value)

    @classmethod
    def parse_prefix(cls, buffer) -> "ParseResult":
        """Reads one OWID from the start of a buffer that may hold more.

        The framed read. What follows the envelope is left alone, because it
        may be the next one rather than rubbish, and the result says how many
        bytes this envelope occupied so a caller can walk a run of them.
        """
        from .parse import parse_prefix

        return parse_prefix(buffer)

    @classmethod
    def parse_bytes(cls, buffer) -> "ParseResult":
        """Reads a complete OWID from a buffer holding exactly one."""
        from .parse import parse_bytes

        return parse_bytes(buffer)

    @classmethod
    def _from_byte_array_or_raise(cls, buffer: bytes) -> "Owid":
        """The raising counterpart of parse_bytes, over the low level reader.

        Private, and not the way to read external data, because bytes that
        are not an OWID are an ordinary outcome and parse_bytes reports the
        reason rather than raising. This route survives so the tests can
        assert the messages the low level reader gives.

        The buffer must hold exactly one OWID, ending with the 64 byte
        signature. Raises OwidError if the first byte is not a known
        version, the buffer is too short for the remaining fields, or the
        declared payload length does not leave exactly the signature at the
        end of the buffer.
        """
        reader = io.Reader(bytes(buffer))
        return cls._from_reader(reader)

    @classmethod
    def _from_reader(cls, reader: "io.Reader") -> "Owid":
        """Creates an OWID by reading the next fields from the reader."""
        version = Version.from_byte(reader.read_byte())
        if version == Version.EMPTY:
            return cls._create(version=version)
        domain = reader.read_string()
        date = reader.read_date(version)
        payload = reader.read_byte_array()
        signature = reader.read_signature()
        return cls._create(
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

    def signed_bytes(self) -> bytes:
        """The bytes the signature covers, being the fields of this OWID
        without the signature field and nothing else."""
        buffer = bytearray()
        self._to_buffer_no_signature(buffer)
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

    def verify_with_crypto(self, crypto: Crypto) -> bool:
        """Verifies this OWID using the crypto instance provided."""
        return crypto.verify_byte_array(self.signed_bytes(), self.signature)

    def verify_with_public_key(self, public_pem: str) -> bool:
        """Verifies this OWID using the public key in SPKI PEM form
        provided."""
        crypto = Crypto.new_verify_only(public_pem)
        return self.verify_with_crypto(crypto)

    def signature_status(self, public_pem: str) -> "SignatureStatus":
        """Says whether the signature is genuine, or why that could not be
        decided.

        Only two of the answers are about the signature. The rest say the
        question could not be answered, which is a different thing and must
        never be reported as a forgery. A key that cannot be decoded leaves the
        signature unjudged, and a caller acting on "invalid" would reject good
        identifiers during an outage. On 30 August 2026 the key endpoints
        served PEM a strict parser rejects and every offline verification
        failed, with the keys and the identifiers both fine.
        """
        from .status import SignatureStatus

        if not public_pem:
            return SignatureStatus.KEY_UNAVAILABLE
        if len(self._signature) != io.SIGNATURE_LENGTH:
            return SignatureStatus.INVALID_SIGNATURE_LENGTH
        try:
            crypto = Crypto.new_verify_only(public_pem)
        except Exception:
            # The key is the thing at fault, not the identifier.
            return SignatureStatus.INVALID_KEY
        try:
            matched = crypto.verify_byte_array(self.signed_bytes(), self._signature)
        except Exception:
            # The provider failed on inputs that were themselves fine.
            return SignatureStatus.VERIFICATION_ERROR
        return (
            SignatureStatus.SIGNATURE_VALID
            if matched
            else SignatureStatus.SIGNATURE_INVALID
        )

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
