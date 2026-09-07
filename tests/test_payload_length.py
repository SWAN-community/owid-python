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
"""Tests for the payload length check in the OWID parse.

The payload length field of an OWID is whatever the sender declared, so
parsing must check it against the bytes present before sizing anything by
it. These tests prove that a declared length that does not leave exactly the
signature after the payload is refused, that refusing it costs no time or
memory sized by the declared number, and that a correctly sized envelope
still parses. The 64 byte signature is the fixed tail every valid OWID ends
with.
"""

from __future__ import annotations

import struct
import time
import tracemalloc
import unittest

from owid import SIGNATURE_LENGTH, Creator, Crypto, Owid, OwidError, Version

DOMAIN = "51d.es"
PAYLOAD = bytes([0x5A]) * 37
SIGNATURE = bytes([0x99]) * SIGNATURE_LENGTH


def envelope(declared_length: int, payload: bytes, signature: bytes) -> bytes:
    """A version 3 envelope, being the version byte, the domain with its
    terminator, four minute bytes, the declared payload length, the payload
    bytes given and the signature bytes given, so a test can make the
    declared length and the bytes present disagree."""
    buffer = bytearray()
    buffer.append(Version.VERSION3.as_byte())
    buffer.extend(DOMAIN.encode("ascii"))
    buffer.append(0)
    buffer.extend(struct.pack("<I", 1000))
    buffer.extend(struct.pack("<I", declared_length))
    buffer.extend(payload)
    buffer.extend(signature)
    return bytes(buffer)


class PayloadLengthTests(unittest.TestCase):
    def test_declared_length_matches_parses(self) -> None:
        """The declared length matches the bytes present, the signature is
        the last 64 bytes, and the envelope parses to the same payload."""
        owid = Owid._from_byte_array_or_raise(
            envelope(len(PAYLOAD), PAYLOAD, SIGNATURE)
        )
        self.assertEqual(owid.payload, PAYLOAD)
        self.assertEqual(owid.signature, SIGNATURE)
        self.assertEqual(owid.domain, DOMAIN)

    def test_matching_one_mebibyte_payload_parses(self) -> None:
        """A matching large payload is valid; size policy belongs upstream."""
        payload = b"\x5a" * (1024 * 1024)

        owid = Owid._from_byte_array_or_raise(
            envelope(len(payload), payload, SIGNATURE)
        )

        self.assertEqual(owid.payload, payload)

    def test_library_output_parses(self) -> None:
        """A round trip through the library's own signing path and writer
        still parses, so the check agrees with what the library itself
        produces."""
        crypto = Crypto.new()
        original = Creator(DOMAIN, crypto).create(PAYLOAD)
        parsed = Owid._from_byte_array_or_raise(original.as_byte_array())
        self.assertEqual(parsed.payload, PAYLOAD)
        self.assertEqual(parsed, original)
        self.assertTrue(parsed.verify_with_crypto(crypto))

    def test_declared_length_off_by_one_is_refused(self) -> None:
        """One more or one fewer than the bytes present is refused, because
        either leaves something other than exactly the signature at the
        end. The message names the declared length and the bytes present
        so the reader of a log can see which the sender got wrong."""
        present = len(PAYLOAD) + SIGNATURE_LENGTH
        for declared in (len(PAYLOAD) - 1, len(PAYLOAD) + 1):
            with self.subTest(declared=declared):
                with self.assertRaises(OwidError) as raised:
                    Owid._from_byte_array_or_raise(
                        envelope(declared, PAYLOAD, SIGNATURE)
                    )
                message = str(raised.exception)
                self.assertIn("'{0}'".format(declared), message)
                self.assertIn("'{0}'".format(present), message)

    def test_trailing_byte_after_signature_is_refused(self) -> None:
        """A byte after the signature is refused, because the signature
        must be the end of the envelope."""
        longer = envelope(len(PAYLOAD), PAYLOAD, SIGNATURE) + b"\x00"
        with self.assertRaises(OwidError):
            Owid._from_byte_array_or_raise(longer)

    def test_short_signature_is_refused(self) -> None:
        """A short signature is refused. The declared payload length is
        right for the payload, but the bytes after it are fewer than a
        signature."""
        with self.assertRaises(OwidError):
            Owid._from_byte_array_or_raise(
                envelope(len(PAYLOAD), PAYLOAD, SIGNATURE[:-1])
            )

    def test_mismatched_large_declaration_is_refused_without_allocating(
        self,
    ) -> None:
        """A large declaration whose payload bytes are absent is cheap.

        The envelope is a few dozen bytes while declaring 64 MiB, then 2 GiB,
        then the largest value the field can hold. The numeric values remain
        valid when the matching payload is present. Python cannot ask for
        the bytes allocated by
        the thread the way the .NET reference does, so two checks stand
        in. A loop of 1,000 parses must finish in under a second, which
        fails if each parse allocates the declared size, and tracemalloc
        must report a peak under 64 KiB for a single parse."""
        for declared in (64 * 1024 * 1024, 0x7FFFFFFF, 0xFFFFFFFF):
            with self.subTest(declared=declared):
                raw = envelope(declared, b"", b"")
                started = time.perf_counter()
                for _ in range(1000):
                    with self.assertRaises(OwidError):
                        Owid._from_byte_array_or_raise(raw)
                elapsed = time.perf_counter() - started
                self.assertLess(
                    elapsed,
                    1.0,
                    "declared {0} took {1:.3f}s for 1,000 parses".format(
                        declared, elapsed
                    ),
                )
                tracemalloc.start()
                try:
                    with self.assertRaises(OwidError):
                        Owid._from_byte_array_or_raise(raw)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertLess(
                    peak,
                    64 * 1024,
                    "declared {0} reached a peak of {1} bytes".format(
                        declared, peak
                    ),
                )

    def test_empty_payload_parses(self) -> None:
        """A declared length of zero followed by the 64 byte signature
        parses, so the check does not refuse the smallest valid payload."""
        owid = Owid._from_byte_array_or_raise(envelope(0, b"", SIGNATURE))
        self.assertEqual(owid.payload, b"")
        self.assertEqual(owid.signature, SIGNATURE)


if __name__ == "__main__":
    unittest.main()
