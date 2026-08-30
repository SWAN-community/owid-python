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
"""Tests for the domain length bound in the OWID parse.

The creator domain is stored as text followed by a zero terminator, so the
parse finds the end of the domain by walking forward to that terminator. If
the terminator is missing or corrupted the walk would otherwise run to the
end of the buffer, which is work an attacker chooses the size of. A domain
has a published maximum length, so these tests prove that a domain of the
maximum length still parses, that a longer one is refused, and that a buffer
whose terminator is missing or far away costs no more than the bound.
"""

from __future__ import annotations

import struct
import time
import tracemalloc
import unittest

from owid import SIGNATURE_LENGTH, Creator, Crypto, Owid, OwidError, Version
from owid.io import MAXIMUM_DOMAIN_LENGTH

#: A domain of exactly the maximum length, built from labels no longer than
#: the 63 characters RFC 1035 allows so that the value is a shape a real
#: domain could take rather than one long run of letters.
MAXIMUM_DOMAIN = ".".join(["a" * 63] * 3 + ["b" * 61])

PAYLOAD = bytes([0x5A]) * 37
SIGNATURE = bytes([0x99]) * SIGNATURE_LENGTH

#: The length of the domain field in the hostile buffers below. Large enough
#: that a walk over the whole of one is hundreds of thousands of times the
#: bounded walk, so the assertions on time and on memory separate the two
#: cases with room to spare.
HOSTILE_LENGTH = 64 * 1024 * 1024


def hostile(domain_bytes: bytes) -> bytes:
    """A buffer holding the version byte and the raw domain bytes given and
    nothing after them. Both callers hand over a domain field the reader must
    refuse, so nothing valid is needed after it, and the only zero byte in
    either buffer is the one the caller puts there itself."""
    return bytes([Version.VERSION3.as_byte()]) + domain_bytes


def envelope(domain_bytes: bytes) -> bytes:
    """A version 3 envelope built from the raw domain bytes given, being the
    version byte, those bytes, four minute bytes, the payload with its length
    and the signature. The domain bytes carry their own terminator, so a test
    can set the length of the domain and leave the rest of the envelope
    valid."""
    buffer = bytearray()
    buffer.append(Version.VERSION3.as_byte())
    buffer.extend(domain_bytes)
    buffer.extend(struct.pack("<I", 1000))
    buffer.extend(struct.pack("<I", len(PAYLOAD)))
    buffer.extend(PAYLOAD)
    buffer.extend(SIGNATURE)
    return bytes(buffer)


def terminated(domain: str) -> bytes:
    """The domain as ASCII followed by the zero terminator."""
    return domain.encode("ascii") + b"\0"


class DomainLengthTests(unittest.TestCase):
    def test_maximum_length_domain_parses(self) -> None:
        """A domain of exactly the maximum length parses and the value round
        trips through the writer and the reader unchanged."""
        self.assertEqual(len(MAXIMUM_DOMAIN), MAXIMUM_DOMAIN_LENGTH)

        owid = Owid.from_byte_array(envelope(terminated(MAXIMUM_DOMAIN)))

        self.assertEqual(owid.domain, MAXIMUM_DOMAIN)
        self.assertEqual(owid.payload, PAYLOAD)
        self.assertEqual(owid.signature, SIGNATURE)
        again = Owid.from_byte_array(owid.as_byte_array())
        self.assertEqual(again.domain, MAXIMUM_DOMAIN)
        self.assertEqual(again, owid)

    def test_one_character_over_the_maximum_is_refused(self) -> None:
        """A domain one character longer than the maximum is refused, and
        the message names the maximum so the reader of a log can see which
        limit the sender crossed."""
        domain = MAXIMUM_DOMAIN + "c"
        self.assertEqual(len(domain), MAXIMUM_DOMAIN_LENGTH + 1)

        with self.assertRaises(OwidError) as raised:
            Owid.from_byte_array(envelope(terminated(domain)))

        self.assertIn(
            "'{0}'".format(MAXIMUM_DOMAIN_LENGTH), str(raised.exception)
        )

    def test_missing_terminator_is_refused_within_the_bound(self) -> None:
        """A domain field with no terminator at all is refused, and the cost
        of refusing it is set by the maximum rather than by the size of the
        buffer.

        The buffer holds 64 MiB of domain characters and no zero byte
        anywhere. A loop of 1,000 parses must finish in under a second,
        which fails if each parse walks the whole buffer, and tracemalloc
        must report a peak under 64 KiB for a single parse."""
        raw = hostile(b"a" * HOSTILE_LENGTH)

        started = time.perf_counter()
        for _ in range(1000):
            with self.assertRaises(OwidError):
                Owid.from_byte_array(raw)
        elapsed = time.perf_counter() - started

        self.assertLess(
            elapsed,
            1.0,
            "1,000 parses of a {0} byte buffer took {1:.3f}s".format(
                HOSTILE_LENGTH, elapsed
            ),
        )
        tracemalloc.start()
        try:
            with self.assertRaises(OwidError):
                Owid.from_byte_array(raw)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(
            peak,
            64 * 1024,
            "refusing the buffer reached a peak of {0} bytes".format(peak),
        )

    def test_distant_terminator_does_not_size_the_domain(self) -> None:
        """A terminator far beyond the maximum is refused without building a
        string of everything before it.

        Without the bound this is the most expensive case of the two,
        because the reader would decode 64 MiB of domain characters into a
        string rather than only walking past them. The peak must stay under
        64 KiB, which is a thousandth of what that string alone would
        take."""
        raw = hostile(b"a" * HOSTILE_LENGTH + b"\0")

        tracemalloc.start()
        try:
            with self.assertRaises(OwidError):
                Owid.from_byte_array(raw)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertLess(
            peak,
            64 * 1024,
            "refusing the buffer reached a peak of {0} bytes".format(peak),
        )

    def test_library_output_parses(self) -> None:
        """A round trip through the library's own signing path and writer
        still parses and still verifies, so the bound refuses nothing the
        library itself produces."""
        crypto = Crypto.new()
        original = Creator(MAXIMUM_DOMAIN, crypto).sign_bytes(PAYLOAD)

        parsed = Owid.from_byte_array(original.as_byte_array())

        self.assertEqual(parsed.domain, MAXIMUM_DOMAIN)
        self.assertEqual(parsed, original)
        self.assertTrue(parsed.verify_with_crypto(crypto, []))


if __name__ == "__main__":
    unittest.main()
