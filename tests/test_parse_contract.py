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

"""What the parse and creation surfaces promise, tested as a contract.

Two promises are kept here. The first is that reading external data always
answers rather than raising, and answers with the same three facts: whether it
worked, the value only when it did, and a named reason either way. The second
is that an OWID can only arrive by parsing one or by a creator signing one, so
no caller can hold a half made or altered identifier.
"""

from __future__ import annotations

import unittest

from owid import Creator, Crypto, Owid
from owid.error import OwidError
from owid.io import SIGNATURE_LENGTH
from owid.status import ParseStatus


def _creator() -> Creator:
    return Creator("example.com", Crypto.new())


class ParseContractTests(unittest.TestCase):
    """The three facts a parse always reports."""

    def test_success_reports_ok_a_value_and_parsed(self) -> None:
        owid = _creator().create(b"\x01\x02\x03")

        result = Owid.try_from_byte_array(owid.as_byte_array())

        self.assertTrue(result.ok)
        self.assertIsNotNone(result.owid)
        self.assertEqual(ParseStatus.PARSED, result.status)
        self.assertTrue(result, "the result is truthy on success")

    def test_empty_payload_parses(self) -> None:
        """Having nothing to say is allowed: the payload is what the creator
        had to say, and an OWID carrying nothing is still an OWID."""
        owid = _creator().create(b"")

        result = Owid.try_from_byte_array(owid.as_byte_array())

        self.assertTrue(result.ok, result.status)
        self.assertEqual(b"", result.owid.payload)

    def test_large_payload_parses(self) -> None:
        """A megabyte parses. The format's limit is the wire format's, and how
        much an application will accept is that application's policy rather
        than something this library decides for it."""
        payload = bytes(1024 * 1024)
        owid = _creator().create(payload)

        result = Owid.try_from_byte_array(owid.as_byte_array())

        self.assertTrue(result.ok, result.status)
        self.assertEqual(len(payload), len(result.owid.payload))

    def test_absent_input_is_missing_input(self) -> None:
        for value in (None, ""):
            with self.subTest(value=value):
                result = Owid.try_from_base64(value)
                self.assertFalse(result.ok)
                self.assertIsNone(result.owid)
                self.assertEqual(ParseStatus.MISSING_INPUT, result.status)

    def test_none_buffer_is_missing_input(self) -> None:
        result = Owid.try_from_byte_array(None)

        self.assertFalse(result.ok)
        self.assertIsNone(result.owid)
        self.assertEqual(ParseStatus.MISSING_INPUT, result.status)

    def test_invalid_base64_is_reported_not_raised(self) -> None:
        result = Owid.try_from_base64("not base 64 at all!!")

        self.assertFalse(result.ok)
        self.assertIsNone(result.owid)
        self.assertEqual(ParseStatus.INVALID_BASE64, result.status)

    def test_unsupported_version_is_reported(self) -> None:
        raw = bytearray(_creator().create(b"x").as_byte_array())
        raw[0] = 9

        result = Owid.try_from_byte_array(bytes(raw))

        self.assertFalse(result.ok)
        self.assertEqual(ParseStatus.UNSUPPORTED_VERSION, result.status)

    def test_trailing_byte_is_refused(self) -> None:
        raw = _creator().create(b"x").as_byte_array() + b"\x00"

        result = Owid.try_from_byte_array(raw)

        self.assertFalse(result.ok)
        self.assertEqual(ParseStatus.BYTE_COUNT_MISMATCH, result.status)


class ConstructionBoundaryTests(unittest.TestCase):
    """An OWID arrives from a parse or a creator, and from nowhere else."""

    def test_direct_construction_is_refused(self) -> None:
        """Python cannot make a constructor package private, so the boundary
        is kept by refusing a caller who has not come through one of the two
        allowed paths. Without it an unsigned OWID could be handed to code
        that cannot tell the difference."""
        with self.assertRaises(OwidError) as caught:
            Owid()

        self.assertIn("cannot be constructed directly", str(caught.exception))

    def test_state_cannot_be_rebound(self) -> None:
        owid = _creator().create(b"abc")

        for field in ("version", "domain", "date", "payload", "signature"):
            with self.subTest(field=field):
                with self.assertRaises(AttributeError):
                    setattr(owid, field, None)

    def test_payload_is_immutable(self) -> None:
        """bytes rather than a mutable buffer, so what a caller was given
        cannot be written into."""
        owid = _creator().create(b"abc")

        self.assertIsInstance(owid.payload, bytes)
        self.assertIsInstance(owid.signature, bytes)


class ParsingIsNotVerificationTests(unittest.TestCase):
    """Two separate questions with two separate answers."""

    def test_structurally_valid_but_unsigned_parses_then_fails(self) -> None:
        crypto = Crypto.new()
        owid = Creator("example.com", crypto).create(b"\x04\x05\x06")
        raw = bytearray(owid.as_byte_array())
        raw[-1] ^= 0xFF

        result = Owid.try_from_byte_array(bytes(raw))

        self.assertTrue(
            result.ok,
            "flipping a signature byte leaves the envelope readable")
        self.assertEqual(ParseStatus.PARSED, result.status)
        self.assertFalse(
            result.owid.verify_with_crypto(crypto, []),
            "and the signature is then found not to match")

    def test_no_verification_happens_during_a_failed_parse(self) -> None:
        """A malformed identifier must be refused before anything reaches a
        key or a signature check."""
        raw = bytearray(_creator().create(b"x").as_byte_array())
        raw[0] = 9

        result = Owid.try_from_byte_array(bytes(raw))

        self.assertFalse(result.ok)
        self.assertIsNone(
            result.owid,
            "no value means nothing exists on which to check a signature")


if __name__ == "__main__":
    unittest.main()
