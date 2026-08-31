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
from owid.status import ParseStatus, SignatureStatus


def _creator() -> Creator:
    return Creator("example.com", Crypto.new())


class ParseContractTests(unittest.TestCase):
    """The three facts a parse always reports."""

    def test_success_reports_ok_a_value_and_parsed(self) -> None:
        owid = _creator().create(b"\x01\x02\x03")

        result = Owid.parse_bytes(owid.as_byte_array())

        self.assertTrue(result.ok)
        self.assertIsNotNone(result.owid)
        self.assertEqual(ParseStatus.PARSED, result.status)
        self.assertTrue(result, "the result is truthy on success")

    def test_empty_payload_parses(self) -> None:
        """Having nothing to say is allowed: the payload is what the creator
        had to say, and an OWID carrying nothing is still an OWID."""
        owid = _creator().create(b"")

        result = Owid.parse_bytes(owid.as_byte_array())

        self.assertTrue(result.ok, result.status)
        self.assertEqual(b"", result.owid.payload)

    def test_large_payload_parses(self) -> None:
        """A megabyte parses. The format's limit is the wire format's, and how
        much an application will accept is that application's policy rather
        than something this library decides for it."""
        payload = bytes(1024 * 1024)
        owid = _creator().create(payload)

        result = Owid.parse_bytes(owid.as_byte_array())

        self.assertTrue(result.ok, result.status)
        self.assertEqual(len(payload), len(result.owid.payload))

    def test_absent_input_is_missing_input(self) -> None:
        for value in (None, ""):
            with self.subTest(value=value):
                result = Owid.parse(value)
                self.assertFalse(result.ok)
                self.assertIsNone(result.owid)
                self.assertEqual(ParseStatus.MISSING_INPUT, result.status)

    def test_none_buffer_is_missing_input(self) -> None:
        result = Owid.parse_bytes(None)

        self.assertFalse(result.ok)
        self.assertIsNone(result.owid)
        self.assertEqual(ParseStatus.MISSING_INPUT, result.status)

    def test_invalid_base64_is_reported_not_raised(self) -> None:
        result = Owid.parse("not base 64 at all!!")

        self.assertFalse(result.ok)
        self.assertIsNone(result.owid)
        self.assertEqual(ParseStatus.INVALID_BASE64, result.status)

    def test_unsupported_version_is_reported(self) -> None:
        raw = bytearray(_creator().create(b"x").as_byte_array())
        raw[0] = 9

        result = Owid.parse_bytes(bytes(raw))

        self.assertFalse(result.ok)
        self.assertEqual(ParseStatus.UNSUPPORTED_VERSION, result.status)

    def test_trailing_byte_is_refused(self) -> None:
        raw = _creator().create(b"x").as_byte_array() + b"\x00"

        result = Owid.parse_bytes(raw)

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

        result = Owid.parse_bytes(bytes(raw))

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

        result = Owid.parse_bytes(bytes(raw))

        self.assertFalse(result.ok)
        self.assertIsNone(
            result.owid,
            "no value means nothing exists on which to check a signature")


if __name__ == "__main__":
    unittest.main()


class EveryFailureConditionTests(unittest.TestCase):
    """One test per failure the vocabulary can report.

    James Rosewell asked that every failure condition is covered. Where a
    member cannot be reached in Python the reason is stated here and on the
    member itself, rather than a path being invented to reach it.
    """

    def test_missing_input(self) -> None:
        self.assertEqual(
            ParseStatus.MISSING_INPUT, Owid.parse_bytes(b"").status)

    def test_invalid_input_type(self) -> None:
        """Python does not check types at the boundary, so something that is
        neither text nor bytes reaches the reader and is named rather than
        raising a TypeError from somewhere deeper."""
        self.assertEqual(
            ParseStatus.INVALID_INPUT_TYPE, Owid.parse(12345).status)
        self.assertEqual(
            ParseStatus.INVALID_INPUT_TYPE, Owid.parse_bytes(12345).status)

    def test_invalid_base64(self) -> None:
        self.assertEqual(
            ParseStatus.INVALID_BASE64, Owid.parse("not base 64!!").status)

    def test_unsupported_version(self) -> None:
        raw = bytearray(_creator().create(b"x").as_byte_array())
        raw[0] = 9
        self.assertEqual(
            ParseStatus.UNSUPPORTED_VERSION, Owid.parse_bytes(bytes(raw)).status)

    def test_empty_marker_is_an_absent_node(self) -> None:
        """The version 0 marker stands for an absent node inside a stream. It
        has no signature, so it can never verify, and no value is handed back. It
        is named for what it is rather than called an unsupported version,
        because version 0 is supported and meaningful, it simply is not an
        OWID."""
        self.assertEqual(
            ParseStatus.ABSENT_NODE, Owid.parse_bytes(b"\x00").status)

    def test_unexpected_end(self) -> None:
        """Data that stops inside a field, before the declared length is even
        read. Distinct from a declaration disagreeing with data that is here."""
        raw = _creator().create(b"x").as_byte_array()[:3]
        self.assertEqual(
            ParseStatus.UNEXPECTED_END, Owid.parse_bytes(raw).status)

    def test_invalid_domain_encoding(self) -> None:
        """A domain that never terminates within the published maximum."""
        raw = bytes([3]) + b"a" * 300
        self.assertEqual(
            ParseStatus.INVALID_DOMAIN_ENCODING, Owid.parse_bytes(raw).status)

    def test_byte_count_mismatch_when_longer(self) -> None:
        raw = _creator().create(b"x").as_byte_array() + b"\x00"
        self.assertEqual(
            ParseStatus.BYTE_COUNT_MISMATCH, Owid.parse_bytes(raw).status)

    def test_byte_count_mismatch_when_signature_is_short(self) -> None:
        """The declared payload cannot leave exactly the signature the version
        requires, which is the finding whichever way the bytes fall short."""
        raw = _creator().create(b"x").as_byte_array()[:-1]
        self.assertEqual(
            ParseStatus.BYTE_COUNT_MISMATCH, Owid.parse_bytes(raw).status)

    def test_implementation_capacity_and_malformed_are_unreachable(self) -> None:
        """IMPLEMENTATION_CAPACITY_EXCEEDED cannot be reached in Python:
        integers are unbounded and a declaration large enough to matter can
        never agree with the bytes actually present, so the count check refuses
        it first. MALFORMED_ENVELOPE is likewise unreachable while the count
        check holds, and both are kept as backstops so that a future change to
        that arithmetic cannot pass silently.

        This test exists to record that, so the gap is a stated decision rather
        than something nobody noticed."""
        self.assertIn(ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED, ParseStatus)
        self.assertIn(ParseStatus.MALFORMED_ENVELOPE, ParseStatus)


class SignatureStatusTests(unittest.TestCase):
    """Keeping "could not check" apart from "does not match"."""

    def test_valid(self) -> None:
        crypto = Crypto.new()
        owid = Creator("example.com", crypto).create(b"abc")
        self.assertEqual(
            SignatureStatus.SIGNATURE_VALID,
            owid.signature_status(crypto.public_key_pem(), []))

    def test_invalid_only_when_it_really_does_not_match(self) -> None:
        crypto = Crypto.new()
        owid = Creator("example.com", crypto).create(b"abc")
        raw = bytearray(owid.as_byte_array())
        raw[-1] ^= 0xFF
        tampered = Owid.parse_bytes(bytes(raw)).owid
        self.assertEqual(
            SignatureStatus.SIGNATURE_INVALID,
            tampered.signature_status(crypto.public_key_pem(), []))

    def test_no_key_is_not_a_forgery(self) -> None:
        crypto = Crypto.new()
        owid = Creator("example.com", crypto).create(b"abc")
        self.assertEqual(
            SignatureStatus.KEY_UNAVAILABLE, owid.signature_status("", []))

    def test_unreadable_key_is_not_a_forgery(self) -> None:
        """This is the case that happened. The key endpoints served PEM a
        strict parser rejects, and reporting it as a forgery would have read as
        an attack rather than the outage it was."""
        crypto = Crypto.new()
        owid = Creator("example.com", crypto).create(b"abc")
        self.assertEqual(
            SignatureStatus.INVALID_KEY,
            owid.signature_status(
                "-----BEGIN PUBLIC KEY-----\nnot base 64\n"
                "-----END PUBLIC KEY-----", []))

    def test_remaining_members_are_unreachable_here(self) -> None:
        """INVALID_SIGNATURE_LENGTH cannot be reached from a parsed OWID,
        because a parse only succeeds when the signature is exactly the
        required length; the guard covers an OWID reaching this by another
        route. VERIFICATION_ERROR needs the cryptographic provider to fail on
        inputs that are themselves fine, and IMPLEMENTATION_CAPACITY_EXCEEDED
        needs more data than this runtime can hold. Both are kept because
        neither may ever be reported as a forgery."""
        self.assertIn(SignatureStatus.INVALID_SIGNATURE_LENGTH, SignatureStatus)
        self.assertIn(SignatureStatus.VERIFICATION_ERROR, SignatureStatus)
        self.assertIn(
            SignatureStatus.IMPLEMENTATION_CAPACITY_EXCEEDED, SignatureStatus)


    def test_an_absent_node_is_skipped_and_the_next_frame_read(self) -> None:
        """The distinction the marker exists for: a caller walking a run of
        frames can tell an absent node from a malformed one, and carry on."""
        envelope = _creator().create(b"after the gap").as_byte_array()
        data = b"\x00" + envelope

        first = Owid.parse_prefix(data)
        self.assertFalse(first.ok, "a marker is not an OWID")
        self.assertIsNone(first.owid)
        self.assertEqual(ParseStatus.ABSENT_NODE, first.status)
        self.assertEqual(1, first.consumed, "and it moves past the one byte")

        second = Owid.parse_prefix(data[first.consumed:])
        self.assertTrue(second.ok, second.status)
        self.assertEqual(b"after the gap", second.owid.payload)


class FramedReadTests(unittest.TestCase):
    """Reading one envelope from a buffer that holds more after it.

    The two reads differ in exactly one place. A whole buffer knows where the
    envelope ends, so the declared payload must leave exactly the signature. A
    framed read does not, because what follows may be the next envelope rather
    than rubbish.
    """

    def test_walks_a_run_of_envelopes(self) -> None:
        creator = _creator()
        first = creator.create(b"first").as_byte_array()
        second = creator.create(b"second").as_byte_array()
        data = first + second

        payloads = []
        while data:
            result = Owid.parse_prefix(data)
            self.assertTrue(result.ok, result.status)
            payloads.append(result.owid.payload)
            data = data[result.consumed:]

        self.assertEqual([b"first", b"second"], payloads)

    def test_the_whole_buffer_read_refuses_the_same_bytes(self) -> None:
        """Where nothing else could own the trailing bytes, they are a
        disagreement rather than the next envelope."""
        creator = _creator()
        data = (creator.create(b"first").as_byte_array()
                + creator.create(b"second").as_byte_array())

        result = Owid.parse_bytes(data)

        self.assertFalse(result.ok)
        self.assertEqual(ParseStatus.BYTE_COUNT_MISMATCH, result.status)

    def test_a_truncated_envelope_is_refused_and_consumes_nothing(self) -> None:
        raw = _creator().create(b"payload").as_byte_array()[:-1]

        result = Owid.parse_prefix(raw)

        self.assertFalse(result.ok)
        # Data stopping early, not a declaration disagreeing with data that is
        # all present. A caller reading from a source still arriving needs to
        # know whether waiting for more bytes would help.
        self.assertEqual(ParseStatus.UNEXPECTED_END, result.status)
        self.assertEqual(0, result.consumed)
        # Reading it again gives the same answer, since nothing moved.
        self.assertEqual(result.status, Owid.parse_prefix(raw).status)

    def test_the_framed_read_reports_the_same_reasons(self) -> None:
        """Everything except what follows the envelope is judged identically,
        so a caller does not have to learn two vocabularies."""
        good = _creator().create(b"payload").as_byte_array()
        unknown = bytearray(good)
        unknown[0] = 9

        for name, raw, expected in (
            ("stops inside a field", good[:3], ParseStatus.UNEXPECTED_END),
            ("nothing supplied", b"", ParseStatus.MISSING_INPUT),
            ("unknown version", bytes(unknown),
             ParseStatus.UNSUPPORTED_VERSION),
            ("the absent marker", b"\x00",
             ParseStatus.ABSENT_NODE),
        ):
            with self.subTest(name):
                self.assertEqual(
                    expected, Owid.parse_prefix(raw).status)
                self.assertEqual(
                    expected, Owid.parse_bytes(raw).status)
