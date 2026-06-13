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
"""Wire format and cross language fixture tests for the Owid type."""

from __future__ import annotations

import unittest

from owid import Crypto, Owid, Version

from tests import fixtures


class CanonicalWireVectorTests(unittest.TestCase):
    """The three canonical vectors must round trip byte exact.

    Each vector is decoded to bytes, parsed to an OWID, and re-serialized.
    The bytes must be identical. The vectors are unpadded base 64, so the
    comparison is made on bytes and not on the base 64 strings.
    """

    def _assert_round_trip(self, vector: str) -> Owid:
        original = fixtures.decode_unpadded(vector)
        owid = Owid.from_byte_array(original)
        self.assertEqual(
            owid.as_byte_array(),
            original,
            "the re-serialized bytes must match the original",
        )
        return owid

    def test_creator_vector_round_trips(self) -> None:
        owid = self._assert_round_trip(fixtures.CREATOR_VECTOR)
        self.assertEqual(owid.version, Version.VERSION2)
        self.assertEqual(owid.domain, "51db.uk")
        self.assertEqual(len(owid.payload), 341)
        # 664619 minutes after the base date is 2021-04-06T12:59Z.
        self.assertEqual(owid.date.year, 2021)
        self.assertEqual(owid.date.month, 4)
        self.assertEqual(owid.date.day, 6)
        self.assertEqual(owid.date.hour, 12)
        self.assertEqual(owid.date.minute, 59)
        self.assertEqual(owid.signature[0], 74)
        self.assertEqual(owid.signature[-1], 64)

    def test_supplier_vector_round_trips(self) -> None:
        owid = self._assert_round_trip(fixtures.SUPPLIER_VECTOR)
        self.assertEqual(owid.version, Version.VERSION2)
        self.assertEqual(owid.domain, "pop-up.swan-demo.uk")
        self.assertEqual(owid.payload, bytes([0x01, 0x03]))
        self.assertEqual(owid.payload_as_base64(), "AQM=")
        self.assertEqual(owid.payload_as_printable(), "0103")

    def test_bad_vector_parses_only(self) -> None:
        # The bad vector parses but its signature does not verify. Only the
        # parse and round trip are asserted here.
        owid = self._assert_round_trip(fixtures.BAD_VECTOR)
        self.assertEqual(owid.domain, "badssp.swan-demo.uk")


class CrossLanguageFixtureTests(unittest.TestCase):
    """Real signatures produced by other implementations must verify.

    For each language the simple and utf8 OWIDs verify on their own, the chain
    root verifies on its own, and the chain party verifies only when the chain
    root is supplied as the single other. A tampered copy must fail.
    """

    def test_simple_and_utf8_verify(self) -> None:
        for name, data in fixtures.ALL_LANGUAGES:
            spki = data["spki"]
            with self.subTest(language=name, fixture="simple"):
                simple = Owid.from_base64(data["simple"])
                self.assertEqual(simple.payload_as_string(), "example")
                self.assertTrue(simple.verify_with_public_key(spki, []))
            with self.subTest(language=name, fixture="utf8"):
                utf8 = Owid.from_base64(data["utf8"])
                self.assertEqual(
                    utf8.payload_as_string(),
                    fixtures.UTF8_PAYLOAD,
                    "the UTF-8 payload must decode to the expected text",
                )
                self.assertTrue(utf8.verify_with_public_key(spki, []))

    def test_chain_verifies_with_root_as_other(self) -> None:
        for name, data in fixtures.ALL_LANGUAGES:
            spki = data["spki"]
            root = Owid.from_base64(data["chain_root"])
            party = Owid.from_base64(data["chain_party"])
            with self.subTest(language=name):
                self.assertEqual(root.payload_as_string(), "root")
                self.assertEqual(party.payload_as_string(), "party")
                # Root verifies on its own.
                self.assertTrue(root.verify_with_public_key(spki, []))
                # Party verifies only with the root supplied as the other.
                self.assertTrue(party.verify_with_public_key(spki, [root]))

    def test_chain_party_fails_without_others(self) -> None:
        for name, data in fixtures.ALL_LANGUAGES:
            spki = data["spki"]
            party = Owid.from_base64(data["chain_party"])
            with self.subTest(language=name):
                self.assertFalse(
                    party.verify_with_public_key(spki, []),
                    "the chain party must not verify without the root",
                )

    def test_tampered_fixtures_fail(self) -> None:
        for name, data in fixtures.ALL_LANGUAGES:
            spki = data["spki"]
            root = Owid.from_base64(data["chain_root"])
            for fixture in ("simple", "utf8", "chain_root"):
                with self.subTest(language=name, fixture=fixture):
                    tampered = Owid.from_base64(
                        fixtures.flip_last_byte(data[fixture])
                    )
                    self.assertFalse(
                        tampered.verify_with_public_key(spki, []),
                        "a flipped signature byte must fail to verify",
                    )
            with self.subTest(language=name, fixture="chain_party"):
                tampered_party = Owid.from_base64(
                    fixtures.flip_last_byte(data["chain_party"])
                )
                self.assertFalse(
                    tampered_party.verify_with_public_key(spki, [root]),
                    "a flipped signature byte must fail to verify",
                )


class SignAndSelfVerifyTests(unittest.TestCase):
    """Signing an OWID locally and verifying it covers the signing path."""

    def test_sign_and_self_verify(self) -> None:
        from owid import Creator

        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        owid = creator.sign_string("Hello World")
        # Verifies with the crypto instance and with the exported public key.
        self.assertTrue(owid.verify_with_crypto(crypto, []))
        self.assertTrue(owid.verify_with_public_key(crypto.public_key_pem(), []))
        # A copy decoded from base 64 also verifies.
        copy = Owid.from_base64(owid.as_base64())
        self.assertEqual(copy, owid)
        self.assertTrue(copy.verify_with_crypto(crypto, []))

    def test_tampered_self_signed_fails(self) -> None:
        from owid import Creator

        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        owid = creator.sign_string("Hello World")
        # Change a payload byte and verification must fail.
        owid.payload = b"Hello Worle"
        self.assertFalse(owid.verify_with_crypto(crypto, []))

    def test_sign_with_others_round_trip(self) -> None:
        from owid import Creator

        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        root = creator.sign_string("root")
        party = Owid(payload=b"party")
        creator.sign_with_others(party, [root])
        # Party verifies with the root as the single other, and fails alone.
        self.assertTrue(party.verify_with_crypto(crypto, [root]))
        self.assertFalse(party.verify_with_crypto(crypto, []))


class PayloadAndSerializationTests(unittest.TestCase):
    """Payload accessors and the empty OWID marker."""

    def test_payload_accessors(self) -> None:
        owid = Owid(payload=bytes([0x01, 0x03]))
        self.assertEqual(owid.payload_as_printable(), "0103")
        self.assertEqual(owid.payload_as_base64(), "AQM=")
        self.assertEqual(Owid(payload=b"example").payload_as_string(), "example")

    def test_unpadded_and_padded_decode(self) -> None:
        # The supplier vector is unpadded. Adding padding must decode to the
        # same OWID.
        unpadded = fixtures.SUPPLIER_VECTOR
        padded = unpadded + "="
        self.assertEqual(
            Owid.from_base64(unpadded), Owid.from_base64(padded)
        )

    def test_empty_marker(self) -> None:
        buffer = bytearray()
        Owid.empty_to_buffer(buffer)
        self.assertEqual(bytes(buffer), bytes([0]))
        owid = Owid.from_byte_array(bytes(buffer))
        self.assertEqual(owid.version, Version.EMPTY)

    def test_short_buffer_raises(self) -> None:
        from owid import OwidError

        with self.assertRaises(OwidError):
            Owid.from_byte_array(bytes([0x03, 0x61]))


if __name__ == "__main__":
    unittest.main()
