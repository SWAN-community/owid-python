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
"""Unit tests for the Crypto type."""

from __future__ import annotations

import unittest

from owid import Crypto, OwidError
from owid.io import SIGNATURE_LENGTH

TEST_PAYLOAD = b"test"


class CryptoTests(unittest.TestCase):
    def test_invalid_public_pem(self) -> None:
        with self.assertRaises(OwidError):
            Crypto.new_verify_only("invalid")

    def test_invalid_private_pem(self) -> None:
        with self.assertRaises(OwidError):
            Crypto.new_sign_only("invalid")

    def test_empty_public_pem(self) -> None:
        # The empty PEM guard must give a clear message rather than an opaque
        # crypto error.
        with self.assertRaises(OwidError) as context:
            Crypto.new_verify_only("")
        self.assertEqual(str(context.exception), "public key PEM is empty")

    def test_whitespace_public_pem(self) -> None:
        with self.assertRaises(OwidError) as context:
            Crypto.new_verify_only("   \n\t ")
        self.assertEqual(str(context.exception), "public key PEM is empty")

    def test_none_public_pem(self) -> None:
        with self.assertRaises(OwidError) as context:
            Crypto.new_verify_only(None)
        self.assertEqual(str(context.exception), "public key PEM is empty")

    def test_empty_private_pem(self) -> None:
        with self.assertRaises(OwidError) as context:
            Crypto.new_sign_only("")
        self.assertEqual(str(context.exception), "private key PEM is empty")

    def test_whitespace_private_pem(self) -> None:
        with self.assertRaises(OwidError) as context:
            Crypto.new_sign_only("  \n ")
        self.assertEqual(str(context.exception), "private key PEM is empty")

    def test_none_private_pem(self) -> None:
        with self.assertRaises(OwidError) as context:
            Crypto.new_sign_only(None)
        self.assertEqual(str(context.exception), "private key PEM is empty")

    def test_sign_and_verify_via_pem(self) -> None:
        # Keys exported to PEM and imported into sign only and verify only
        # instances must produce signatures that verify.
        crypto = Crypto.new()
        private_pem = crypto.private_key_pem()
        public_pem = crypto.public_key_pem()
        self.assertIn("BEGIN PRIVATE KEY", private_pem)
        self.assertIn("BEGIN PUBLIC KEY", public_pem)
        signer = Crypto.new_sign_only(private_pem)
        verifier = Crypto.new_verify_only(public_pem)
        signature = signer.sign_byte_array(TEST_PAYLOAD)
        self.assertEqual(len(signature), SIGNATURE_LENGTH)
        self.assertTrue(verifier.verify_byte_array(TEST_PAYLOAD, signature))

    def test_signer_can_also_verify(self) -> None:
        # A sign only instance derives the public key and can verify too.
        crypto = Crypto.new()
        signer = Crypto.new_sign_only(crypto.private_key_pem())
        signature = signer.sign_byte_array(TEST_PAYLOAD)
        self.assertTrue(signer.verify_byte_array(TEST_PAYLOAD, signature))

    def test_verify_only_cannot_sign(self) -> None:
        crypto = Crypto.new()
        verifier = Crypto.new_verify_only(crypto.public_key_pem())
        self.assertFalse(verifier.can_sign())
        with self.assertRaises(OwidError):
            verifier.sign_byte_array(TEST_PAYLOAD)

    def test_verify_only_cannot_export_private(self) -> None:
        crypto = Crypto.new()
        verifier = Crypto.new_verify_only(crypto.public_key_pem())
        with self.assertRaises(OwidError):
            verifier.private_key_pem()

    def test_wrong_length_signature_errors(self) -> None:
        crypto = Crypto.new()
        with self.assertRaises(OwidError):
            crypto.verify_byte_array(TEST_PAYLOAD, bytes(63))

    def test_zero_signature_is_invalid(self) -> None:
        # A 64 byte signature of all zeros has r and s of zero, which can
        # never verify, and returns False rather than raising.
        crypto = Crypto.new()
        self.assertFalse(crypto.verify_byte_array(TEST_PAYLOAD, bytes(64)))

    def test_wrong_data_does_not_verify(self) -> None:
        crypto = Crypto.new()
        signature = crypto.sign_byte_array(TEST_PAYLOAD)
        self.assertFalse(crypto.verify_byte_array(b"other", signature))

    def test_can_sign_and_can_verify(self) -> None:
        crypto = Crypto.new()
        self.assertTrue(crypto.can_sign())
        self.assertTrue(crypto.can_verify())

    def test_sec1_private_pem_accepted(self) -> None:
        # The SEC1 ("EC PRIVATE KEY") form must also be accepted.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        sec1 = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("utf-8")
        self.assertIn("EC PRIVATE KEY", sec1)
        signer = Crypto.new_sign_only(sec1)
        signature = signer.sign_byte_array(TEST_PAYLOAD)
        self.assertTrue(signer.verify_byte_array(TEST_PAYLOAD, signature))


if __name__ == "__main__":
    unittest.main()
