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
"""Unit tests for the Creator type."""

from __future__ import annotations

import unittest

from owid import Configuration, Creator, Crypto, OwidError, Version


class CreatorTests(unittest.TestCase):
    def test_sign_sets_domain_date_and_version(self) -> None:
        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        owid = creator.sign_string("Hello World")
        self.assertEqual(owid.domain, "example.com")
        self.assertEqual(owid.version, Version.VERSION3)
        self.assertEqual(len(owid.signature), 64)
        self.assertTrue(owid.verify_with_crypto(crypto, []))

    def test_sign_string_and_sign_bytes_match(self) -> None:
        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        from_string = creator.sign_string("payload")
        from_bytes = creator.sign_bytes(b"payload")
        self.assertEqual(from_string.payload, from_bytes.payload)

    def test_empty_domain_raises(self) -> None:
        crypto = Crypto.new()
        with self.assertRaises(OwidError):
            Creator("", crypto)

    def test_whitespace_domain_raises(self) -> None:
        crypto = Crypto.new()
        with self.assertRaises(OwidError):
            Creator("   ", crypto)

    def test_verify_only_crypto_cannot_create_creator(self) -> None:
        verifier = Crypto.new_verify_only(Crypto.new().public_key_pem())
        with self.assertRaises(OwidError):
            Creator("example.com", verifier)

    def test_from_configuration(self) -> None:
        crypto = Crypto.new()
        configuration = Configuration(
            domain="example.com", private_key=crypto.private_key_pem()
        )
        creator = Creator.from_configuration(configuration)
        self.assertEqual(creator.domain, "example.com")
        owid = creator.sign_string("Hello World")
        # The OWID must verify with the public key from the original crypto.
        self.assertTrue(owid.verify_with_public_key(crypto.public_key_pem(), []))

    def test_from_configuration_empty_key_raises(self) -> None:
        configuration = Configuration(domain="example.com", private_key="")
        with self.assertRaises(OwidError):
            Creator.from_configuration(configuration)

    def test_crypto_property(self) -> None:
        crypto = Crypto.new()
        creator = Creator("example.com", crypto)
        self.assertIs(creator.crypto, crypto)


if __name__ == "__main__":
    unittest.main()
