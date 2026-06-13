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
"""Unit tests for the well known end point helpers."""

from __future__ import annotations

import json
import unittest

from owid import Creator, Crypto, OwidError, Version, endpoints


def _new_creator() -> Creator:
    return Creator("example.com", Crypto.new())


class EndpointTests(unittest.TestCase):
    def test_paths(self) -> None:
        self.assertEqual(
            endpoints.creator_path(Version.VERSION3), "/owid/api/v3/creator"
        )
        self.assertEqual(
            endpoints.public_key_path(Version.VERSION3),
            "/owid/api/v3/public-key",
        )

    def test_creator_response_fields(self) -> None:
        creator = _new_creator()
        body = endpoints.creator_response(
            creator, "Example Org", "https://example.com/contract"
        )
        parsed = json.loads(body)
        self.assertEqual(parsed["domain"], "example.com")
        self.assertEqual(parsed["name"], "Example Org")
        self.assertEqual(parsed["contractURL"], "https://example.com/contract")
        self.assertIn("BEGIN PUBLIC KEY", parsed["publicKeySPKI"])
        # The JSON field names must match the specification.
        self.assertIn("publicKeySPKI", body)
        self.assertIn("contractURL", body)

    def test_creator_response_default_contract_url(self) -> None:
        creator = _new_creator()
        body = endpoints.creator_response(creator, "Example Org")
        parsed = json.loads(body)
        self.assertEqual(parsed["contractURL"], "")

    def test_public_key_response_formats(self) -> None:
        creator = _new_creator()
        for fmt in ("spki", "pkcs"):
            body = endpoints.public_key_response(creator, fmt)
            self.assertIn("BEGIN PUBLIC KEY", body)

    def test_public_key_response_invalid_format(self) -> None:
        creator = _new_creator()
        with self.assertRaises(OwidError):
            endpoints.public_key_response(creator, "other")


if __name__ == "__main__":
    unittest.main()
