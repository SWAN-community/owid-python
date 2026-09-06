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
"""Fetching the key that was in force when an identifier was signed, from the
well known end point on the creator domain.

The live end point answers 401 without a credential, so these tests run
against a stand in on the loopback address which serves the real published
51d.es schedule. The URL under test is the one the package builds, with only
the host replaced, so a fault in the path or the query is caught here.
"""

from __future__ import annotations

import os
import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from unittest import mock

from owid import (
    Creator,
    Crypto,
    Owid,
    OwidError,
    PublicKeyFetchError,
    SignatureStatus,
    Version,
    io,
    public_key_fetch,
)

from tests import key_fixtures
from tests.key_end_point import Answer, KeyEndPoint

#: No other OWIDs were covered by the signature on the fixture.
ALONE: List[Owid] = []

#: The date the fixture identifier carries, which the cloud trims to the day.
IDENTIFIER_DATE = datetime(2026, 9, 4, tzinfo=timezone.utc)


def crafted(version: Version, domain: str, date: datetime) -> Owid:
    """Builds an OWID with the version, domain and date given and a signature
    of zeroes, for the cases that are about the URL rather than the
    signature. Reading it back is the only way an OWID reaches a caller, so
    the bytes are written and then read."""
    buffer = bytearray()
    io.write_byte(buffer, version.as_byte())
    io.write_string(buffer, domain)
    io.write_date(buffer, date, version)
    io.write_byte_array(buffer, b"")
    io.write_signature(buffer, bytes(io.SIGNATURE_LENGTH))
    result = Owid.parse_bytes(bytes(buffer))
    assert result.ok, result.status
    assert result.owid is not None
    return result.owid


class PublicKeyFetchTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keys are held against the URL they were fetched from, and a test
        # that counts requests has to start from nothing held.
        public_key_fetch.clear_cache()
        self.started: List[KeyEndPoint] = []

    def tearDown(self) -> None:
        for end_point in self.started:
            end_point.stop()
        self.started.clear()
        public_key_fetch.clear_cache()

    def end_point(self, answer: Answer = Answer.SCHEDULE) -> KeyEndPoint:
        """Starts a stand in end point and stops it when the test ends."""
        end_point = KeyEndPoint(answer)
        self.started.append(end_point)
        return end_point

    def test_url_names_the_minute_the_identifier_was_created(self) -> None:
        """The URL names the minute the identifier was created, which is the
        value the end point selects a key by, and it names the well known
        path from the specification."""
        self.assertEqual(
            "https://51d.es/owid/api/v3/public-key?date={0}&format=pkcs".format(
                key_fixtures.IDENTIFIER_MINUTES
            ),
            public_key_fetch.public_key_url(key_fixtures.identifier(), "https"),
            "should ask 51d.es for the key in force on 4 September 2026",
        )

    def test_url_uses_the_version_the_identifier_carries(self) -> None:
        """The version in the path comes from the version byte of the
        identifier rather than from a constant, so an identifier written by
        an earlier version asks the end point that serves that version."""
        version2 = crafted(Version.VERSION2, "example.com", IDENTIFIER_DATE)
        self.assertIs(Version.VERSION2, version2.version)
        self.assertEqual(
            "https://example.com/owid/api/v2/public-key?date={0}&format=pkcs"
            .format(key_fixtures.IDENTIFIER_MINUTES),
            public_key_fetch.public_key_url(version2, "https"),
            "should ask the version 2 end point",
        )

    def test_url_of_a_newly_signed_owid_names_its_own_minute(self) -> None:
        creator = Creator("example.com", Crypto.new())
        owid = creator.create_string("payload")
        self.assertEqual(
            "https://example.com/owid/api/v3/public-key?date={0}&format=pkcs"
            .format(io.minutes_since_base(owid.date)),
            public_key_fetch.public_key_url(owid, "https"),
            "should name the minute the OWID was signed",
        )

    def test_dated_fetch_verifies_an_identifier_from_an_earlier_key_week(
        self,
    ) -> None:
        """The fetch asks for the key in force when the identifier was signed
        and verifies it, with the identifier signed in a week earlier than
        the one the end point counts as current."""
        owid = key_fixtures.identifier()
        end_point = self.end_point()
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
            "should verify against the key in force when it was signed",
        )
        self.assertEqual(
            [str(key_fixtures.IDENTIFIER_MINUTES)],
            end_point.dates(),
            "the request should name the minute the identifier was created",
        )

    def test_undated_fetch_leaves_an_earlier_weeks_identifier_unverified(
        self,
    ) -> None:
        """The same identifier against the same end point without the date,
        which is the request a port that forgets the date makes. The end
        point answers with the key in force at the moment of the request, ten
        days after the identifier was signed, the signature does not match
        that key, and a genuine identifier reads as a forgery."""
        owid = key_fixtures.identifier()
        end_point = self.end_point()
        undated = end_point.base + "/owid/api/v3/public-key?format=pkcs"
        self.assertIs(
            SignatureStatus.SIGNATURE_INVALID,
            public_key_fetch._signature_status_at_url(owid, undated, ALONE),
            "an undated request gets the key in force at the request, which "
            "did not sign it",
        )
        self.assertEqual([None], end_point.dates(), "the request carried no date")

    def test_a_key_the_end_point_cannot_serve_is_key_unavailable(self) -> None:
        """An end point that cannot serve a key for the date leaves the
        signature unjudged rather than reporting a genuine identifier as a
        forgery."""
        owid = key_fixtures.identifier()
        end_point = self.end_point()
        # A fortnight before the schedule begins, which no key in it covers,
        # so the end point answers 404 the way the cloud does.
        before = key_fixtures.scheduled_keys()[0].starts_at - timedelta(days=14)
        url = "{0}/owid/api/v3/public-key?date={1}&format=pkcs".format(
            end_point.base, io.minutes_since_base(before)
        )
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch._signature_status_at_url(owid, url, ALONE),
            "no key means the signature was never examined",
        )

    def test_a_refused_request_carries_the_status_and_the_code(self) -> None:
        """The refusal carries the code and the domain, not only a message."""
        end_point = self.end_point()
        url = end_point.base + "/owid/api/v3/public-key?date=0&format=pkcs"
        with self.assertRaises(PublicKeyFetchError) as refused:
            public_key_fetch._public_key_pem_at_url(url, "51d.es")
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(404, refused.exception.status_code)
        self.assertEqual("51d.es", refused.exception.domain)

    def test_a_malformed_date_is_refused_by_the_end_point(self) -> None:
        """The stand in refuses a date that is not a count of minutes with a
        400, as the cloud does, and the package reports the refusal as a key
        that could not be obtained."""
        end_point = self.end_point()
        url = end_point.base + "/owid/api/v3/public-key?date=abc&format=pkcs"
        with self.assertRaises(PublicKeyFetchError) as refused:
            public_key_fetch._public_key_pem_at_url(url, "51d.es")
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(400, refused.exception.status_code)

    def test_an_end_point_that_cannot_be_reached_is_key_unavailable(
        self,
    ) -> None:
        """An end point that cannot be reached at all leaves the signature
        unjudged. Nothing about the identifier is known, so calling it
        invalid would report an outage as an attack."""
        owid = key_fixtures.identifier()
        end_point = KeyEndPoint()
        url = end_point.url_for(owid)
        end_point.stop()
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch._signature_status_at_url(owid, url, ALONE),
            "a connection that is refused leaves the signature unjudged",
        )

    def test_a_redirect_is_not_followed(self) -> None:
        """A creator whose domain answers with a redirect does not get the
        key at the other end trusted as its own. The answer is that the key
        is unavailable, carrying the 302, and the request that would have
        gone to the other host is never made. Without this a network
        attacker who could bend a creator's DNS or a misconfigured creator
        could substitute the key, and forgeries would verify."""
        owid = key_fixtures.identifier()
        end_point = self.end_point(Answer.REDIRECT)
        with self.assertRaises(PublicKeyFetchError) as refused:
            public_key_fetch._public_key_pem_at_url(
                end_point.url_for(owid), owid.domain
            )
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(302, refused.exception.status_code)
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
        )

    def test_a_key_that_cannot_be_read_is_invalid_key(self) -> None:
        """Text shaped like a PEM that holds no key is a fault in the key, and
        never a signature that does not match."""
        owid = key_fixtures.identifier()
        end_point = self.end_point(Answer.BROKEN_KEY)
        self.assertIs(
            SignatureStatus.INVALID_KEY,
            public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
        )

    def test_keys_are_held_per_request_and_not_per_domain(self) -> None:
        """Keys are held against the URL they came from, which names the
        minute, so two identifiers from different weeks fetch two different
        keys and a key held for one week never answers for another. A store
        keyed by domain alone would hand the second identifier the first
        one's key."""
        end_point = self.end_point()
        earlier = crafted(
            Version.VERSION3,
            key_fixtures.IDENTIFIER_DOMAIN,
            IDENTIFIER_DATE - timedelta(days=14),
        )
        later = crafted(
            Version.VERSION3, key_fixtures.IDENTIFIER_DOMAIN, IDENTIFIER_DATE
        )
        first = public_key_fetch._public_key_pem_at_url(
            end_point.url_for(earlier), key_fixtures.IDENTIFIER_DOMAIN
        )
        second = public_key_fetch._public_key_pem_at_url(
            end_point.url_for(later), key_fixtures.IDENTIFIER_DOMAIN
        )
        self.assertNotEqual(first, second, "two weeks, two keys")
        self.assertEqual(2, len(end_point.dates()), "one request per week")
        again = public_key_fetch._public_key_pem_at_url(
            end_point.url_for(earlier), key_fixtures.IDENTIFIER_DOMAIN
        )
        self.assertEqual(first, again, "the held key is the one fetched for that week")
        self.assertEqual(
            2, len(end_point.dates()), "a week already held is not asked for again"
        )
        self.assertIn("BEGIN PUBLIC KEY", first)

    def test_the_cache_is_bounded(self) -> None:
        """When the store reaches its bound it is emptied and filled again, so
        a long running verifier never holds more than the bound."""
        end_point = self.end_point()
        weeks = [
            crafted(
                Version.VERSION3,
                key_fixtures.IDENTIFIER_DOMAIN,
                IDENTIFIER_DATE - timedelta(days=7 * back),
            )
            for back in (0, 1, 2)
        ]
        with mock.patch.object(public_key_fetch, "MAXIMUM_CACHED_KEYS", 2):
            for week in weeks:
                public_key_fetch._public_key_pem_at_url(
                    end_point.url_for(week), key_fixtures.IDENTIFIER_DOMAIN
                )
            self.assertEqual(3, len(end_point.dates()))
            # The third arrival emptied the store, so the first week is
            # fetched again rather than answered from what was held.
            public_key_fetch._public_key_pem_at_url(
                end_point.url_for(weeks[0]), key_fixtures.IDENTIFIER_DOMAIN
            )
            self.assertEqual(4, len(end_point.dates()))

    def test_a_domain_that_is_not_a_domain_name_is_refused_before_any_request(
        self,
    ) -> None:
        """The domain arrives inside an OWID, which came from outside, so a
        value that would change the shape of the URL rather than name a host
        in it is refused before any request is made."""
        owid = crafted(Version.VERSION3, "51d.es/evil?x=", IDENTIFIER_DATE)
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "https")

        def no_request(url: str, timeout: float) -> Tuple[int, bytes]:
            self.fail("no request should be made for a refused domain")

        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch.signature_status(owid, "https", ALONE, no_request),
        )

    def test_a_scheme_that_does_not_make_an_http_request_is_refused(
        self,
    ) -> None:
        """A caller chooses the scheme, and one that reads something other
        than a creator, such as a file, is refused rather than opened."""
        owid = key_fixtures.identifier()
        fixture = pathlib.Path(key_fixtures._DATA, "identifier.txt").resolve()
        url = fixture.as_uri()
        self.assertTrue(url.startswith("file:"))
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch._signature_status_at_url(owid, url, ALONE),
        )
        with self.assertRaises(PublicKeyFetchError) as refused:
            public_key_fetch._public_key_pem_at_url(url, owid.domain)
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(0, refused.exception.status_code)

    def test_a_missing_owid_or_scheme_is_refused(self) -> None:
        owid = key_fixtures.identifier()
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(None, "https")  # type: ignore[arg-type]
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "")
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "   ")
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch.signature_status(None, "https"),  # type: ignore[arg-type]
        )

    def test_a_transport_of_the_callers_own_is_used(self) -> None:
        """A caller whose environment needs its own HTTP client supplies a
        transport, which is asked for the URL the package builds and whose
        answer is held like any other."""
        owid = key_fixtures.identifier()
        pem = key_fixtures.schedule().key_for(owid).public_key_pem
        calls: List[Tuple[str, float]] = []

        def transport(url: str, timeout: float) -> Tuple[int, bytes]:
            calls.append((url, timeout))
            return 200, pem.encode("utf-8")

        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            public_key_fetch.signature_status(owid, "https", ALONE, transport),
        )
        self.assertTrue(
            public_key_fetch.verify(owid, "https", ALONE, transport)
        )
        self.assertEqual(
            [
                (
                    public_key_fetch.public_key_url(owid, "https"),
                    public_key_fetch.TIMEOUT_SECONDS,
                )
            ],
            calls,
            "one request, for the URL the package builds, then the cache",
        )

    def test_verify_answers_true_only_for_a_genuine_signature(self) -> None:
        owid = key_fixtures.identifier()
        schedule = key_fixtures.schedule()
        keys = schedule.keys
        signing = schedule.key_for(owid)
        following = keys[keys.index(signing) + 1]

        def wrong_week(url: str, timeout: float) -> Tuple[int, bytes]:
            return 200, following.public_key_pem.encode("utf-8")

        self.assertFalse(
            public_key_fetch.verify(owid, "https", ALONE, wrong_week),
            "the following week's key did not sign the identifier",
        )

    def test_a_transport_that_raises_is_key_unavailable(self) -> None:
        owid = key_fixtures.identifier()

        def unreachable(url: str, timeout: float) -> Tuple[int, bytes]:
            raise OSError("no route")

        def unusable(url: str, timeout: float) -> Tuple[int, bytes]:
            raise ValueError("unknown url type")

        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch.signature_status(owid, "https", ALONE, unreachable),
        )
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch.signature_status(owid, "https", ALONE, unusable),
        )

    def test_a_response_larger_than_a_key_is_refused(self) -> None:
        """A body beyond the bound is not a key, and is neither held nor
        decoded."""
        owid = key_fixtures.identifier()
        too_large = b"x" * (public_key_fetch.MAXIMUM_RESPONSE_BYTES + 1)

        def oversized(url: str, timeout: float) -> Tuple[int, bytes]:
            return 200, too_large

        with self.assertRaises(PublicKeyFetchError) as refused:
            public_key_fetch.public_key_pem(owid, "https", oversized)
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(200, refused.exception.status_code)
        public_key_fetch.clear_cache()
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            public_key_fetch.signature_status(owid, "https", ALONE, oversized),
        )


if __name__ == "__main__":
    unittest.main()
