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

The fetch is asynchronous and has no synchronous form, so every test that
reaches it is a coroutine run by the standard library's
IsolatedAsyncioTestCase on an event loop of its own.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import pathlib
import unittest
import time
import threading
import urllib.parse
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from unittest import mock

from owid import (
    Creator,
    DatedPublicKey,
    PublicKeySchedule,
    endpoints,
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


class PublicKeyFetchTests(unittest.IsolatedAsyncioTestCase):
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

    def test_every_function_that_reaches_the_network_is_a_coroutine(
        self,
    ) -> None:
        """The fetch has no synchronous form. Building the URL and emptying
        the cache touch nothing outside the process and stay ordinary
        functions, and everything that could make a request is awaited."""
        for reaches_the_network in (
            public_key_fetch.public_key_pem,
            public_key_fetch.signature_status,
            public_key_fetch.verify,
        ):
            self.assertTrue(
                inspect.iscoroutinefunction(reaches_the_network),
                "{0} must be awaited".format(reaches_the_network.__name__),
            )
        for stays_in_process in (
            public_key_fetch.public_key_url,
            public_key_fetch.clear_cache,
        ):
            self.assertFalse(
                inspect.iscoroutinefunction(stays_in_process),
                "{0} makes no request".format(stays_in_process.__name__),
            )

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

    async def test_dated_fetch_verifies_an_identifier_from_an_earlier_key_week(
        self,
    ) -> None:
        """The fetch asks for the key in force when the identifier was signed
        and verifies it, with the identifier signed in a week earlier than
        the one the end point counts as current."""
        owid = key_fixtures.identifier()
        end_point = self.end_point()
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            await public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
            "should verify against the key in force when it was signed",
        )
        self.assertEqual(
            [str(key_fixtures.IDENTIFIER_MINUTES)],
            end_point.dates(),
            "the request should name the minute the identifier was created",
        )

    async def test_undated_fetch_leaves_an_earlier_weeks_identifier_unverified(
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
            await public_key_fetch._signature_status_at_url(
                owid, undated, ALONE
            ),
            "an undated request gets the key in force at the request, which "
            "did not sign it",
        )
        self.assertEqual([None], end_point.dates(), "the request carried no date")

    async def test_a_key_the_end_point_cannot_serve_is_key_unavailable(
        self,
    ) -> None:
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
            await public_key_fetch._signature_status_at_url(owid, url, ALONE),
            "no key means the signature was never examined",
        )

    async def test_a_refused_request_carries_the_status_and_the_code(
        self,
    ) -> None:
        """The refusal carries the code and the domain, not only a message."""
        end_point = self.end_point()
        url = end_point.base + "/owid/api/v3/public-key?date=0&format=pkcs"
        with self.assertRaises(PublicKeyFetchError) as refused:
            await public_key_fetch._public_key_pem_at_url(url, "51d.es")
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(404, refused.exception.status_code)
        self.assertEqual("51d.es", refused.exception.domain)

    async def test_a_malformed_date_is_refused_by_the_end_point(self) -> None:
        """The stand in refuses a date that is not a count of minutes with a
        400, as the cloud does, and the package reports the refusal as a key
        that could not be obtained."""
        end_point = self.end_point()
        url = end_point.base + "/owid/api/v3/public-key?date=abc&format=pkcs"
        with self.assertRaises(PublicKeyFetchError) as refused:
            await public_key_fetch._public_key_pem_at_url(url, "51d.es")
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(400, refused.exception.status_code)

    async def test_an_end_point_that_cannot_be_reached_is_key_unavailable(
        self,
    ) -> None:
        """An end point that cannot be reached at all leaves the signature
        unjudged. Nothing about the identifier is known, so calling it
        invalid would report an outage as an attack."""
        owid = key_fixtures.identifier()
        end_point = KeyEndPoint()
        url = end_point.url_for(owid)
        # Stopping the server waits for its polling loop to notice, up to
        # half a second, so it is done off the event loop rather than
        # blocking the loop for that long.
        await asyncio.to_thread(end_point.stop)
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch._signature_status_at_url(owid, url, ALONE),
            "a connection that is refused leaves the signature unjudged",
        )

    async def test_a_redirect_is_not_followed(self) -> None:
        """A creator whose domain answers with a redirect does not get the
        key at the other end trusted as its own. The answer is that the key
        is unavailable, carrying the 302, and the request that would have
        gone to the other host is never made. Without this a network
        attacker who could bend a creator's DNS or a misconfigured creator
        could substitute the key, and forgeries would verify."""
        owid = key_fixtures.identifier()
        end_point = self.end_point(Answer.REDIRECT)
        with self.assertRaises(PublicKeyFetchError) as refused:
            await public_key_fetch._public_key_pem_at_url(
                end_point.url_for(owid), owid.domain
            )
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(302, refused.exception.status_code)
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
        )

    async def test_a_key_that_cannot_be_read_is_invalid_key(self) -> None:
        """Text shaped like a PEM that holds no key is a fault in the key, and
        never a signature that does not match."""
        owid = key_fixtures.identifier()
        end_point = self.end_point(Answer.BROKEN_KEY)
        self.assertIs(
            SignatureStatus.INVALID_KEY,
            await public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), ALONE
            ),
        )

    async def test_keys_are_held_per_request_and_not_per_domain(self) -> None:
        """Keys are held against the span of minutes the creator confirmed
        them for, so two identifiers from different weeks fetch two different
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
        first = await public_key_fetch._public_key_pem_at_url(
            end_point.url_for(earlier), key_fixtures.IDENTIFIER_DOMAIN
        )
        second = await public_key_fetch._public_key_pem_at_url(
            end_point.url_for(later), key_fixtures.IDENTIFIER_DOMAIN
        )
        self.assertNotEqual(first, second, "two weeks, two keys")
        self.assertEqual(2, len(end_point.dates()), "one request per week")
        again = await public_key_fetch._public_key_pem_at_url(
            end_point.url_for(earlier), key_fixtures.IDENTIFIER_DOMAIN
        )
        self.assertEqual(first, again, "the held key is the one fetched for that week")
        self.assertEqual(
            2, len(end_point.dates()), "a week already held is not asked for again"
        )
        self.assertIn("BEGIN PUBLIC KEY", first)

    async def test_the_cache_is_bounded(self) -> None:
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
                await public_key_fetch._public_key_pem_at_url(
                    end_point.url_for(week), key_fixtures.IDENTIFIER_DOMAIN
                )
            self.assertEqual(3, len(end_point.dates()))
            # The third arrival emptied the store, so the first week is
            # fetched again rather than answered from what was held.
            await public_key_fetch._public_key_pem_at_url(
                end_point.url_for(weeks[0]), key_fixtures.IDENTIFIER_DOMAIN
            )
            self.assertEqual(4, len(end_point.dates()))

    @staticmethod
    def _at(moment: datetime) -> Owid:
        """An identifier from the fixture domain dated at the moment."""
        return crafted(Version.VERSION3, key_fixtures.IDENTIFIER_DOMAIN, moment)

    @staticmethod
    async def _pem_at(end_point: KeyEndPoint, moment: datetime) -> str:
        """The PEM the fetch answers for an identifier dated at the moment."""
        return await public_key_fetch._public_key_pem_at_url(
            end_point.url_for(PublicKeyFetchTests._at(moment)),
            key_fixtures.IDENTIFIER_DOMAIN,
        )

    @staticmethod
    def _in_force(moment: datetime) -> str:
        """The PEM the published schedule says was in force at the moment."""
        key = key_fixtures.schedule().key_in_force(moment)
        assert key is not None
        return key.public_key_pem

    async def test_a_minute_between_two_confirmed_minutes_is_served_from_the_cache(
        self,
    ) -> None:
        """A key the creator has confirmed for two minutes is served for every
        minute between them without a request, because a key is in force from
        the start of its period until the next key starts. A minute outside
        every confirmed span is asked about."""
        end_point = self.end_point(Answer.SPANLESS)
        # The week of 31 August 2026, which the fixture identifier was signed
        # in, and which is wholly in the past so the cache reads each minute
        # as itself rather than as now.
        first = datetime(2026, 8, 31, 0, 1, tzinfo=timezone.utc)
        last = datetime(2026, 9, 6, 23, 0, tzinfo=timezone.utc)
        pem = await self._pem_at(end_point, first)
        self.assertEqual(pem, await self._pem_at(end_point, last), "one key covers the week")
        self.assertEqual(2, len(end_point.dates()), "the two ends of the span were asked about")
        for between in (
            first + timedelta(minutes=1),
            first + timedelta(days=3),
            last - timedelta(minutes=1),
        ):
            self.assertEqual(pem, await self._pem_at(end_point, between))
        self.assertEqual(
            2, len(end_point.dates()), "a minute between two confirmed minutes is not asked about"
        )
        self.assertEqual(
            1, public_key_fetch._cached_key_count(), "one key is held however many minutes it covers"
        )
        self.assertNotEqual(
            pem,
            await self._pem_at(end_point, first - timedelta(minutes=2)),
            "a minute in the week before is the earlier week's key",
        )
        self.assertEqual(3, len(end_point.dates()), "a minute before the span is asked about")
        self.assertEqual(
            2, public_key_fetch._cached_key_count(), "the earlier week's key is held as a second key"
        )

    async def test_a_hundred_identifiers_in_one_confirmed_period_make_no_request(
        self,
    ) -> None:
        """The case that made the cache almost useless when it was keyed by
        the whole URL. A hundred identifiers with a hundred different minutes
        inside one key's period cost a hundred requests then. With the ends
        of the period confirmed they cost none."""
        end_point = self.end_point(Answer.SPANLESS)
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        await self._pem_at(end_point, start)
        await self._pem_at(end_point, start + timedelta(minutes=100))
        for i in range(1, 101):
            await self._pem_at(end_point, start + timedelta(minutes=i))
        self.assertEqual(
            2,
            len(end_point.dates()),
            "a hundred identifiers over a hundred minutes made no request "
            "once both ends of the span were known",
        )

    async def test_a_key_is_never_served_for_a_minute_outside_its_confirmed_span(
        self,
    ) -> None:
        """A key is only ever served for a minute inside the span the creator
        has confirmed it for. Where the creator rotated between two confirmed
        minutes, the minutes between them belong to neither key until the
        creator is asked, and every answer agrees with the published
        schedule."""
        end_point = self.end_point(Answer.SPANLESS)
        rotation = datetime(2026, 8, 31, tzinfo=timezone.utc)
        week = timedelta(days=7)
        minute = timedelta(minutes=1)
        # The start of the week before the rotation and the end of the week
        # after it, so the two keys are held with the rotation between.
        await self._pem_at(end_point, rotation - week)
        await self._pem_at(end_point, rotation + week - minute)
        self.assertEqual(2, len(end_point.dates()))
        self.assertEqual(2, public_key_fetch._cached_key_count())

        # Every minute across the rotation, in an order that walks in from
        # both sides, is answered with the key the schedule gives, whether
        # from the cache or by asking.
        moments = [
            rotation - minute,
            rotation,
            rotation - 2 * minute,
            rotation + minute,
            rotation - week / 2,
            rotation + week / 2,
            rotation - 3 * minute,
            rotation + 2 * minute,
            rotation - minute,
            rotation,
        ]
        for moment in moments:
            self.assertEqual(
                self._in_force(moment),
                await self._pem_at(end_point, moment),
                "the key served for {0}".format(moment),
            )
        self.assertEqual(
            2, public_key_fetch._cached_key_count(), "two keys are held, each with its own span"
        )
        asked = len(end_point.dates())
        self.assertTrue(
            2 < asked < 2 + len(moments),
            "some minutes were asked about and some were served: {0}".format(asked),
        )

        # The minute either side of the rotation is now confirmed, so nothing
        # across the whole fortnight needs asking.
        moment = rotation - week
        while moment < rotation + week:
            self.assertEqual(
                self._in_force(moment),
                await self._pem_at(end_point, moment),
                "the key served for {0}".format(moment),
            )
            moment += timedelta(hours=1)
        self.assertEqual(
            asked, len(end_point.dates()), "both spans are fully confirmed, so nothing was asked"
        )

    async def test_a_minute_within_the_drift_allowance_is_not_held(self) -> None:
        """A minute within the clock drift allowance of now, or later, is
        asked about every time and never held, because a creator whose clock
        differs from this one's may have read it as its present rather than
        as the minute named. A minute beyond the allowance is held as usual.
        Live identifiers therefore cost one request per minute per creator and older ones cost none."""
        end_point = self.end_point(Answer.SPANLESS)
        started = io.minutes_since_base(datetime.now(timezone.utc))
        now = datetime.now(timezone.utc)
        recent = now - timedelta(minutes=1)
        await self._pem_at(end_point, recent)
        await self._pem_at(end_point, recent)
        await self._pem_at(end_point, now + timedelta(days=7))
        await public_key_fetch._public_key_pem_at_url(
            end_point.base + "/owid/api/v3/public-key?format=pkcs",
            key_fixtures.IDENTIFIER_DOMAIN,
        )
        old = now - timedelta(
            minutes=public_key_fetch.CLOCK_DRIFT_ALLOWANCE_MINUTES + 1
        )
        await self._pem_at(end_point, old)
        await self._pem_at(end_point, old)
        if io.minutes_since_base(datetime.now(timezone.utc)) != started:
            self.skipTest(
                "the minute changed during the test, so the calls were not "
                "all about the same now"
            )
        self.assertEqual(
            5,
            len(end_point.dates()),
            "the recent minute was asked about twice, the future minute and "
            "the request with no date once each, and the old minute once "
            "with the second call held",
        )
        self.assertEqual(
            1, public_key_fetch._cached_key_count(), "only the old minute's key is held"
        )

    async def test_a_key_answered_with_its_span_is_held_for_the_whole_span(self) -> None:
        """A creator that states the moments the key is valid from and to,
        which is what the package's own server side helper answers, has the
        whole span held from that one answer, so every other minute of the
        span is served without a request."""
        end_point = self.end_point()
        pem = await self._pem_at(end_point, datetime(2026, 8, 31, 0, 1, tzinfo=timezone.utc))
        for moment in (
            datetime(2026, 9, 6, 23, 59, tzinfo=timezone.utc),
            datetime(2026, 9, 3, 12, tzinfo=timezone.utc),
            datetime(2026, 8, 31, tzinfo=timezone.utc),
        ):
            self.assertEqual(pem, await self._pem_at(end_point, moment), str(moment))
        self.assertEqual(1, len(end_point.dates()), "the whole week was held from one answer")
        self.assertEqual(1, public_key_fetch._cached_key_count())
        before = await self._pem_at(end_point, datetime(2026, 8, 30, 23, 59, tzinfo=timezone.utc))
        self.assertNotEqual(pem, before, "the minute before the week is the earlier week's key")
        await self._pem_at(end_point, datetime(2026, 8, 24, tzinfo=timezone.utc))
        self.assertEqual(2, len(end_point.dates()), "the earlier week was held from its one answer")

    async def test_a_recent_minute_is_served_where_the_creator_stated_the_span(self) -> None:
        """The drift allowance, which keeps minutes near now out of a cache
        built from confirmed minutes, does not apply to a span the creator
        stated itself, so live identifiers cost one request per key rather
        than one per minute."""
        end_point = self.end_point()
        now = datetime.now(timezone.utc)
        current = key_fixtures.schedule().key_in_force(now)
        if current is None or key_fixtures.schedule().next_start_after(current) is None:
            self.skipTest("the fixture schedule has no key after the one in force now")
        await self._pem_at(end_point, now - timedelta(minutes=1))
        await self._pem_at(end_point, now)
        await self._pem_at(end_point, now - timedelta(minutes=10))
        self.assertEqual(
            1, len(end_point.dates()), "the current key was served for every recent minute from one answer"
        )

    @staticmethod
    def _signed_at(domain: str, moment: datetime, crypto: Crypto) -> Owid:
        """An identifier for the domain dated at the moment and signed with
        the crypto given, standing for one whose signing machine's clock did
        not agree with the creator's schedule to the minute."""
        owid = Owid._create(
            version=Version.VERSION3, domain=domain, date=moment, payload=b"payload"
        )
        owid._signature = crypto.sign_byte_array(owid.data_for_crypto([]))
        return owid

    async def test_a_signature_failing_near_the_edge_of_a_span_is_checked_against_the_neighbour(
        self,
    ) -> None:
        """An identifier dated just after a key started, but signed with the
        key before it, verifies, and one dated just before a key started but
        signed with it verifies too, because the neighbouring key is tried
        when the selected key fails within the drift allowance of the span's
        edge. Further from the edge the failure stands. The stand in creator
        answers with the package's own server side helper, so the loop
        between the two halves of the package is closed."""
        first, second, third = Crypto.new(), Crypto.new(), Crypto.new()
        rotation = datetime(2026, 8, 31, tzinfo=timezone.utc)
        week = timedelta(days=7)
        schedule = PublicKeySchedule(
            [
                DatedPublicKey(rotation - week, first.public_key_pem()),
                DatedPublicKey(rotation, second.public_key_pem()),
                DatedPublicKey(rotation + week, third.public_key_pem()),
            ]
        )
        requests: List[str] = []

        async def creator(url: str, timeout: float) -> Tuple[int, bytes]:
            requests.append(url)
            date = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)).get("date")
            status, body = endpoints.public_key_response_at(schedule, "pkcs", date)
            return status, body.encode("utf-8")

        url = "https://creator.test/owid/api/v3/public-key?date={0}&format=pkcs"

        async def status_of(owid: Owid) -> SignatureStatus:
            return await public_key_fetch._signature_status_at_url(
                owid, url.format(io.minutes_since_base(owid.date)), None, creator
            )

        late = self._signed_at("creator.test", rotation + timedelta(minutes=5), first)
        self.assertIs(SignatureStatus.SIGNATURE_VALID, await status_of(late),
                      "signed with the earlier key just after the rotation")
        self.assertEqual(2, len(requests), "the selected key and then the earlier key were asked for")
        early = self._signed_at("creator.test", rotation - timedelta(minutes=5), second)
        self.assertIs(SignatureStatus.SIGNATURE_VALID, await status_of(early),
                      "signed with the later key just before the rotation")
        self.assertEqual(2, len(requests), "both keys are held with their spans")
        far = self._signed_at("creator.test", rotation + timedelta(minutes=20), first)
        self.assertIs(SignatureStatus.SIGNATURE_INVALID, await status_of(far),
                      "well inside the later key's span")
        self.assertEqual(2, len(requests), "the neighbouring minutes lie inside the spans held")
        genuine = self._signed_at("creator.test", rotation + timedelta(days=3), second)
        self.assertIs(SignatureStatus.SIGNATURE_VALID, await status_of(genuine))
        forged = self._signed_at("creator.test", rotation + timedelta(days=3), third)
        self.assertIs(SignatureStatus.SIGNATURE_INVALID, await status_of(forged),
                      "signed with a key not in force at its date")

    async def test_an_answer_that_is_not_the_json_form_is_a_key_that_cannot_be_read(self) -> None:
        """The PEM alone as text is reported as a key this package cannot read rather than used, and so is a span that ends before it starts."""
        end_point = self.end_point(Answer.PEM_ONLY)
        owid = key_fixtures.identifier()
        self.assertIs(
            SignatureStatus.INVALID_KEY,
            await public_key_fetch._signature_status_at_url(owid, end_point.url_for(owid)),
        )

        async def contradictory(url: str, timeout: float) -> Tuple[int, bytes]:
            return 200, json.dumps(
                {
                    "publicKeySPKI": key_fixtures.schedule().keys[0].public_key_pem,
                    "validFrom": "2026-08-31T00:00:00Z",
                    "validTo": "2026-08-24T00:00:00Z",
                }
            ).encode("utf-8")

        self.assertIs(
            SignatureStatus.INVALID_KEY,
            await public_key_fetch._signature_status_at_url(
                owid, end_point.url_for(owid), None, contradictory
            ),
        )

    def test_many_threads_verifying_one_owid_together_make_one_request(self) -> None:
        """Threads verifying the same OWID at the same moment, each on its own
        event loop, make one request for its key between them, and every one
        of them gets the answer. The stand in transport holds its answer until
        every thread has asked, so all of them are in flight together against
        one request."""
        callers = 8
        owid = key_fixtures.identifier()
        pem = key_fixtures.schedule().key_for(owid).public_key_pem
        answer = endpoints.public_key_answer(pem, None, None, None).encode("utf-8")
        requests: List[str] = []
        release = threading.Event()
        started = threading.Barrier(callers + 1)

        async def transport(url: str, timeout: float) -> Tuple[int, bytes]:
            requests.append(url)
            await asyncio.get_running_loop().run_in_executor(None, release.wait)
            return 200, answer

        url = public_key_fetch.public_key_url(owid, "https")
        statuses: List[SignatureStatus] = []

        def verify() -> None:
            started.wait()
            statuses.append(
                asyncio.run(
                    public_key_fetch._signature_status_at_url(owid, url, None, transport)
                )
            )

        threads = [threading.Thread(target=verify) for _ in range(callers)]
        for thread in threads:
            thread.start()
        # Every thread goes at the same moment, and the transport only
        # answers once they are all waiting on it.
        started.wait()
        time.sleep(0.3)
        release.set()
        for thread in threads:
            thread.join(30)
        self.assertEqual(callers, len(statuses), "every thread finished")
        self.assertEqual({SignatureStatus.SIGNATURE_VALID}, set(statuses))
        self.assertEqual(1, len(requests), "one request for {0} threads".format(callers))

    async def test_concurrent_awaits_for_one_key_share_one_request(
        self,
    ) -> None:
        """Two callers who await the same key while the request for it is in
        flight share that request, and both receive its answer. The transport
        is held open until both have asked, so the second caller cannot be
        answered from the cache and has to join the request itself."""
        owid = key_fixtures.identifier()
        pem = key_fixtures.schedule().key_for(owid).public_key_pem
        arrived = asyncio.Event()
        release = asyncio.Event()
        calls: List[str] = []

        async def held_open(url: str, timeout: float) -> Tuple[int, bytes]:
            calls.append(url)
            arrived.set()
            await release.wait()
            return 200, endpoints.public_key_answer(pem, None, None, None).encode("utf-8")

        first = asyncio.ensure_future(
            public_key_fetch.public_key_pem(owid, "https", held_open)
        )
        second = asyncio.ensure_future(
            public_key_fetch.public_key_pem(owid, "https", held_open)
        )
        await arrived.wait()
        self.assertFalse(first.done(), "the request is still in flight")
        self.assertFalse(second.done(), "the second caller is waiting on it")
        release.set()
        self.assertEqual([pem, pem], await asyncio.gather(first, second))
        self.assertEqual(
            [public_key_fetch.public_key_url(owid, "https")],
            calls,
            "one request for the URL the package builds, shared by both",
        )
        self.assertTrue(
            await public_key_fetch.verify(owid, "https", ALONE, held_open),
            "a later caller is answered from the cache",
        )
        self.assertEqual(1, len(calls), "the cache answered the third caller")

    async def test_concurrent_awaits_share_one_request_to_the_end_point(
        self,
    ) -> None:
        """The same sharing over the default transport, against the stand in
        end point, which records one request for the three callers."""
        owid = key_fixtures.identifier()
        end_point = self.end_point()
        url = end_point.url_for(owid)
        pems = await asyncio.gather(
            *[
                public_key_fetch._public_key_pem_at_url(url, owid.domain)
                for _ in range(3)
            ]
        )
        self.assertEqual(3, len(pems))
        self.assertEqual(1, len(set(pems)), "every caller received the key")
        self.assertIn("BEGIN PUBLIC KEY", pems[0])
        self.assertEqual(
            [str(key_fixtures.IDENTIFIER_MINUTES)],
            end_point.dates(),
            "three callers, one request",
        )

    async def test_a_failure_in_flight_reaches_every_waiter(self) -> None:
        """A request that fails is reported to every caller waiting on it, and
        then forgotten, so the next caller makes a request of its own rather
        than being handed the old failure."""
        owid = key_fixtures.identifier()
        release = asyncio.Event()
        calls: List[str] = []

        async def held_then_refused(
            url: str, timeout: float
        ) -> Tuple[int, bytes]:
            calls.append(url)
            await release.wait()
            raise OSError("no route")

        first = asyncio.ensure_future(
            public_key_fetch.signature_status(
                owid, "https", ALONE, held_then_refused
            )
        )
        second = asyncio.ensure_future(
            public_key_fetch.signature_status(
                owid, "https", ALONE, held_then_refused
            )
        )
        while not calls:
            await asyncio.sleep(0)
        release.set()
        self.assertEqual(
            [SignatureStatus.KEY_UNAVAILABLE, SignatureStatus.KEY_UNAVAILABLE],
            await asyncio.gather(first, second),
        )
        self.assertEqual(1, len(calls), "one request, shared by both callers")
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, held_then_refused
            ),
        )
        self.assertEqual(
            2,
            len(calls),
            "a failed request is not held, so the next caller asks again",
        )

    async def test_cancelling_one_waiter_leaves_the_request_running(
        self,
    ) -> None:
        """Cancelling a caller must not cancel the request another caller is
        waiting on, and a request on a worker thread could not be stopped
        part way in any case, so the request completes and its answer is
        held for the caller that is still waiting."""
        owid = key_fixtures.identifier()
        pem = key_fixtures.schedule().key_for(owid).public_key_pem
        release = asyncio.Event()
        calls: List[str] = []

        async def held_open(url: str, timeout: float) -> Tuple[int, bytes]:
            calls.append(url)
            await release.wait()
            return 200, endpoints.public_key_answer(pem, None, None, None).encode("utf-8")

        first = asyncio.ensure_future(
            public_key_fetch.public_key_pem(owid, "https", held_open)
        )
        second = asyncio.ensure_future(
            public_key_fetch.public_key_pem(owid, "https", held_open)
        )
        while not calls:
            await asyncio.sleep(0)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        release.set()
        self.assertEqual(pem, await second)
        self.assertEqual(1, len(calls))

    async def test_a_domain_that_is_not_a_domain_name_is_refused_before_any_request(
        self,
    ) -> None:
        """The domain arrives inside an OWID, which came from outside, so a
        value that would change the shape of the URL rather than name a host
        in it is refused before any request is made."""
        owid = crafted(Version.VERSION3, "51d.es/evil?x=", IDENTIFIER_DATE)
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "https")

        async def no_request(url: str, timeout: float) -> Tuple[int, bytes]:
            self.fail("no request should be made for a refused domain")

        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, no_request
            ),
        )

    async def test_a_scheme_that_does_not_make_an_http_request_is_refused(
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
            await public_key_fetch._signature_status_at_url(owid, url, ALONE),
        )
        with self.assertRaises(PublicKeyFetchError) as refused:
            await public_key_fetch._public_key_pem_at_url(url, owid.domain)
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(0, refused.exception.status_code)

    async def test_a_missing_owid_or_scheme_is_refused(self) -> None:
        owid = key_fixtures.identifier()
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(None, "https")  # type: ignore[arg-type]
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "")
        with self.assertRaises(OwidError):
            public_key_fetch.public_key_url(owid, "   ")
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                None, "https"  # type: ignore[arg-type]
            ),
        )

    async def test_a_transport_of_the_callers_own_is_used(self) -> None:
        """A caller whose environment needs its own HTTP client supplies a
        transport, which is asked for the URL the package builds and whose
        answer is held like any other."""
        owid = key_fixtures.identifier()
        pem = key_fixtures.schedule().key_for(owid).public_key_pem
        calls: List[Tuple[str, float]] = []

        async def transport(url: str, timeout: float) -> Tuple[int, bytes]:
            calls.append((url, timeout))
            return 200, endpoints.public_key_answer(pem, None, None, None).encode("utf-8")

        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, transport
            ),
        )
        self.assertTrue(
            await public_key_fetch.verify(owid, "https", ALONE, transport)
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

    async def test_verify_answers_true_only_for_a_genuine_signature(
        self,
    ) -> None:
        owid = key_fixtures.identifier()
        schedule = key_fixtures.schedule()
        keys = schedule.keys
        signing = schedule.key_for(owid)
        following = keys[keys.index(signing) + 1]

        async def wrong_week(url: str, timeout: float) -> Tuple[int, bytes]:
            return 200, endpoints.public_key_answer(following.public_key_pem, None, None, None).encode("utf-8")

        self.assertFalse(
            await public_key_fetch.verify(owid, "https", ALONE, wrong_week),
            "the following week's key did not sign the identifier",
        )

    async def test_a_transport_that_raises_is_key_unavailable(self) -> None:
        owid = key_fixtures.identifier()

        async def unreachable(url: str, timeout: float) -> Tuple[int, bytes]:
            raise OSError("no route")

        async def unusable(url: str, timeout: float) -> Tuple[int, bytes]:
            raise ValueError("unknown url type")

        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, unreachable
            ),
        )
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, unusable
            ),
        )

    async def test_a_response_larger_than_a_key_is_refused(self) -> None:
        """A body beyond the bound is not a key, and is neither held nor
        decoded."""
        owid = key_fixtures.identifier()
        too_large = b"x" * (public_key_fetch.MAXIMUM_RESPONSE_BYTES + 1)

        async def oversized(url: str, timeout: float) -> Tuple[int, bytes]:
            return 200, too_large

        with self.assertRaises(PublicKeyFetchError) as refused:
            await public_key_fetch.public_key_pem(owid, "https", oversized)
        self.assertIs(SignatureStatus.KEY_UNAVAILABLE, refused.exception.status)
        self.assertEqual(200, refused.exception.status_code)
        public_key_fetch.clear_cache()
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            await public_key_fetch.signature_status(
                owid, "https", ALONE, oversized
            ),
        )


if __name__ == "__main__":
    unittest.main()
