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
"""Choosing the key that signed an identifier out of the schedule a creator
has published, checked against a genuine identifier the 51Degrees cloud issued
on 4 September 2026 and the thirty keys the cloud published for that creator.

The fault this guards against was found on 4 September 2026 in the .NET port,
which selected the key by the moment the key material was generated. The cloud
had generated thirteen weeks of keys in one run on 1 September, so the newest
generated key was one whose period had not begun, and a genuine identifier was
reported as not matching.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from owid import (
    Crypto,
    DatedPublicKey,
    OwidError,
    PublicKeySchedule,
    SignatureStatus,
)

from tests import key_fixtures


def fresh_pem() -> str:
    return Crypto.new().public_key_pem()


class PublicKeyScheduleTests(unittest.TestCase):
    def test_genuine_identifier_verifies_against_the_key_in_force_on_its_date(
        self,
    ) -> None:
        """The published key for the week of 31 August 2026 verifies the
        identifier created on 4 September, checked directly against the
        record rather than through the schedule, so the fixture itself is
        shown to be sound."""
        owid = key_fixtures.identifier()
        week = [
            key
            for key in key_fixtures.scheduled_keys()
            if key.starts_at == key_fixtures.WEEK_OF_THE_IDENTIFIER
        ]
        self.assertEqual(1, len(week), "the schedule holds that week once")
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            owid.signature_status(week[0].pem),
        )

    def test_schedule_verifies_the_genuine_identifier(self) -> None:
        owid = key_fixtures.identifier()
        schedule = key_fixtures.schedule()
        chosen = schedule.key_for(owid)
        self.assertIsNotNone(chosen)
        self.assertEqual(key_fixtures.WEEK_OF_THE_IDENTIFIER, chosen.starts_at)
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID, schedule.signature_status(owid)
        )
        self.assertTrue(schedule.verify(owid))

    def test_a_later_weeks_key_does_not_verify_an_earlier_weeks_identifier(
        self,
    ) -> None:
        """The key that started after the identifier was signed reports the
        signature as not matching, which is the answer a verifier that took
        the newest key would have given for a genuine identifier."""
        owid = key_fixtures.identifier()
        schedule = key_fixtures.schedule()
        keys = schedule.keys
        signing = schedule.key_for(owid)
        following = keys[keys.index(signing) + 1]
        self.assertGreater(following.starts_at, owid.date)
        self.assertIs(
            SignatureStatus.SIGNATURE_INVALID,
            owid.signature_status(following.public_key_pem),
        )

    def test_the_last_key_is_not_the_key_in_force(self) -> None:
        """A schedule is published ahead of time, so its last key is one whose
        period has not begun, and serving that where the current key was
        meant would fail every check of an identifier signed today."""
        now = datetime.now(timezone.utc)
        schedule = PublicKeySchedule(
            [
                DatedPublicKey(now - timedelta(days=7), fresh_pem()),
                DatedPublicKey(now + timedelta(days=7), fresh_pem()),
            ]
        )
        self.assertEqual(
            now + timedelta(days=7),
            schedule.last().starts_at,
            "the last key is the one with the latest start",
        )
        self.assertEqual(
            now - timedelta(days=7),
            schedule.current().starts_at,
            "the key in force now is the one that has started",
        )

    def test_verified_under_the_published_starts_and_invalid_when_shifted(
        self,
    ) -> None:
        """The two pass check that tells selecting by start from anything
        else. Under the published schedule the genuine identifier verifies.
        Move every start one week later, keeping every key, and the same
        identifier must read as not matching, because the key now chosen
        for its date is the one that was in force the week before. A
        selection that ignored the starts would answer the same both
        times."""
        owid = key_fixtures.identifier()
        published = key_fixtures.scheduled_keys()
        as_published = PublicKeySchedule(
            DatedPublicKey(key.starts_at, key.pem) for key in published
        )
        shifted = PublicKeySchedule(
            DatedPublicKey(key.starts_at + timedelta(days=7), key.pem)
            for key in published
        )
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID, as_published.signature_status(owid)
        )
        self.assertIs(
            SignatureStatus.SIGNATURE_INVALID, shifted.signature_status(owid)
        )

    def test_selection_ignores_the_moment_the_keys_were_generated(self) -> None:
        """The shape that broke the .NET port. Thirteen of the published keys
        were generated in one batch on 1 September 2026 and cover the weeks
        from 7 September to 30 November, so on 4 September the newest key
        that had already been generated was one that had not started yet."""
        owid = key_fixtures.identifier()
        published = key_fixtures.scheduled_keys()
        generated_before = [
            key for key in published if key.created <= owid.date
        ]
        self.assertTrue(generated_before, "keys were generated before the date")
        newest_generated = max(generated_before, key=lambda key: key.created)
        sharing_the_batch = [
            key for key in published if key.created == newest_generated.created
        ]
        self.assertEqual(
            13,
            len(sharing_the_batch),
            "thirteen keys share the generation moment of 1 September",
        )
        self.assertGreater(
            newest_generated.starts_at,
            owid.date,
            "the newest generated key had not started when the identifier "
            "was signed",
        )
        self.assertIs(
            SignatureStatus.SIGNATURE_INVALID,
            owid.signature_status(newest_generated.pem),
            "selecting on the generation moment reports a genuine identifier "
            "as not matching",
        )
        chosen = key_fixtures.schedule().key_for(owid)
        self.assertIsNotNone(chosen, "the schedule covers the date")
        self.assertEqual(
            key_fixtures.WEEK_OF_THE_IDENTIFIER,
            chosen.starts_at,
            "selecting on the start picks the week that was running",
        )
        self.assertIs(
            SignatureStatus.SIGNATURE_VALID,
            owid.signature_status(chosen.public_key_pem),
            "selecting on the start verifies the genuine identifier",
        )

    def test_a_key_is_in_force_from_its_start_until_the_next_start(self) -> None:
        schedule = key_fixtures.schedule()
        keys = schedule.keys
        for index in range(1, len(keys)):
            previous = keys[index - 1]
            key = keys[index]
            start = key.starts_at
            self.assertEqual(
                key.starts_at,
                schedule.key_in_force(start).starts_at,
                "the start belongs to the key that is starting",
            )
            self.assertEqual(
                previous.starts_at,
                schedule.key_in_force(start - timedelta(minutes=1)).starts_at,
                "the minute before the start belongs to the key before",
            )
            self.assertEqual(
                key.starts_at,
                schedule.key_in_force(start + timedelta(days=6)).starts_at,
                "the rest of the week belongs to the key that started",
            )

    def test_keys_may_arrive_in_any_order(self) -> None:
        forwards = key_fixtures.schedule().keys
        backwards = PublicKeySchedule(reversed(forwards)).keys
        self.assertEqual(
            [key.starts_at for key in forwards],
            [key.starts_at for key in backwards],
            "the schedule is held oldest start first whatever the order given",
        )
        self.assertEqual(len(forwards), len(PublicKeySchedule(reversed(forwards))))

    def test_a_date_before_the_schedule_has_no_key(self) -> None:
        schedule = key_fixtures.schedule()
        before = schedule.keys[0].starts_at - timedelta(minutes=1)
        self.assertIsNone(schedule.key_in_force(before))
        self.assertIsNone(schedule.key_in_force(None))
        owid = key_fixtures.identifier()
        late_start = PublicKeySchedule(
            [DatedPublicKey(owid.date + timedelta(days=1), fresh_pem())]
        )
        self.assertIsNone(late_start.key_for(owid))
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE, late_start.signature_status(owid)
        )
        self.assertFalse(late_start.verify(owid))

    def test_an_empty_schedule_has_no_key(self) -> None:
        schedule = PublicKeySchedule([])
        self.assertEqual(0, len(schedule))
        self.assertIsNone(schedule.last())
        self.assertIsNone(schedule.current())
        self.assertIsNone(schedule.key_in_force(datetime.now(timezone.utc)))
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE,
            schedule.signature_status(key_fixtures.identifier()),
        )

    def test_a_missing_owid_is_key_unavailable(self) -> None:
        schedule = key_fixtures.schedule()
        self.assertIsNone(schedule.key_for(None))
        self.assertIs(
            SignatureStatus.KEY_UNAVAILABLE, schedule.signature_status(None)
        )
        self.assertFalse(schedule.verify(None))

    def test_two_keys_sharing_a_start_are_settled_in_favour_of_the_first_supplied(
        self,
    ) -> None:
        """A creator does not publish two keys for one start, so the case is
        settled the way the cloud settles it rather than left to chance."""
        start = datetime(2026, 8, 31, tzinfo=timezone.utc)
        first = DatedPublicKey(start, fresh_pem())
        second = DatedPublicKey(start, fresh_pem())
        schedule = PublicKeySchedule([second, first])
        self.assertIs(second, schedule.key_in_force(start))
        self.assertIs(second, schedule.key_in_force(start + timedelta(days=3)))
        reordered = PublicKeySchedule([first, second])
        self.assertIs(first, reordered.key_in_force(start))

    def test_naive_datetimes_are_read_as_utc(self) -> None:
        aware = datetime(2026, 8, 31, tzinfo=timezone.utc)
        key = DatedPublicKey(datetime(2026, 8, 31), fresh_pem())
        self.assertEqual(aware, key.starts_at)
        schedule = PublicKeySchedule([key])
        self.assertIs(key, schedule.key_in_force(datetime(2026, 9, 4)))
        self.assertIsNone(schedule.key_in_force(datetime(2026, 8, 30, 23, 59)))

    def test_missing_values_are_refused(self) -> None:
        with self.assertRaises(OwidError):
            PublicKeySchedule(None)  # type: ignore[arg-type]
        with self.assertRaises(OwidError):
            PublicKeySchedule([None])  # type: ignore[list-item]
        with self.assertRaises(OwidError):
            DatedPublicKey(None, fresh_pem())  # type: ignore[arg-type]
        with self.assertRaises(OwidError):
            DatedPublicKey("2026-08-31", fresh_pem())  # type: ignore[arg-type]
        with self.assertRaises(OwidError):
            DatedPublicKey(datetime.now(timezone.utc), "")
        with self.assertRaises(OwidError):
            DatedPublicKey(datetime.now(timezone.utc), "   ")

    def test_the_keys_handed_out_cannot_be_changed(self) -> None:
        schedule = key_fixtures.schedule()
        keys = schedule.keys
        with self.assertRaises(TypeError):
            keys[0] = DatedPublicKey(  # type: ignore[index]
                datetime.now(timezone.utc), fresh_pem()
            )
        with self.assertRaises(AttributeError):
            keys[0].starts_at = datetime.now(timezone.utc)  # type: ignore[misc]
        self.assertEqual(30, len(schedule), "the published schedule holds thirty keys")


if __name__ == "__main__":
    unittest.main()
