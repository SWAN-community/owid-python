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
"""The public key end point of a creator that rotates its key, answering the
date parameter the way the specification requires: the key in force at the
date asked, the key in force now where no date is given or the date is later
than now, 404 where no key is in force, and 400 where the date is not a count
of minutes."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from owid import Crypto, DatedPublicKey, OwidError, PublicKeySchedule, endpoints, io


def fresh_pem() -> str:
    return Crypto.new().public_key_pem()


class PublicKeyResponseAtTests(unittest.TestCase):
    def setUp(self) -> None:
        self.last_week = DatedPublicKey(
            datetime(2026, 8, 24, tzinfo=timezone.utc), fresh_pem()
        )
        self.this_week = DatedPublicKey(
            datetime(2026, 8, 31, tzinfo=timezone.utc), fresh_pem()
        )
        self.next_week = DatedPublicKey(
            datetime(2026, 9, 7, tzinfo=timezone.utc), fresh_pem()
        )
        self.schedule = PublicKeySchedule(
            [self.next_week, self.last_week, self.this_week]
        )
        # The moment of the request, in the week of 31 August 2026 with the
        # following week's key already published.
        self.now = datetime(2026, 9, 4, 20, 32, tzinfo=timezone.utc)

    def minutes(self, moment: datetime) -> str:
        return str(io.minutes_since_base(moment))

    def test_a_dated_request_is_served_the_key_in_force_then(self) -> None:
        asked = datetime(2026, 8, 26, tzinfo=timezone.utc)
        self.assertEqual(
            (200, self.last_week.public_key_pem),
            endpoints.public_key_response_at(
                self.schedule, "pkcs", self.minutes(asked), self.now
            ),
        )
        self.assertEqual(
            (200, self.this_week.public_key_pem),
            endpoints.public_key_response_at(
                self.schedule, "spki", self.minutes(self.now), self.now
            ),
        )

    def test_the_date_may_arrive_as_a_number(self) -> None:
        asked = datetime(2026, 8, 26, tzinfo=timezone.utc)
        self.assertEqual(
            (200, self.last_week.public_key_pem),
            endpoints.public_key_response_at(
                self.schedule, "pkcs", io.minutes_since_base(asked), self.now
            ),
        )

    def test_an_undated_request_is_served_the_key_in_force_now(self) -> None:
        """The key in force now is not the last key of the schedule, which is
        one whose period has not begun."""
        for absent in (None, ""):
            self.assertEqual(
                (200, self.this_week.public_key_pem),
                endpoints.public_key_response_at(
                    self.schedule, "pkcs", absent, self.now
                ),
            )

    def test_a_future_date_is_read_as_now(self) -> None:
        """A caller cannot ask for a key whose period has not begun, because a
        key that has signed nothing yet has nothing to verify."""
        future = datetime(2026, 9, 8, tzinfo=timezone.utc)
        self.assertEqual(
            (200, self.this_week.public_key_pem),
            endpoints.public_key_response_at(
                self.schedule, "pkcs", self.minutes(future), self.now
            ),
        )

    def test_a_date_beyond_the_calendar_is_read_as_now(self) -> None:
        """The largest value the field can hold is past the year 9999, and it
        is after every key, so the answer is the key in force now rather than
        a failure in the date arithmetic."""
        self.assertEqual(
            (200, self.this_week.public_key_pem),
            endpoints.public_key_response_at(
                self.schedule, "pkcs", str(0xFFFFFFFF), self.now
            ),
        )

    def test_a_date_before_the_schedule_is_404(self) -> None:
        before = datetime(2026, 8, 23, tzinfo=timezone.utc)
        self.assertEqual(
            (404, ""),
            endpoints.public_key_response_at(
                self.schedule, "pkcs", self.minutes(before), self.now
            ),
        )
        self.assertEqual(
            (404, ""),
            endpoints.public_key_response_at(
                PublicKeySchedule([]), "pkcs", None, self.now
            ),
        )

    def test_a_date_that_is_not_a_count_of_minutes_is_400(self) -> None:
        for malformed in ("abc", "-1", "1.5", " 12", "+5", "4294967296", "²"):
            with self.subTest(date=malformed):
                self.assertEqual(
                    (400, ""),
                    endpoints.public_key_response_at(
                        self.schedule, "pkcs", malformed, self.now
                    ),
                )
        self.assertEqual(
            (400, ""),
            endpoints.public_key_response_at(self.schedule, "pkcs", -1, self.now),
        )
        self.assertEqual(
            (400, ""),
            endpoints.public_key_response_at(self.schedule, "pkcs", True, self.now),
        )

    def test_the_format_must_be_spki_or_pkcs(self) -> None:
        with self.assertRaises(OwidError):
            endpoints.public_key_response_at(self.schedule, "der", None, self.now)

    def test_the_moment_of_the_request_defaults_to_now(self) -> None:
        """Without a moment supplied the clock is used, so the answer is the
        latest key that has started by the time the test runs."""
        status, body = endpoints.public_key_response_at(self.schedule, "pkcs", None)
        self.assertEqual(200, status)
        self.assertIn("BEGIN PUBLIC KEY", body)
        started = [
            key for key in self.schedule.keys
            if key.starts_at <= datetime.now(timezone.utc)
        ]
        self.assertEqual(started[-1].public_key_pem, body)


if __name__ == "__main__":
    unittest.main()
