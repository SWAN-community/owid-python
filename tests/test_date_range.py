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
"""Dates the wire format can carry but this runtime cannot.

Versions 2 and 3 carry the date as an unsigned 32 bit count of minutes since
2020-01-01, which runs to 4,294,967,295 and lands on 15 February 10186.
datetime.max is the last moment of the year 9999, so the last count the
runtime can hold is 4,197,074,399 and the next cannot be represented. Before
the guard the addition raised OverflowError on that count, so a read that
promises never to raise raised on caller data. The same bytes read fine in
Java, PHP and JavaScript, so the finding is the runtime's limit and not a
fault in the data, which is what IMPLEMENTATION_CAPACITY_EXCEEDED means. Both
reading contracts are checked.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from owid import Creator, Crypto, Owid
from owid.io import BASE_DATE, MAXIMUM_MINUTES, SIGNATURE_LENGTH
from owid.status import ParseStatus

DOMAIN = "example.com"

#: The last count a datetime can hold, which is 9999-12-31 23:59. Written as
#: a number here, and derived from datetime.max in the library, so the two
#: are checked against each other below.
LAST_INSIDE = 4_197_074_399

#: The first count the runtime cannot hold, one minute into the year 10000.
FIRST_BEYOND = LAST_INSIDE + 1


def _with_minutes(minutes: int) -> bytes:
    """A signed version 3 envelope with its date bytes replaced. The date
    follows the version byte and the terminated domain, and is four little
    endian bytes. The signature no longer matches, which does not matter,
    because parsing and verifying are separate questions."""
    raw = bytearray(
        Creator(DOMAIN, Crypto.new()).create(b"\x01\x02\x03").as_byte_array())
    at = 1 + len(DOMAIN) + 1
    raw[at:at + 4] = minutes.to_bytes(4, "little")
    return bytes(raw)


def _version1_with_hours(hours: int) -> bytes:
    """A version 1 envelope built by hand, because no creator writes that
    version any more. Two big endian bytes of hours, then the payload count,
    payload and a signature of the right length."""
    return (
        bytes([1])
        + DOMAIN.encode("ascii") + b"\x00"
        + hours.to_bytes(2, "big")
        + (1).to_bytes(4, "little") + b"\x07"
        + bytes(SIGNATURE_LENGTH)
    )


class DateRangeTests(unittest.TestCase):

    def _refused_on_both_contracts(self, raw: bytes) -> None:
        for read in (Owid.parse_bytes, Owid.parse_prefix):
            with self.subTest(read=read.__name__):
                result = read(raw)
                self.assertFalse(result.ok)
                self.assertIsNone(result.owid, "no value on failure")
                self.assertEqual(
                    ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED,
                    result.status)
                self.assertEqual(0, result.consumed, "nothing is consumed")

    def _parsed_on_both_contracts(self, raw: bytes) -> datetime:
        whole = Owid.parse_bytes(raw)
        self.assertTrue(whole.ok, whole.status)
        framed = Owid.parse_prefix(raw)
        self.assertTrue(framed.ok, framed.status)
        self.assertEqual(whole.owid.date, framed.owid.date)
        self.assertEqual(len(raw), framed.consumed)
        return whole.owid.date

    def test_maximum_count_is_capacity_exceeded(self) -> None:
        """The largest count the wire can carry."""
        self._refused_on_both_contracts(_with_minutes(0xFFFFFFFF))

    def test_first_count_beyond_the_runtime_is_capacity_exceeded(self) -> None:
        """One minute into the year 10000."""
        self._refused_on_both_contracts(_with_minutes(FIRST_BEYOND))

    def test_last_count_inside_the_runtime_parses(self) -> None:
        date = self._parsed_on_both_contracts(_with_minutes(LAST_INSIDE))
        self.assertEqual(
            datetime(9999, 12, 31, 23, 59, tzinfo=timezone.utc), date)

    def test_the_boundary_is_the_last_whole_minute_before_max(self) -> None:
        """Pins the boundary to the runtime rather than to a number someone
        worked out once. The library derives it and this test states it, and
        the arithmetic the guard prevents is shown to raise."""
        self.assertEqual(LAST_INSIDE, MAXIMUM_MINUTES)
        BASE_DATE + timedelta(minutes=LAST_INSIDE)
        with self.assertRaises(OverflowError):
            BASE_DATE + timedelta(minutes=FIRST_BEYOND)

    def test_version1_maximum_hours_parses(self) -> None:
        """Version 1 counts hours in two bytes, so its largest count is 65,535
        hours, which is 23 June 2027 and under eight years from the base
        date. The arithmetic cannot leave the runtime's range, so the reader
        has no guard for it and this shows none is needed."""
        date = self._parsed_on_both_contracts(_version1_with_hours(0xFFFF))
        self.assertEqual(
            datetime(2027, 6, 23, 15, 0, tzinfo=timezone.utc), date)


if __name__ == "__main__":
    unittest.main()
