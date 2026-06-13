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
"""Unit tests for the low level IO helpers."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from owid import OwidError, Version
from owid import io


class IoTests(unittest.TestCase):
    def test_base_date(self) -> None:
        self.assertEqual(
            io.BASE_DATE, datetime(2020, 1, 1, tzinfo=timezone.utc)
        )
        # The base date is unix timestamp 1577836800.
        self.assertEqual(int(io.BASE_DATE.timestamp()), 1577836800)

    def test_date_round_trip_version_2(self) -> None:
        date = datetime.now(timezone.utc)
        buffer = bytearray()
        io.write_date(buffer, date, Version.VERSION2)
        self.assertEqual(len(buffer), 4)
        reader = io.Reader(bytes(buffer))
        result = reader.read_date(Version.VERSION2)
        # The minute count must match because the encoding is minute precise.
        self.assertEqual(
            int((result - io.BASE_DATE).total_seconds() // 60),
            int((date - io.BASE_DATE).total_seconds() // 60),
        )

    def test_date_round_trip_version_1(self) -> None:
        date = io.BASE_DATE + timedelta(hours=12345)
        buffer = bytearray()
        io.write_date(buffer, date, Version.VERSION1)
        self.assertEqual(len(buffer), 2, "version 1 uses two bytes")
        reader = io.Reader(bytes(buffer))
        result = reader.read_date(Version.VERSION1)
        self.assertEqual(result, date, "version 1 keeps hour granularity")

    def test_version_1_big_endian(self) -> None:
        # 12345 hours is 0x3039 stored big endian as 0x30 0x39.
        date = io.BASE_DATE + timedelta(hours=0x3039)
        buffer = bytearray()
        io.write_date(buffer, date, Version.VERSION1)
        self.assertEqual(bytes(buffer), bytes([0x30, 0x39]))

    def test_date_before_base_raises(self) -> None:
        date = io.BASE_DATE - timedelta(minutes=1)
        buffer = bytearray()
        with self.assertRaises(OwidError):
            io.write_date(buffer, date, Version.VERSION3)

    def test_string_round_trip(self) -> None:
        buffer = bytearray()
        io.write_string(buffer, "example.com")
        self.assertEqual(buffer[-1], 0, "string is null terminated")
        reader = io.Reader(bytes(buffer))
        self.assertEqual(reader.read_string(), "example.com")

    def test_string_with_null_raises(self) -> None:
        buffer = bytearray()
        with self.assertRaises(OwidError):
            io.write_string(buffer, "bad\x00domain")

    def test_u32_little_endian(self) -> None:
        buffer = bytearray()
        io.write_u32(buffer, 0x0A242B01)
        self.assertEqual(bytes(buffer), bytes([0x01, 0x2B, 0x24, 0x0A]))
        reader = io.Reader(bytes(buffer))
        self.assertEqual(reader.read_u32(), 0x0A242B01)

    def test_byte_array_round_trip(self) -> None:
        buffer = bytearray()
        io.write_byte_array(buffer, b"payload")
        reader = io.Reader(bytes(buffer))
        self.assertEqual(reader.read_byte_array(), b"payload")

    def test_signature_length_enforced(self) -> None:
        buffer = bytearray()
        with self.assertRaises(OwidError):
            io.write_signature(buffer, bytes(63))

    def test_signature_round_trip(self) -> None:
        signature = bytes(range(64))
        buffer = bytearray()
        io.write_signature(buffer, signature)
        reader = io.Reader(bytes(buffer))
        self.assertEqual(reader.read_signature(), signature)

    def test_read_past_end_raises(self) -> None:
        reader = io.Reader(b"\x01")
        reader.read_byte()
        with self.assertRaises(OwidError):
            reader.read_byte()

    def test_read_string_without_terminator_raises(self) -> None:
        reader = io.Reader(b"no terminator")
        with self.assertRaises(OwidError):
            reader.read_string()


if __name__ == "__main__":
    unittest.main()
