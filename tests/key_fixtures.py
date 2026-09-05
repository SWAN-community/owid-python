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
"""A genuine identifier and the published signing key schedule of the creator
that issued it, shared with the other OWID ports so that every port is checked
against the same real data.

The identifier is a 51Did creator context identifier the 51Degrees cloud
issued on 4 September 2026 for the creator domain 51d.es. The schedule is the
thirty weekly keys the public key end point served for that domain from
11 May to 30 November 2026. Both are public and carry no secret.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, NamedTuple

from owid import Owid, ParseStatus
from owid.public_key_schedule import DatedPublicKey, PublicKeySchedule

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

#: The date the identifier carries, in whole minutes since 2020-01-01, which
#: is 2026-09-04T00:00:00Z because the cloud dates an identifier to the day,
#: and is the value a fetch names.
IDENTIFIER_MINUTES = 3_510_720

#: The creator domain the identifier carries.
IDENTIFIER_DOMAIN = "51d.es"

#: The start of the key that signed the identifier, being the week that was
#: running on 4 September 2026.
WEEK_OF_THE_IDENTIFIER = datetime(2026, 8, 31, tzinfo=timezone.utc)


class ScheduledKey(NamedTuple):
    """One record of the published schedule, being the moment the key came
    into force, the moment the key material was generated, and the PEM."""

    starts_at: datetime
    created: datetime
    pem: str


def identifier() -> Owid:
    """The genuine identifier, read from the fixture."""
    value = _records("identifier.txt")
    assert len(value) == 1, "the fixture holds one identifier"
    result = Owid.parse(value[0])
    assert result.status is ParseStatus.PARSED, result.status
    assert result.owid is not None
    return result.owid


def scheduled_keys() -> List[ScheduledKey]:
    """Every record of the published schedule, in the order published."""
    keys = []
    for record in _records("public-key-schedule.txt"):
        fields = record.split(" ")
        assert len(fields) == 3, "a record is a start, a generation moment and a key"
        keys.append(
            ScheduledKey(
                _instant(fields[0]), _instant(fields[1]), pem(fields[2])
            )
        )
    return keys


def schedule() -> PublicKeySchedule:
    """The published schedule as the package holds it, with only the start of
    each key, because the generation moment plays no part in the choice."""
    return PublicKeySchedule(
        DatedPublicKey(key.starts_at, key.pem) for key in scheduled_keys()
    )


def pem(body: str) -> str:
    """Wraps the base 64 body of a Subject Public Key Info into the PEM form
    the public key end point serves."""
    lines = ["-----BEGIN PUBLIC KEY-----"]
    for start in range(0, len(body), 64):
        lines.append(body[start : start + 64])
    lines.append("-----END PUBLIC KEY-----")
    return "\n".join(lines) + "\n"


def _instant(value: str) -> datetime:
    """Reads a moment written the way the schedule writes them, for example
    2026-08-31T00:00:00Z."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _records(name: str) -> List[str]:
    """Reads a fixture, dropping the comment lines and the blank ones."""
    path = os.path.join(_DATA, name)
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
