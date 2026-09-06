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
"""Helpers for hosting the well known end points required by the OWID
specification.

These are framework agnostic. They return the path and body so that any HTTP
server can serve them. The mandatory end points are the creator end point at
/owid/api/v{version}/creator returning JSON with the domain, common name, and
public key of the creator, and the public key end point at
/owid/api/v{version}/public-key returning the public key as PEM text. The
format query parameter must be spki or pkcs.

A creator that rotates its signing key answers the optional date parameter of
the public key end point with public_key_response_at, which chooses from the
published schedule the way the specification requires.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union

from . import io
from .creator import Creator
from .error import OwidError
from .public_key_schedule import PublicKeySchedule
from .version import Version


def creator_path(version: Version) -> str:
    """Returns the path of the creator end point for the version provided. For
    example /owid/api/v3/creator."""
    return "/owid/api/v{0}/creator".format(version.as_byte())


def public_key_path(version: Version) -> str:
    """Returns the path of the public key end point for the version provided.
    For example /owid/api/v3/public-key."""
    return "/owid/api/v{0}/public-key".format(version.as_byte())


def creator_response(creator: Creator, name: str, contract_url: str = "") -> str:
    """Returns the JSON body for the creator end point.

    The body contains the domain, name, public key in SPKI form, and the
    contract URL.
    """
    body = {
        "domain": creator.domain,
        "name": name,
        "publicKeySPKI": creator.crypto.subject_public_key_info(),
        "contractURL": contract_url,
    }
    return json.dumps(body)


def public_key_response(creator: Creator, format: str) -> str:
    """Returns the text body for the public key end point.

    The specification allows the key to be requested in SPKI or PKCS form.
    This implementation returns the SPKI PEM for both values because the
    importers in every implementation accept it.

    Raises OwidError if the format is not spki or pkcs.
    """
    if format in ("spki", "pkcs"):
        return creator.crypto.subject_public_key_info()
    raise OwidError(
        "format parameter 'spki' or 'pkcs' must be provided, "
        "received '{0}'".format(format)
    )


def public_key_response_at(
    schedule: PublicKeySchedule,
    format: str,
    date: Union[str, int, None],
    now: Optional[datetime] = None,
) -> Tuple[int, str]:
    """Returns the status code and text body for the public key end point of
    a creator that rotates its key, chosen from the schedule the way the
    specification requires.

    The date parameter is the OWID's own date, counted in whole minutes since
    2020-01-01, and the key served is the one in force then, being the latest
    key whose start is at or before it. A request without a date, or with a
    date later than the moment of the request, is served the key in force at
    that moment, so a caller cannot ask for a key whose period has not begun.
    The answer is 200 with the PEM, 404 with an empty body where no key is in
    force at the date, and 400 with an empty body where the date is not a
    count of minutes. The moment of the request is now, and a test may supply
    it.

    Raises OwidError if the format is not spki or pkcs.
    """
    if format not in ("spki", "pkcs"):
        raise OwidError(
            "format parameter 'spki' or 'pkcs' must be provided, "
            "received '{0}'".format(format)
        )
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        # Read as UTC, the only zone the wire format knows, so this agrees
        # with the schedule rather than refusing to compare.
        moment = moment.replace(tzinfo=timezone.utc)
    asked = moment
    if date is not None and date != "":
        minutes = _minutes(date)
        if minutes is None:
            return 400, ""
        if minutes <= io.MAXIMUM_MINUTES:
            asked = io.BASE_DATE + timedelta(minutes=minutes)
        if asked > moment:
            asked = moment
    key = schedule.key_in_force(asked)
    if key is None:
        return 404, ""
    return 200, key.public_key_pem


def _minutes(date: Union[str, int]) -> Optional[int]:
    """The date parameter as a count of minutes, or None where it is not an
    unsigned 32 bit integer, written in decimal digits when it is text."""
    if isinstance(date, bool):
        return None
    if isinstance(date, int):
        value = date
    elif isinstance(date, str) and date.isascii() and date.isdigit():
        value = int(date)
    else:
        return None
    if value < 0 or value > 0xFFFFFFFF:
        return None
    return value
