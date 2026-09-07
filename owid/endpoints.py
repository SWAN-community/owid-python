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
/owid/api/v{version}/public-key returning the public key as a JSON object.
The format query parameter must be spki or pkcs.

The public key end point answers with a JSON object carrying the key as
publicKeySPKI together with validFrom and validTo, the UTC moments the key came
into force and the next key starts, so a client holds the key for the whole
span from one answer. A creator that rotates its signing key answers the
optional date parameter with public_key_response_at, which chooses from the
published schedule the way the specification requires. Every answer is checked
with validate_public_key_answer before it is returned, so a creator never sends
an answer a client would refuse.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Tuple, Union

from . import io
from .creator import Creator
from .crypto import Crypto
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
    """Returns the JSON body for the public key end point of a creator with
    one key and no schedule. The key is stated as publicKeySPKI and both
    validFrom and validTo are null, because the creator knows nothing about
    when the key started or will stop.

    The specification allows the key to be requested in SPKI or PKCS form.
    This implementation returns the SPKI PEM for both values because the
    importers in every implementation accept it.

    Raises OwidError if the format is not spki or pkcs, or the key cannot be
    read.
    """
    if format not in ("spki", "pkcs"):
        raise OwidError(
            "format parameter 'spki' or 'pkcs' must be provided, "
            "received '{0}'".format(format)
        )
    return public_key_answer(creator.crypto.subject_public_key_info(), None, None, None)


def public_key_answer(
    public_key_pem: str,
    valid_from: Optional[datetime],
    valid_to: Optional[datetime],
    asked: Optional[datetime],
) -> str:
    """Returns the JSON body of the public key end point for the key and the
    span it covers, checked with validate_public_key_answer first so that a
    creator never sends an answer it would itself refuse. The moment asked
    about, where known, is checked against the span as well.

    Raises OwidError if the answer would not be valid.
    """
    answer = {
        "publicKeySPKI": public_key_pem,
        "validFrom": _moment_text(valid_from),
        "validTo": _moment_text(valid_to),
    }
    validate_public_key_answer(answer, asked)
    return json.dumps(answer)


def validate_public_key_answer(
    answer: Mapping[str, Any], asked: Optional[datetime]
) -> Tuple[str, Optional[datetime], Optional[datetime]]:
    """Checks a public key answer the way both the creator that sends it and
    the client that reads it must, returning the key and the moments it is
    valid from and to.

    The key must be a public key this package can read, a key valid to a
    moment must be valid from an earlier one, and where the moment asked about
    is known the key must have come into force by then and, if it has an end,
    not have ended. A creator that fails this check has a fault in its
    schedule or its store, and answering with a server error shows it up
    rather than passing it on.

    Raises OwidError where the answer is not valid.
    """
    if not isinstance(answer, Mapping):
        raise OwidError("the public key answer is not a JSON object")
    pem = answer.get("publicKeySPKI")
    if not isinstance(pem, str) or not pem.strip():
        raise OwidError("the public key answer holds no key")
    try:
        Crypto.new_verify_only(pem)
    except OwidError as failed:
        raise OwidError(
            "the public key answer holds a key that cannot be read"
        ) from failed
    valid_from = _moment_of(answer.get("validFrom"), "validFrom")
    valid_to = _moment_of(answer.get("validTo"), "validTo")
    if valid_to is not None:
        if valid_from is None:
            raise OwidError(
                "the public key answer states when the key ends but not when it started"
            )
        if valid_to <= valid_from:
            raise OwidError(
                "the public key answer states a key that ends before it starts"
            )
    if asked is not None:
        moment = asked if asked.tzinfo is not None else asked.replace(tzinfo=timezone.utc)
        if valid_from is not None and valid_from > moment:
            raise OwidError(
                "the public key answer states a key that had not started at the "
                "moment asked about"
            )
        if valid_to is not None and valid_to <= moment:
            raise OwidError(
                "the public key answer states a key that had ended at the moment "
                "asked about"
            )
    return pem, valid_from, valid_to


def _moment_text(moment: Optional[datetime]) -> Optional[str]:
    """The moment as an RFC 3339 string in UTC, or None."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _moment_of(value: Any, field: str) -> Optional[datetime]:
    """The field's value as an aware UTC datetime, or None where it is null.
    Raises OwidError where it is anything else."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise OwidError("the public key answer's {0} is not a moment".format(field))
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as failed:
        raise OwidError(
            "the public key answer's {0} is not a moment".format(field)
        ) from failed
    if moment.tzinfo is None:
        raise OwidError(
            "the public key answer's {0} does not say it is UTC".format(field)
        )
    return moment.astimezone(timezone.utc)
def public_key_response_at(
    schedule: PublicKeySchedule,
    format: str,
    date: Union[str, int, None],
    now: Optional[datetime] = None,
) -> Tuple[int, str]:
    """Returns the status code and JSON body for the public key end point of
    a creator that rotates its key, chosen from the schedule the way the
    specification requires.

    The date parameter is the OWID's own date, counted in whole minutes since
    2020-01-01, and the key served is the one in force then, being the latest
    key whose start is at or before it. A request without a date, or with a
    date later than the moment of the request, is served the key in force at
    that moment, so a caller cannot ask for a key whose period has not begun.
    The answer is 200 with the JSON body from public_key_answer, stating the
    key and the moments it is valid from and to, 404 with an empty body where
    no key is in force at the date, and 400 with an empty body where the date
    is not a count of minutes. The moment of the request is now, and a test
    may supply it.

    Raises OwidError if the format is not spki or pkcs, or the answer would
    fail validate_public_key_answer, which is a fault in the schedule.
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
    return 200, public_key_answer(
        key.public_key_pem, key.starts_at, schedule.next_start_after(key), asked
    )


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
