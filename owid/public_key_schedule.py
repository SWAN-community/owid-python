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
"""The signing public keys a creator has published, held so that the key
which was in force at any date can be found.

Creators rotate weekly, so the key that is current when an identifier is
checked is not the key that signed the identifier unless the check happens in
the same week. Verifying anything older than a few days means choosing the
right key out of the schedule, and this module holds the rule for that choice
in one place so every caller makes the same choice.

The rule is the one the cloud itself applies, being the latest key whose
start is at or before the date asked about. Keys are generated in batches,
often many weeks ahead of the weeks the keys cover, so the moment key
material was generated says nothing about which key signed anything and is
not held here at all. Selecting on a generation moment picks a key that has
not started yet and reports a genuine identifier as not matching, which is
what the .NET port did before that port was fixed.

A date the schedule does not reach, being one earlier than the first start,
has no key. That answer is reported as SignatureStatus.KEY_UNAVAILABLE rather
than as a signature that does not match, because with no key the signature
was never examined.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence, Tuple

from .error import OwidError
from .owid import Owid
from .status import SignatureStatus


def _aware(moment: datetime) -> datetime:
    """A naive datetime is read as UTC, which is the only zone the wire format
    knows, so a caller who builds starts from calendar dates without naming a
    zone gets the comparison the dates were meant to have."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


class DatedPublicKey:
    """One signing public key together with the moment the key came into
    force. The key stays in force until the next key in the schedule starts.
    Both values are read only."""

    __slots__ = ("_starts_at", "_public_key_pem")

    def __init__(self, starts_at: datetime, public_key_pem: str) -> None:
        """Raises OwidError if the start is missing or the PEM is empty."""
        if starts_at is None:
            raise OwidError("the start of the key is missing")
        if not isinstance(starts_at, datetime):
            raise OwidError("the start of the key must be a datetime")
        if public_key_pem is None or not public_key_pem.strip():
            raise OwidError("public key PEM is empty")
        self._starts_at = _aware(starts_at)
        self._public_key_pem = public_key_pem

    @property
    def starts_at(self) -> datetime:
        """The moment from which this key signs, in UTC."""
        return self._starts_at

    @property
    def public_key_pem(self) -> str:
        """The public key in Subject Public Key Info PEM form, as the public
        key end point serves the key."""
        return self._public_key_pem

    def __repr__(self) -> str:
        return "DatedPublicKey(starts_at={0!r})".format(
            self._starts_at.isoformat()
        )


class PublicKeySchedule:
    """The keys a creator has published, oldest start first, and the rule
    that picks the key in force at a date."""

    __slots__ = ("_keys",)

    def __init__(self, keys: Iterable[DatedPublicKey]) -> None:
        """Holds the keys provided, which may arrive in any order.

        Where two keys share a start, the one supplied first wins, which is
        how the 51Degrees cloud and the .NET port settle it. A creator does
        not publish two keys for one start, so the case is settled rather
        than left to chance.

        Raises OwidError if the collection is missing or holds a missing key.
        """
        if keys is None:
            raise OwidError("the collection of keys is missing")
        ordered = list(keys)
        for key in ordered:
            if key is None or not isinstance(key, DatedPublicKey):
                raise OwidError("a key in the schedule is missing")
        # The sort is stable, so keys sharing a start keep the order they
        # were supplied in and the first supplied stays first.
        ordered.sort(key=lambda key: key.starts_at)
        self._keys: Tuple[DatedPublicKey, ...] = tuple(ordered)

    @property
    def keys(self) -> Tuple[DatedPublicKey, ...]:
        """The keys held, oldest start first. The tuple cannot be changed."""
        return self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def key_in_force(self, date: Optional[datetime]) -> Optional[DatedPublicKey]:
        """Returns the key that was in force at the date given, being the
        latest key whose start is at or before that date, or None where the
        schedule begins after the date. A naive datetime is read as UTC."""
        if date is None:
            return None
        moment = _aware(date)
        index = len(self._keys) - 1
        while index >= 0:
            key = self._keys[index]
            if key.starts_at <= moment:
                # Keys sharing a start sit in the order supplied, and the
                # first supplied is the answer.
                while (
                    index > 0
                    and self._keys[index - 1].starts_at == key.starts_at
                ):
                    index -= 1
                    key = self._keys[index]
                return key
            index -= 1
        return None

    def last(self) -> Optional[DatedPublicKey]:
        """Returns the key with the latest start, or None where the schedule
        holds no keys.

        This is not the key in force now. A creator publishes its schedule
        ahead of time, so the last key by start is usually one whose period
        has not begun and which has signed nothing yet. The key in force now
        is current(). Serving the last key where the current one was meant is
        the same fault as selecting by the generation moment, being a key
        from a period that has not started, and it is the fault the .NET port
        carried in its answer to a request that named no date.
        """
        if not self._keys:
            return None
        return self._keys[-1]

    def current(self) -> Optional[DatedPublicKey]:
        """Returns the key in force now, being the latest key whose start is
        at or before the current moment, or None where no key has started.
        This is what a creator serves for a request that names no date."""
        return self.key_in_force(datetime.now(timezone.utc))

    def key_for(self, owid: Optional[Owid]) -> Optional[DatedPublicKey]:
        """Returns the key that signed the OWID, being the key in force at the
        date the OWID carries, or None where the schedule does not reach back
        to that date."""
        if owid is None:
            return None
        return self.key_in_force(owid.date)

    def signature_status(
        self, owid: Optional[Owid], others: Optional[Sequence[Owid]] = None
    ) -> SignatureStatus:
        """Says whether the signature on the OWID is genuine, using the key
        that was in force when the OWID was signed. The answer is
        SignatureStatus.KEY_UNAVAILABLE where the schedule holds no key for
        the date, because the signature was never examined."""
        if owid is None:
            return SignatureStatus.KEY_UNAVAILABLE
        key = self.key_for(owid)
        if key is None:
            return SignatureStatus.KEY_UNAVAILABLE
        return owid.signature_status(key.public_key_pem, others)

    def verify(
        self, owid: Optional[Owid], others: Optional[Sequence[Owid]] = None
    ) -> bool:
        """Returns True only when the signature verifies under the key in
        force when the OWID was signed."""
        status = self.signature_status(owid, others)
        return status is SignatureStatus.SIGNATURE_VALID
