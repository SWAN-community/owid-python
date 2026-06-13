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
"""The creator binds a domain to a signing key so that new OWIDs can be
produced.

A creator sets the domain that hosts the well known end points and uses the
crypto instance holding the signing key to produce the signature.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence

from .crypto import Crypto
from .error import OwidError
from .io import SIGNATURE_LENGTH
from .owid import Owid
from .version import DEFAULT_VERSION


class Configuration:
    """Configuration for a Creator where the domain and keys come from
    settings rather than code."""

    def __init__(
        self,
        domain: str = "",
        private_key: str = "",
        public_key: Optional[str] = None,
    ) -> None:
        #: Domain associated with the creator.
        self.domain = domain
        #: The private key in PKCS#8 or SEC1 PEM form used to sign OWIDs.
        self.private_key = private_key
        #: The public key in SPKI PEM form. Optional because it can be derived
        #: from the private key.
        self.public_key = public_key


class Creator:
    """Needed to create new OWIDs.

    A creator binds the domain that hosts the well known end points to the
    crypto instance holding the signing key.
    """

    def __init__(self, domain: str, crypto: Crypto) -> None:
        """Creates a new creator for the domain using the crypto instance for
        signing.

        Raises OwidError if the domain is empty or whitespace, or the crypto
        instance can not sign.
        """
        if domain is None or domain.strip() == "":
            raise OwidError("domain '{0}' is not valid".format(domain))
        if not crypto.can_sign():
            raise OwidError("instance of Crypto cannot be used to generate a signature")
        self._domain = domain
        self._crypto = crypto

    @classmethod
    def from_configuration(cls, configuration: Configuration) -> "Creator":
        """Creates a new creator from configuration containing the domain and
        the private key PEM.

        Raises OwidError if the domain is empty or whitespace, or the private
        key PEM is not valid.
        """
        crypto = Crypto.new_sign_only(configuration.private_key)
        return cls(configuration.domain, crypto)

    @property
    def domain(self) -> str:
        """Domain associated with the OWID creator."""
        return self._domain

    @property
    def crypto(self) -> Crypto:
        """Used to sign OWIDs from this creator."""
        return self._crypto

    def sign(self, owid: Owid) -> None:
        """Signs the OWID provided, setting the domain to the creator domain,
        the date to the current time, and the version to the current version,
        then signing it."""
        self.sign_with_others(owid, [])

    def sign_with_others(self, owid: Owid, others: Sequence[Owid]) -> None:
        """Signs the OWID provided together with the other OWIDs provided.

        The same others, in the same order, must be passed when verifying.
        """
        owid.version = DEFAULT_VERSION
        owid.domain = self._domain
        # Truncate to whole minutes so the in-memory date matches the value
        # written to the wire format. This keeps a signed OWID equal to a copy
        # decoded from its bytes, and ensures signing and verification operate
        # on the same minute precise value.
        owid.date = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        data = owid.data_for_crypto(others)
        owid.signature = self._crypto.sign_byte_array(data)
        if len(owid.signature) != SIGNATURE_LENGTH:
            raise OwidError(
                "signature length '{0}' not compatible with '{1}' OWID "
                "signature length".format(len(owid.signature), SIGNATURE_LENGTH)
            )

    def sign_string(self, value: str) -> Owid:
        """Creates a new signed OWID for the creator containing the string as
        the payload."""
        return self.sign_bytes(value.encode("utf-8"))

    def sign_bytes(self, value: bytes) -> Owid:
        """Creates a new signed OWID for the creator containing the bytes as
        the payload."""
        owid = Owid(payload=value)
        self.sign(owid)
        return owid
