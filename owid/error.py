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
"""The error types raised across the package.

OwidError carries a human readable message. It is raised where
the fault lies in the calling code or in the local key material, being a
domain or payload that cannot be written, a key that cannot be imported or
exported, an attempt to construct an OWID directly, and a version the writer
does not know.

Reading data that came from outside does not raise. Bytes that are not an OWID
are an ordinary outcome, so the parse surfaces answer with a ParseResult
carrying a ParseStatus, and a signature that cannot be judged is reported as a
SignatureStatus rather than as an exception.

PublicKeyFetchError is the one subclass. It is raised by public_key_fetch
when the public key of another creator could not be obtained, and it carries
the status to report so that the caller never mistakes an outage for a
forgery.
"""

from __future__ import annotations

from .status import SignatureStatus


class OwidError(Exception):
    """Raised when an OWID can not be created, written, signed, or verified,
    and never for external data that turns out not to be an OWID."""

    pass


class PublicKeyFetchError(OwidError):
    """Raised by owid.public_key_fetch when the public key of a creator could
    not be obtained.

    Carries the status a caller should report for the identifier, which is
    never a signature that does not match because the signature was never
    examined, the domain the key was asked of, and the response code, which
    is 0 where no response arrived at all.
    """

    def __init__(
        self,
        message: str,
        status: SignatureStatus,
        domain: str,
        status_code: int = 0,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.domain = domain
        self.status_code = status_code
