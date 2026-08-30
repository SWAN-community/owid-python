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

"""Why reading an OWID succeeded or failed."""

from enum import Enum


class ParseStatus(Enum):
    """Why a parse of external data succeeded or failed.

    Malformed data arriving from outside is expected, not exceptional. An
    OWID is read from whatever a caller was given, which on a public endpoint
    means anything at all, so every one of these outcomes is a normal result
    rather than a fault. Raising for them costs the construction and unwinding
    of an exception per bad input, which is a cost whoever is sending the data
    chooses the size of.

    These names are the cross-language vocabulary. Each implementation spells
    its surface in its own idiom, but the set of facts reported is the same
    everywhere, so a failure means the same thing whichever language read the
    bytes.
    """

    #: The bytes form a structurally valid OWID. This says nothing about the
    #: signature, which is a separate question answered separately.
    PARSED = "Parsed"

    #: Nothing was supplied to parse.
    MISSING_INPUT = "MissingInput"

    #: The input was supplied in a form this surface cannot read.
    INVALID_INPUT_TYPE = "InvalidInputType"

    #: The string is not valid base 64, so there are no bytes to read.
    INVALID_BASE64 = "InvalidBase64"

    #: The first byte names a version this implementation does not know.
    UNSUPPORTED_VERSION = "UnsupportedVersion"

    #: The data stopped in the middle of a field. Distinct from
    #: BYTE_COUNT_MISMATCH, which is a declaration that disagrees with data
    #: that is all present.
    UNEXPECTED_END = "UnexpectedEnd"

    #: The creator domain is not terminated, or is longer than the published
    #: maximum.
    INVALID_DOMAIN_ENCODING = "InvalidDomainEncoding"

    #: The declared payload byte count disagrees with the bytes actually
    #: present. Checked before anything is sized by the declaration, so a
    #: sender cannot make a reader allocate by claiming a large payload it did
    #: not send.
    BYTE_COUNT_MISMATCH = "ByteCountMismatch"

    #: The envelope is structurally consistent but larger than this runtime
    #: can hold. Not a fault in the data, and deliberately distinct from the
    #: data being wrong, because the same bytes may be readable elsewhere.
    IMPLEMENTATION_CAPACITY_EXCEEDED = "ImplementationCapacityExceeded"

    #: Malformed in a way none of the above describes. A fallback for the
    #: genuinely unclassified, not a substitute for naming a failure that is
    #: already understood.
    MALFORMED_ENVELOPE = "MalformedEnvelope"


class SignatureStatus(Enum):
    """The outcome of asking whether an OWID's signature is genuine.

    Only two of these say anything about the signature itself. The rest say
    the question could not be answered, which is a different thing and must
    never be reported as a forgery. A key that cannot be fetched, a key that
    cannot be decoded, or a provider that fails leaves the signature unjudged,
    and a caller acting on "invalid" would reject good identifiers during an
    outage.

    On 30 August 2026 the key endpoints published PEM wrapped at 76
    characters, which a strict parser rejects, and every offline verification
    against them failed. The keys were fine and the identifiers were fine.
    Reported as INVALID_KEY that reads as the operational fault it was;
    reported as SIGNATURE_INVALID it would have read as an attack.
    """

    #: The signature is genuine for this data and this key.
    SIGNATURE_VALID = "SignatureValid"

    #: The signature is well formed and does not match. The only status that
    #: means the identifier should be distrusted.
    SIGNATURE_INVALID = "SignatureInvalid"

    #: A signature field of the wrong length reached a verification surface
    #: directly. Truncation in raw external input is a parse UNEXPECTED_END
    #: instead, because there the envelope never formed.
    INVALID_SIGNATURE_LENGTH = "InvalidSignatureLength"

    #: No key could be obtained, or none covers the identifier's date. The
    #: signature was never examined.
    KEY_UNAVAILABLE = "KeyUnavailable"

    #: Key material arrived but cannot be decoded, imported or used as the
    #: required type. The fault is in the key, not the identifier.
    INVALID_KEY = "InvalidKey"

    #: The work required exceeds what this runtime can hold.
    IMPLEMENTATION_CAPACITY_EXCEEDED = "ImplementationCapacityExceeded"

    #: The check could not be completed for a reason that is not the
    #: identifier's fault, such as a malformed key list or a cryptographic
    #: provider failing on valid inputs.
    VERIFICATION_ERROR = "VerificationError"
