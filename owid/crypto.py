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
"""All the public and support methods associated with signing and
verification. Nothing to do with the web or HTTP.

OWID uses ECDSA with the NIST P-256 curve (also known as secp256r1 or
prime256v1) and the SHA-256 hash, as required by the specification. The
signature is the 64 byte concatenation of the big endian r and s values.

The cryptography library produces and consumes ASN.1 DER signatures, so the
signing and verification methods convert between DER and the raw 64 byte form
that OWID stores.
"""

from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .error import OwidError
from .io import SIGNATURE_LENGTH


class Crypto:
    """Holds the public and private keys used to sign and verify OWIDs.

    An instance can hold both keys, or only one of them when created with
    new_sign_only or new_verify_only.
    """

    def __init__(
        self,
        signing_key: Optional[EllipticCurvePrivateKey] = None,
        verifying_key: Optional[EllipticCurvePublicKey] = None,
    ) -> None:
        self._signing_key = signing_key
        self._verifying_key = verifying_key

    @classmethod
    def new(cls) -> "Crypto":
        """Creates a new instance and generates a public and private key pair
        used to sign and verify OWIDs."""
        signing_key = ec.generate_private_key(ec.SECP256R1())
        return cls(signing_key, signing_key.public_key())

    @classmethod
    def new_sign_only(cls, private_pem: str) -> "Crypto":
        """Creates a new instance for signing OWIDs from the private key PEM
        provided.

        Both PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") PEM forms are
        accepted, matching the forms produced by the other language
        implementations. The verifying key is derived from the private key so
        the instance can also verify.

        Raises OwidError if the PEM is empty or not a valid P-256 private key.
        """
        if private_pem is None or private_pem.strip() == "":
            raise OwidError("private key PEM is empty")
        try:
            signing_key = serialization.load_pem_private_key(
                private_pem.encode("utf-8"), password=None
            )
        except Exception as exc:
            raise OwidError("key operation failed because {0}".format(exc))
        if not isinstance(signing_key, EllipticCurvePrivateKey):
            raise OwidError("key operation failed because the key is not an EC key")
        return cls(signing_key, signing_key.public_key())

    @classmethod
    def new_verify_only(cls, public_pem: str) -> "Crypto":
        """Creates a new instance for verifying OWIDs from the public key PEM
        provided in Subject Public Key Info (SPKI) form.

        Raises OwidError if the PEM is empty or not a valid P-256 public key.
        """
        if public_pem is None or public_pem.strip() == "":
            raise OwidError("public key PEM is empty")
        try:
            verifying_key = serialization.load_pem_public_key(
                public_pem.encode("utf-8")
            )
        except Exception as exc:
            raise OwidError("key operation failed because {0}".format(exc))
        if not isinstance(verifying_key, EllipticCurvePublicKey):
            raise OwidError("key operation failed because the key is not an EC key")
        return cls(None, verifying_key)

    def sign_byte_array(self, data: bytes) -> bytes:
        """Signs the byte array with the private key and returns the 64 byte
        signature.

        Raises OwidError if the instance was created for verification only.
        """
        if self._signing_key is None:
            raise OwidError("instance of Crypto cannot be used to generate a signature")
        der = self._signing_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if len(signature) != SIGNATURE_LENGTH:
            raise OwidError(
                "signature length '{0}' not compatible with '{1}' OWID "
                "signature length".format(len(signature), SIGNATURE_LENGTH)
            )
        return signature

    def verify_byte_array(self, data: bytes, signature: bytes) -> bool:
        """Returns True if the signature is valid for the data.

        A signature of the wrong length raises OwidError. A signature of the
        right length that does not match the data returns False rather than
        raising.

        Raises OwidError if the instance was created without a public key.
        """
        if self._verifying_key is None:
            raise OwidError("instance of Crypto cannot be used to verify a signature")
        if len(signature) != SIGNATURE_LENGTH:
            raise OwidError(
                "signature length '{0}' not compatible with '{1}' OWID "
                "signature length".format(len(signature), SIGNATURE_LENGTH)
            )
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        # Values of r or s that are zero can never form a valid signature.
        if r == 0 or s == 0:
            return False
        der = encode_dss_signature(r, s)
        try:
            self._verifying_key.verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def subject_public_key_info(self) -> str:
        """Returns the public key in Subject Public Key Info (SPKI) PEM form
        for use with the well known end points or other implementations.

        Raises OwidError if the instance has no public key.
        """
        if self._verifying_key is None:
            raise OwidError("instance of Crypto cannot be used to export a public key")
        return self._verifying_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def public_key_pem(self) -> str:
        """Returns the public key in PEM form. Alias of
        subject_public_key_info."""
        return self.subject_public_key_info()

    def private_key_pem(self) -> str:
        """Returns the private key in PKCS#8 PEM form.

        Raises OwidError if the instance has no private key.
        """
        if self._signing_key is None:
            raise OwidError("instance of Crypto cannot be used to export a private key")
        return self._signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

    def can_sign(self) -> bool:
        """True if the instance can be used to sign OWIDs."""
        return self._signing_key is not None

    def can_verify(self) -> bool:
        """True if the instance can be used to verify OWIDs."""
        return self._verifying_key is not None
