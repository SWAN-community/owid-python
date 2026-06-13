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
"""Shared test fixtures.

The canonical wire vectors prove the reader and writer match the wire format.
The cross language signed fixtures prove real signatures produced by other
implementations verify, which is the strongest check that the crypto data and
signature handling are correct.
"""

from __future__ import annotations

import base64

# Canonical wire format vectors. Version 2, unpadded base 64.

CREATOR_VECTOR = (
    "AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQAAAA27"
    "eOAAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6uiN3rz1rAxJHj2"
    "rNKvV/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFSZHXJ1mO/U/bkHhGCSG"
    "/BStI/fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4hOXBIb/auLhy7mftegVZqvbep"
    "qw8nVf8ByI94w9I/XLNwf5kAFpFeSeo8kwRhXqUyUuWT7FYIi4DnOP9zyTaAY8xgMh77oU"
    "jL/QJjbXAuc3dhbi1kZW1vLnVrACskCgACAAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6p"
    "f2JyFim3zg6lLivRDqpCD921elvxdn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8J"
    "i4m4ScYkpQvD3KjsLbqI5c7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jek"
    "MEA"
)

SUPPLIER_VECTOR = (
    "AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrAjf8y29"
    "Ru0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w"
)

BAD_VECTOR = (
    "AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2WXNTGSi"
    "ogw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk"
)

# The expected UTF-8 payload used by all the utf8 fixtures.
UTF8_PAYLOAD = "Zürich ❤ OWID £€"

# Cross language signed fixtures. Each entry holds the SPKI public key and the
# four signed OWIDs to verify.

GO = {
    "domain": "go.swan-demo.uk",
    "spki": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n"
        "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "simple": (
        "A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMDfcAkRk8U"
        "4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4ojeSzNX56Qn"
    ),
    "utf8": (
        "A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPigqzxY+4Q"
        "gUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QCWZfkcKCKNGSM8hYZE"
        "fYjJtViG+tA+"
    ),
    "chain_party": (
        "A2dvLnN3YW4tZGVtby51awA/vTMABQAAAHBhcnR5l7NyNmFw2lxqc4DKJWoq0UVd5ujG"
        "V/+fvVxqYTRlwCFxaSuwvnhLQQHjX5spxWb4O08IeuiuGCat1WFB/Wqlyw=="
    ),
    "chain_root": (
        "A2dvLnN3YW4tZGVtby51awA/vTMABAAAAHJvb3R/bEqzG8gAy9yTF1UMEtOlYXBBmn3a"
        "20jxXq5NmxIC8iuZvduOXKMf+K8VoAapkWwfpoDKQHS09IhljasZqC0k"
    ),
}

DOTNET = {
    "domain": "dotnet.swan-demo.uk",
    "spki": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ\n"
        "A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "simple": (
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU2FJbLjof"
        "8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcwEetjN1z9UWzyh0w=="
    ),
    "utf8": (
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lEIMKj4oKs"
        "VuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg2rKMybcsAxMmnrDtF"
        "2xsk1cJvHgoIYpSJJQ=="
    ),
    "chain_party": (
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAUAAABwYXJ0eXtD6H4R7GbvRyFU+bCKgjMA"
        "ZFFm8KHln80XPwQOBb/Ub9EZfE4Ml3ueRkKX51+MD98RFgTSmjbqrAnzFkLlilA="
    ),
    "chain_root": (
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAQAAAByb290fErj2LccPYCduWUW8vY2aBjr"
        "ecDfnTpVpv3+SESJMFW5pcuPKEQik2rC0fWEoB5Vr6e0k5inrhUGiF2c2Y2YDw=="
    ),
}

RUST = {
    "domain": "rust.swan-demo.uk",
    "spki": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki\n"
        "aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "simple": (
        "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyfDxbykxur"
        "SxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/ErjSOMMQo5CI="
    ),
    "utf8": (
        "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDCo+KCrDHe"
        "nDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZUWDIobtJHE5n9a81p"
        "Tsn/Kvi74Azzx4s="
    ),
    "chain_party": (
        "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAFAAAAcGFydHmJ7qaxWgIZUHmGOQb2xC+RuZNw"
        "rkMmo1SA9/MfI4SoEpRYdnteXAKUQXxTOK3lmQ3Qz3UwBB6gBb3Q8hi1Wx0R"
    ),
    "chain_root": (
        "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAEAAAAcm9vdFd0+QLaBLGPyBrQO+VNunBIQZzw"
        "8/lhEiDOKTx36Dc93A0n0fzPDMt/C+BdWMqhnL4nVvyurb3IHR7DUAmgmO0="
    ),
}

ALL_LANGUAGES = [("go", GO), ("dotnet", DOTNET), ("rust", RUST)]


def flip_last_byte(value: str) -> str:
    """Decodes the base 64 OWID, flips the last byte (a signature byte), and
    re-encodes. Used to assert that a tampered signature fails to verify."""
    raw = bytearray(decode_unpadded(value))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def decode_unpadded(value: str) -> bytes:
    """Decodes a standard alphabet base 64 string that may be unpadded."""
    remainder = len(value) % 4
    if remainder == 2:
        value += "=="
    elif remainder == 3:
        value += "="
    return base64.b64decode(value)
