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
"""

from __future__ import annotations

import json

from .creator import Creator
from .error import OwidError
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
