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
"""Open Web Id (OWID).

Simple cryptographically auditable identifiers and processors.

Read the OWID project at https://github.com/SWAN-community/owid to learn more
about the concepts before looking into this implementation. This package
creates, signs, serializes, and verifies OWIDs.

An OWID is a compact binary structure signed with an ECDSA NIST P-256 key and
a SHA-256 digest. OWIDs chain together to form verifiable trees.
"""

from __future__ import annotations

from . import endpoints
from .creator import Configuration, Creator
from .crypto import Crypto
from .error import OwidError
from .io import SIGNATURE_LENGTH
from .owid import Owid
from .version import DEFAULT_VERSION, Version

__all__ = [
    "Configuration",
    "Creator",
    "Crypto",
    "OwidError",
    "Owid",
    "Version",
    "DEFAULT_VERSION",
    "SIGNATURE_LENGTH",
    "endpoints",
]

__version__ = "0.1.0"
