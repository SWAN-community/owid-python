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
"""The error type raised across the package.

A single exception type carries a human readable message. It is raised where
the fault lies in the calling code or in the local key material, being a
domain or payload that cannot be written, a key that cannot be imported or
exported, an attempt to construct an OWID directly, and a version the writer
does not know.

Reading data that came from outside does not raise. Bytes that are not an OWID
are an ordinary outcome, so the parse surfaces answer with a ParseResult
carrying a ParseStatus, and a signature that cannot be judged is reported as a
SignatureStatus rather than as an exception.
"""

from __future__ import annotations


class OwidError(Exception):
    """Raised when an OWID can not be created, written, signed, or verified,
    and never for external data that turns out not to be an OWID."""

    pass
