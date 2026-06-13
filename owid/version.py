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
"""The byte version of an OWID, always the first byte of the serialized form.

Versions 1 and 2 were deprecated during development of the specification
because they used an insecure algorithm or an insufficiently precise time
indicator. They remain readable for compatibility with data created by earlier
implementations.
"""

from __future__ import annotations

from enum import IntEnum

from .error import OwidError


class Version(IntEnum):
    """The byte version of an OWID."""

    #: Marker used to indicate an optional OWID that is not present.
    EMPTY = 0
    #: Deprecated. Stored the date as a two byte big endian count of hours
    #: elapsed since the base date.
    VERSION1 = 1
    #: Deprecated. Stored the date as a four byte little endian count of
    #: minutes elapsed since the base date.
    VERSION2 = 2
    #: The current version. The wire format is identical to version 2.
    VERSION3 = 3

    def as_byte(self) -> int:
        """Returns the version as the byte written to the serialized form."""
        return int(self)

    @classmethod
    def from_byte(cls, value: int) -> "Version":
        """Returns the version for the byte value.

        Raises OwidError if the byte is not a known version.
        """
        try:
            return cls(value)
        except ValueError:
            raise OwidError("OWID version '{0}' not supported".format(value))


#: The version used for new OWIDs.
DEFAULT_VERSION = Version.VERSION3
