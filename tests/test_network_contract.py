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
"""No read can cause a request. The one module that reaches the network is
public_key_fetch, which a caller reaches only by importing it, and nothing
else in the package imports it. The source is scanned for the ways Python
reaches the network, which is a stronger statement than any single test of
the parse path, and the same contract the PHP port keeps."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SOURCE = os.path.join(_ROOT, "owid")

#: The modules through which Python reaches the network.
_NETWORK = ("urllib", "http.client", "socket", "requests", "httpx", "aiohttp")

#: The module that is allowed to reach it.
_FETCH = "public_key_fetch.py"

#: The ways a module in the package could import the fetch.
_FETCH_IMPORTS = (
    "from .public_key_fetch import",
    "from . import public_key_fetch",
    "import owid.public_key_fetch",
    "from owid.public_key_fetch import",
    "from owid import public_key_fetch",
)


def _import_forms(module: str):
    """The statements that would bring the module in, as they appear in
    source, so that prose naming a module in a comment does not count."""
    return (
        "import {0}".format(module),
        "from {0} import".format(module),
        "from {0}.".format(module),
    )


class NetworkContractTests(unittest.TestCase):
    def _sources(self):
        for name in sorted(os.listdir(_SOURCE)):
            if name.endswith(".py"):
                path = os.path.join(_SOURCE, name)
                with open(path, "r", encoding="utf-8") as handle:
                    yield name, handle.read()

    def test_nothing_but_the_fetch_reaches_the_network(self) -> None:
        seen = []
        for name, source in self._sources():
            seen.append(name)
            if name == _FETCH:
                self.assertIn(
                    "import urllib.request",
                    source,
                    "the fetch reaches the network through urllib",
                )
                continue
            for module in _NETWORK:
                for form in _import_forms(module):
                    self.assertNotIn(
                        form, source, "{0} must not reach {1}".format(name, module)
                    )
            for form in _FETCH_IMPORTS:
                # The package's own __init__ names the import in a comment
                # for the reader, which is prose and not a statement.
                lines = [
                    line
                    for line in source.splitlines()
                    if form in line and not line.lstrip().startswith("#")
                ]
                self.assertEqual(
                    [], lines, "{0} must not reach the fetch".format(name)
                )
        self.assertIn(_FETCH, seen, "the fetch is part of the package")

    def test_importing_the_package_does_not_load_the_fetch(self) -> None:
        """A caller who never asks for the fetch never loads the network
        client, which is what lets the core keep its promise of no network
        access of its own. Checked in a fresh interpreter, because the one
        running these tests has already imported the fetch."""
        script = (
            "import sys; import owid; "
            "print('owid.public_key_fetch' in sys.modules); "
            "import owid.public_key_fetch; "
            "print('owid.public_key_fetch' in sys.modules)"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(["False", "True"], completed.stdout.split())


if __name__ == "__main__":
    unittest.main()
