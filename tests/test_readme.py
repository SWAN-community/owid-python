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

"""Runs the Python examples in the README so that documentation naming a
method that does not exist fails the build.

The examples are taken in the order they appear and run in one namespace,
because the later ones use the creator and the OWID the first one makes, which
is how a reader follows them. Checks are appended so that the examples are
shown to do what the surrounding text says they do rather than merely to run.
"""

from __future__ import annotations

import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
README = os.path.join(os.path.dirname(_HERE), "README.md")

#: Fenced blocks marked as Python, in the order they appear.
_BLOCK = re.compile(r"```python\r?\n(.*?)```", re.DOTALL)


def _examples():
    with open(README, "r", encoding="utf-8") as handle:
        return _BLOCK.findall(handle.read())


class ReadmeTests(unittest.TestCase):
    """Every documented example runs, and does what the text says it does."""

    def test_readme_still_carries_its_examples(self) -> None:
        """A README that lost its examples would pass the run below without
        having run anything, so the count is asserted first."""
        self.assertGreaterEqual(len(_examples()), 4)

    def test_readme_examples_run(self) -> None:
        namespace = {"__name__": "readme_example"}
        for index, example in enumerate(_examples()):
            with self.subTest(example=index):
                exec(compile(example, "README.md#{0}".format(index), "exec"),
                     namespace)

        # The first example read its own identifier back.
        result = namespace["result"]
        self.assertTrue(result.ok, result.status)
        self.assertEqual(namespace["owid"], result.owid)

        # The signature status example found a genuine signature.
        status = namespace["status"]
        self.assertEqual("SignatureValid", status.value)

        # The framed walk stepped over the absent node and read both OWIDs.
        self.assertEqual(["first", "second"], namespace["payloads"])


if __name__ == "__main__":
    unittest.main()
