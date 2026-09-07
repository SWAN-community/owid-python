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
"""A stand in for the public key end point of a creator, answering the way
the cloud controller does and serving the real published 51d.es schedule.

The live end point answers 401 without a credential, so the tests stand this
up on the loopback address instead, which is what the Java, Rust and Go ports
do for the same reason.

A request naming a date is served the key that was in force then, a request
without one is served the key in force at the moment of the request, a date
after that moment is read as that moment, and a date the schedule does not
reach is a 404. That is how the cloud answers, and the moment of the request
is fixed at REQUEST_MOMENT so the tests are repeatable. The date parameter of
every request is recorded, so a test can say what went over the wire rather
than only what the URL builder returned.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional

from owid import Owid, endpoints, io
from owid.public_key_fetch import public_key_url

from tests import key_fixtures

#: The moment the end point treats as now, ten days after the fixture
#: identifier was signed and in the week that followed. Every port's stand in
#: uses this moment. An undated request is therefore served a key other than
#: the one that signed the fixture, exactly as it would be against the live
#: creator in that week.
REQUEST_MOMENT = datetime(2026, 9, 14, tzinfo=timezone.utc)


class Answer(Enum):
    """What the end point serves."""

    #: The published schedule, chosen by the date requested.
    SCHEDULE = "schedule"
    #: Text shaped like a PEM that no key can be read out of.
    #: The published schedule as JSON with the key alone and no moments, as a
    #: creator with one key and no schedule answers.
    SPANLESS = "spanless"
    #: The key alone as text, which the specification does not allow.
    PEM_ONLY = "pem-only"
    BROKEN_KEY = "broken-key"
    #: A redirect to a host that is not the creator, which a client must
    #: not follow.
    REDIRECT = "redirect"


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    end_point: "KeyEndPoint"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - the name is the protocol's.
        end_point = self.server.end_point  # type: ignore[attr-defined]
        query = urllib.parse.urlsplit(self.path).query
        values = urllib.parse.parse_qs(query, keep_blank_values=True)
        date = values.get("date", [None])[0]
        end_point.record(date)
        if end_point.answer is Answer.REDIRECT:
            self.send_response(302)
            self.send_header("Location", "http://elsewhere.invalid/key.pem")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            body = end_point.body(date)
        except ValueError:
            # A date that is not a number is refused, as the cloud refuses
            # it, rather than failing inside the handler.
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain" if end_point.answer is Answer.PEM_ONLY else "application/json",
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # The test output is for the assertions, not for the request log.
        pass


class KeyEndPoint:
    """A running stand in, listening on the loopback address."""

    def __init__(self, answer: Answer = Answer.SCHEDULE) -> None:
        self._answer = answer
        self._schedule = key_fixtures.schedule()
        self._dates: List[Optional[str]] = []
        self._lock = threading.Lock()
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.end_point = self
        self.base = "http://127.0.0.1:{0}".format(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stops the end point, after which its address refuses connections."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def url_for(self, owid: Owid) -> str:
        """The URL a fetch would use, with the creator domain replaced by this
        end point. The path and the query are the ones the package builds, so
        what is under test is the real URL rather than a copy of it."""
        built = public_key_url(owid, "http")
        at = built.index(owid.domain)
        return self.base + built[at + len(owid.domain) :]

    def dates(self) -> List[Optional[str]]:
        """The date parameter of every request served so far, in order."""
        with self._lock:
            return list(self._dates)

    def record(self, date: Optional[str]) -> None:
        with self._lock:
            self._dates.append(date)

    @property
    def answer(self) -> Answer:
        """What this end point serves."""
        return self._answer

    def body(self, date: Optional[str]) -> Optional[str]:
        """The body to serve, or None where the end point has no key. Raises
        ValueError where the date is not a count of minutes."""
        if self._answer is Answer.BROKEN_KEY:
            # Shaped like a PEM, with a body no key can be read out of. It is sent as the JSON form without the check a creator applies, because that check is what catches it.
            return json.dumps(
                {
                    "publicKeySPKI": (
                        "-----BEGIN PUBLIC KEY-----\n"
                        "bm90IGEga2V5\n"
                        "-----END PUBLIC KEY-----\n"
                    ),
                    "validFrom": None,
                    "validTo": None,
                }
            )
        asked = REQUEST_MOMENT
        if date is not None:
            minutes = int(date)
            if minutes <= io.MAXIMUM_MINUTES:
                asked = io.BASE_DATE + timedelta(minutes=minutes)
            if asked > REQUEST_MOMENT:
                asked = REQUEST_MOMENT
        key = self._schedule.key_in_force(asked)
        if key is None:
            return None
        if self._answer is Answer.PEM_ONLY:
            return key.public_key_pem
        if self._answer is Answer.SPANLESS:
            return endpoints.public_key_answer(key.public_key_pem, None, None, None)
        # The answer the package's own server side helper builds, so the
        # client is tested against what a creator built on it sends.
        status, body = endpoints.public_key_response_at(
            self._schedule, "pkcs", date, REQUEST_MOMENT
        )
        assert status == 200, status
        return body
