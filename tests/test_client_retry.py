# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""How `issue` behaves while the node is restarting, refusing, or asking for a
pause — the transport-retry policy wired into the real client. A fake clock
makes the waits observable without spending them.
"""

import json

import pytest

from certcrypt.client import CertcryptNodeClient, CertcryptNodeError, DeadLetter
from certcrypt.types import LooseCommitment

_REFUSE = object()


class Scripted:
    """A transport that plays `replies` in order (the last one repeats), plus a
    clock whose sleeps advance it."""

    def __init__(self, replies):
        self._replies = replies
        self.now = 1_000_000.0
        self.slept: list[float] = []
        self.seen_ids: set[str] = set()
        self.calls = 0

    def transport(self, method, url, headers, body, timeout):
        r = self._replies[min(self.calls, len(self._replies) - 1)]
        self.calls += 1
        if body:
            self.seen_ids.add(json.loads(body)["request_id"])
        if r is _REFUSE:
            raise ConnectionRefusedError("ECONNREFUSED")
        text = "" if r.get("body") is None else json.dumps(r["body"])
        headers = {"retry-after": r["retry_after"]} if r.get("retry_after") else {}
        return r["status"], text, headers

    def now_ms(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        ms = seconds * 1000
        self.slept.append(ms)
        self.now += ms

    def client(self, **kw) -> CertcryptNodeClient:
        return CertcryptNodeClient(
            "http://node.test",
            transport=self.transport,
            now_ms=self.now_ms,
            sleep=self.sleep,
            **kw,
        )


_COMMITMENTS = [
    LooseCommitment(
        capacity_evidence={"profile": "zero-data.unlinkable"},
        operative={"holder_id": "h", "pool_id": "p"},
    )
]

_ACCEPTED = {
    "request_id": "R",
    "submission_set_id": "S",
    "results": [
        {
            "operation_id": "op_1",
            "commitment_index": 0,
            "state": {"state": "accepted", "upstream_operation_id": "U"},
        }
    ],
}

_RESTARTING = {"status": 503, "retry_after": "10", "body": {"error": "node_restarting"}}


def test_a_nodes_retry_after_is_waited_out_exactly_and_never_spends_an_attempt():
    s = Scripted([_RESTARTING, _RESTARTING, _RESTARTING, {"status": 200, "body": _ACCEPTED}])
    # Two counted attempts would end a client that counted the pauses.
    client = s.client(retry_max_attempts=2)
    res = client.issue(_COMMITMENTS)
    assert res.results[0].state_name == "accepted"
    assert s.slept == [10_000, 10_000, 10_000], "exactly what the node asked"
    assert len(s.seen_ids) == 1, "one request_id across every retry"


def test_a_restart_with_the_port_closed_is_waited_out_by_time_not_by_a_count():
    # Twelve refused connections: more than the old fixed five attempts allowed.
    s = Scripted([_REFUSE] * 12 + [{"status": 200, "body": _ACCEPTED}])
    client = s.client(retry_base_ms=10, retry_cap_ms=100)
    res = client.issue(_COMMITMENTS)
    assert res.results[0].state_name == "accepted"
    assert s.calls == 13


def test_the_time_budget_ends_the_retrying_and_the_error_says_why():
    s = Scripted([_REFUSE])
    client = s.client(retry_max_elapsed_ms=5_000, retry_base_ms=1_000, retry_cap_ms=1_000)
    with pytest.raises(CertcryptNodeError, match="gave up after"):
        client.issue(_COMMITMENTS)
    total = sum(s.slept)
    assert total <= 5_000, f"never sleeps past the budget (slept {total} ms)"


def test_a_requested_pause_longer_than_the_budget_gives_up_at_once_with_the_wait_attached():
    s = Scripted([{"status": 503, "retry_after": "600", "body": {"error": "node_restarting"}}])
    client = s.client()
    with pytest.raises(CertcryptNodeError) as excinfo:
        client.issue(_COMMITMENTS)
    assert excinfo.value.status == 503
    assert excinfo.value.retry_after_ms == 600_000, "the caller can still see when to come back"
    assert s.slept == [], "no partial wait that could not succeed"


def test_a_refusal_about_the_request_is_not_retried():
    s = Scripted([{"status": 401, "body": {"error": "unauthorized"}}])
    client = s.client()
    with pytest.raises(CertcryptNodeError) as excinfo:
        client.issue(_COMMITMENTS)
    assert excinfo.value.status == 401
    assert s.calls == 1


def test_accepted_for_retry_per_member_is_final_the_node_holds_the_set():
    s = Scripted(
        [
            {
                "status": 202,
                "body": {
                    "request_id": "R",
                    "submission_set_id": "S",
                    "results": [
                        {
                            "operation_id": "op_a",
                            "commitment_index": 0,
                            "state": {"state": "accepted_for_retry", "error": "retry_later"},
                        }
                    ],
                },
            }
        ]
    )
    client = s.client()
    res = client.issue(_COMMITMENTS)
    assert res.results[0].operation_id == "op_a"
    assert s.calls == 1, "not resubmitted"


def test_a_read_that_reveals_a_late_members_upstream_id_hands_it_over():
    learned: list[tuple[str, str]] = []
    s = Scripted(
        [
            {
                "status": 200,
                "body": {
                    "operation_id": "op_a",
                    "state": {"state": "accepted", "upstream_operation_id": "UP-9"},
                },
            }
        ]
    )
    client = s.client(on_upstream_operation_id=lambda op, up: learned.append((op, up)))
    client.get_operation("op_a")
    assert learned == [("op_a", "UP-9")]


def test_dead_letters_are_listed_and_redriven_through_the_node():
    urls: list[str] = []

    def transport(method, url, headers, body, timeout):
        urls.append(f"{method} {url}")
        if url.endswith("/v1/outbox/dead"):
            reply = {"dead": [{"request_id": "R1", "attempts": 12, "created_at_ms": 5, "last_error": "HTTP 401"}]}
            return 200, json.dumps(reply), {}
        return 202, json.dumps({"request_id": "R1", "state": "pending"}), {}

    client = CertcryptNodeClient("http://node.test", transport=transport)
    dead = client.list_dead_letters()
    assert dead == [DeadLetter(request_id="R1", attempts=12, created_at_ms=5, last_error="HTTP 401")]
    client.redrive_dead_letter("R1")
    assert urls == [
        "GET http://node.test/v1/outbox/dead",
        "POST http://node.test/v1/outbox/dead/R1/redrive",
    ]


def test_a_wait_sits_out_a_requested_pause_without_counting_it():
    """Six pauses in a row: more than the five consecutive failures that end a
    wait. A node restarting mid-wait is not failing."""
    pause = {"status": 503, "retry_after": "10", "body": {"error": "node_restarting"}}
    done = {"status": 200, "body": {"operation_id": "op_a", "state": {"state": "independent_ready"}}}
    s = Scripted([pause] * 6 + [done])
    client = s.client()
    record = client.wait_for_operation("op_a", interval_ms=10)
    assert record.state_name == "independent_ready"
    assert s.slept == [10_000] * 6
