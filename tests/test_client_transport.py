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

"""The transport around every request: the 30 s bound, the retried reads, the
liveness probe that never raises, and the submit whose answer was lost.

Each of these is a decision about a misbehaving node — one that accepts the
connection and never answers, restarts mid-read, or answers 200 with a body that
is not one — and none of them shows against a healthy node.
"""

import json

import pytest

from certcrypt.client import REQUEST_TIMEOUT_S, CertcryptNodeClient, CertcryptNodeError
from certcrypt.types import LooseCommitment

_REFUSE = object()


class _Scripted:
    """Plays `replies` in order (the last repeats), recording each request; a
    clock whose sleeps advance it."""

    def __init__(self, replies):
        self.replies = replies
        self.seen = []
        self.now = 1_000_000.0

    def transport(self, method, url, headers, body, timeout):
        self.seen.append(
            {"method": method, "url": url, "body": json.loads(body) if body else None, "timeout": timeout}
        )
        r = self.replies[min(len(self.seen) - 1, len(self.replies) - 1)]
        if r is _REFUSE:
            raise ConnectionRefusedError("ECONNREFUSED")
        status, text = r
        return status, text if isinstance(text, str) else json.dumps(text), {}

    def client(self):
        def sleep(seconds):
            self.now += seconds * 1000

        return CertcryptNodeClient(
            "https://node.test", transport=self.transport, now_ms=lambda: self.now, sleep=sleep
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
    "results": [{"operation_id": "op-1", "commitment_index": 0, "state": {"state": "accepted"}}],
}
_OP_BODY = {"operation_id": "op-1", "state": {"state": "processing"}}
_REF = "ab" * 32
_ACTIVATE = dict(
    code="c",
    holder_key_set_root="r",
    key_set_disclosure={},
    key_set_possession_b64="cA==",
    rules_version="rules/conformance",
    system_root_fingerprint="aa" * 32,
    valid_until="2100-01-01T00:00:00Z",
)


# --- health -----------------------------------------------------------------


def test_health_is_true_on_a_2xx():
    assert _Scripted([(200, "ok")]).client().health() is True


def test_health_is_false_on_an_error_status():
    assert _Scripted([(503, "down")]).client().health() is False


def test_health_is_false_not_a_raise_on_a_transport_failure():
    s = _Scripted([_REFUSE])
    assert s.client().health() is False
    assert len(s.seen) == 1  # a liveness probe is one request, never retried


def test_health_gives_up_after_30_s_and_reports_false():
    def never_answers(method, url, headers, body, timeout):
        assert timeout == 30.0
        raise TimeoutError("timed out")

    client = CertcryptNodeClient("https://node.test", transport=never_answers)
    assert client.health() is False


# --- the 30 s bound on every request -----------------------------------------


def test_the_request_timeout_is_30_seconds():
    assert REQUEST_TIMEOUT_S == 30.0


def test_every_request_carries_the_timeout():
    s = _Scripted(
        [
            (200, "ok"),  # health
            (200, _ACCEPTED),  # issue
            (409, {"error": "integration_key_replaced", "message": "use the latest key"}),  # activate
            (200, _OP_BODY),  # get_operation
            (200, {"operation_id": "op-1", "status": "processing"}),  # by-commitment
            (200, {"emissions": [], "truncated": False}),  # unresolved
            (200, {"dead": []}),  # dead letters
            (202, {}),  # redrive
        ]
    )
    client = s.client()
    client.health()
    client.issue(_COMMITMENTS)
    with pytest.raises(CertcryptNodeError):
        client.activate(**_ACTIVATE)
    client.get_operation("op-1")
    client.get_emission_by_commitment(_REF)
    client.list_unresolved_emissions("2026-01-01T00:00:00Z")
    client.list_dead_letters()
    client.redrive_dead_letter("R1")
    assert len(s.seen) == 8
    for call in s.seen:
        assert call["timeout"] == 30.0, f"{call['method']} {call['url']} carries no timeout"


# --- reads are retried under the transport-retry policy -----------------------


def test_get_operation_rides_out_a_503():
    s = _Scripted([(503, "restarting"), (200, _OP_BODY)])
    assert s.client().get_operation("op-1").state_name == "processing"
    assert len(s.seen) == 2


def test_get_operation_rides_out_a_refused_connection():
    s = _Scripted([_REFUSE, (200, _OP_BODY)])
    assert s.client().get_operation("op-1").state_name == "processing"
    assert len(s.seen) == 2


def test_get_operation_does_not_retry_a_404():
    s = _Scripted([(404, "no such operation")])
    with pytest.raises(CertcryptNodeError) as excinfo:
        s.client().get_operation("op-x")
    assert excinfo.value.status == 404
    assert len(s.seen) == 1


def test_get_emission_by_commitment_rides_out_a_503():
    s = _Scripted([(503, "restarting"), (200, {"operation_id": "op-1", "status": "processing"})])
    assert s.client().get_emission_by_commitment(_REF).status == "processing"
    assert len(s.seen) == 2


def test_list_unresolved_emissions_rides_out_a_503():
    s = _Scripted([(503, "restarting"), (200, {"emissions": [], "truncated": False})])
    page = s.client().list_unresolved_emissions("2026-01-01T00:00:00Z")
    assert page.emissions == [] and page.truncated is False
    assert len(s.seen) == 2


def test_list_dead_letters_rides_out_a_503():
    s = _Scripted([(503, "restarting"), (200, {"dead": []})])
    assert s.client().list_dead_letters() == []
    assert len(s.seen) == 2


def test_a_read_that_keeps_failing_gives_up_on_the_time_budget_saying_so():
    s = _Scripted([(503, "down")])
    with pytest.raises(CertcryptNodeError, match=r"gave up after \d+s and \d+ attempt\(s\)"):
        s.client().get_operation("op-1")


# --- a 2xx submit whose body is not JSON --------------------------------------


def test_a_2xx_submit_whose_body_is_not_json_is_retried_with_the_same_request_id():
    s = _Scripted([(200, "<html>proxy error</html>"), (200, _ACCEPTED)])
    res = s.client().issue(_COMMITMENTS)
    assert res.results[0].operation_id == "op-1"
    assert len(s.seen) == 2
    ids = [c["body"]["request_id"] for c in s.seen]
    assert ids[0] == ids[1]  # the retry is the SAME request


def test_a_2xx_submit_whose_body_is_json_but_not_an_object_is_retried_too():
    s = _Scripted([(200, [1, 2]), (200, _ACCEPTED)])
    s.client().issue(_COMMITMENTS)
    assert len(s.seen) == 2


def test_a_submit_that_never_gets_a_readable_answer_gives_up_naming_it():
    s = _Scripted([(200, "not json")])
    with pytest.raises(
        CertcryptNodeError, match=r"^issue failed: unparseable node response — gave up after"
    ):
        s.client().issue(_COMMITMENTS)


# --- activation refusals say why -----------------------------------------------


def test_an_activation_refusal_carries_the_nodes_code_and_message():
    s = _Scripted([(409, {"error": "integration_key_replaced", "message": "use the latest key"})])
    with pytest.raises(CertcryptNodeError) as excinfo:
        s.client().activate(**_ACTIVATE)
    err = excinfo.value
    assert str(err) == "activate failed: HTTP 409 — integration_key_replaced: use the latest key"
    assert err.status == 409
    assert err.code == "integration_key_replaced"
