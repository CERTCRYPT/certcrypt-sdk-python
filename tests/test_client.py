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

"""The node client, driven through an injected transport.

No test here touches the network. That is not only for speed: the behaviors
worth pinning are the ones that only show up against a misbehaving node — a
retried GET, a blip mid-wait, a 404, a window that runs late — and those are
hard to provoke against a healthy one.

This file has no conformance vectors behind it, unlike the crypto and artifact
layers: the node's HTTP surface is not part of the published byte contract. The
guarantee here is weaker by nature, so the tests pin decisions rather than bytes.
"""

import base64
import json

import pytest

from certcrypt.artifacts.capacity_evidence import (
    MAX_SUBMISSION_SET_MEMBERS,
    SubmissionSetTooLargeError,
)
from certcrypt.artifacts.commitment_inclusion import commitment_subtree_root
from certcrypt.client import (
    CertcryptNodeClient,
    CertcryptNodeError,
    next_poll_delay_ms)
from certcrypt.types import LooseCommitment, SettlementWindowEstimate


class FakeTransport:
    """Scripted responses, recording every call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": json.loads(body) if body else None,
            }
        )
        if not self._responses:
            # pytest.fail is a BaseException: the client cannot mistake it for a
            # transport error and retry it.
            pytest.fail(f"unexpected extra call: {method} {url}")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item if len(item) == 3 else (*item, {})


def _fake_clock():
    """A clock whose sleeps advance it, so a retry never spends real time."""
    now = [0.0]
    return {
        "now_ms": lambda: now[0],
        "sleep": lambda seconds: now.__setitem__(0, now[0] + seconds * 1000),
    }


def _client(responses, **kw):
    transport = FakeTransport(responses)
    kw.setdefault("retry_base_ms", 0)
    for k, v in _fake_clock().items():
        kw.setdefault(k, v)
    return (
        CertcryptNodeClient("https://node.example/", transport=transport, **kw),
        transport)


def _commitment():
    return LooseCommitment(
        capacity_evidence={"profile": "zero-data.unlinkable"},
        operative={"holder_id": "h", "pool_id": "p"})


# --------------------------------------------------------------------------
# requests, auth, retries
# --------------------------------------------------------------------------


def test_base_url_trailing_slash_is_normalized():
    client, transport = _client([(200, "{}")])
    client.health()
    assert transport.calls[0]["url"] == "https://node.example/health"


_ISSUE_ACCEPTED = (
    200,
    '{"request_id":"r","results":[{"operation_id":"op-1","commitment_index":0,'
    '"state":{"state":"accepted"}}]}',
)


def test_issuer_proof_is_the_only_credential_sent():
    # The node authenticates an issuer only by this header, built fresh per
    # request; no bearer goes out for the node to ignore.
    built = []
    client, transport = _client(
        [_ISSUE_ACCEPTED],
        issuer_auth_proof=lambda m, u, b: built.append(1) or f"proof-{len(built)}")
    client.issue([_commitment()])
    headers = transport.calls[0]["headers"]
    assert headers["x-certcrypt-issuer-auth"] == "proof-1"
    assert "authorization" not in {k.lower() for k in headers}


def test_issue_422_upstream_refusal_is_not_retried_and_names_the_status():
    # The node answers 422 + IssueResponse when the upstream service refused the
    # request itself. Nothing was queued and the same bytes get the same answer.
    body = json.dumps({
        "request_id": "r",
        "results": [],
        "state": {
            "state": "submission_failed",
            "error": "request refused",
            "upstream_status": 400,
        },
    })
    client, transport = _client([(422, body)] * 3, retry_max_attempts=5)
    with pytest.raises(CertcryptNodeError) as info:
        client.issue([_commitment()])
    err = info.value
    assert err.status == 422
    assert err.code == "submission_failed"
    assert err.upstream_status == 400
    assert "submission_failed (upstream HTTP 400): request refused" in str(err)
    assert len(transport.calls) == 1, "a definitive refusal is never resent"


def test_issue_422_request_error_surfaces_code_and_message():
    body = json.dumps({
        "error": "empty_submission",
        "message": "the request carries no commitments",
        "request_id": "r",
    })
    client, transport = _client([(422, body)] * 3, retry_max_attempts=5)
    with pytest.raises(CertcryptNodeError) as info:
        client.issue([_commitment()])
    err = info.value
    assert err.status == 422
    assert err.code == "empty_submission"
    assert err.upstream_status is None
    assert "HTTP 422 — empty_submission: the request carries no commitments" in str(err)
    assert len(transport.calls) == 1, "a request error is never resent"


def test_issuer_proof_omitted_when_provider_returns_none():
    client, transport = _client([_ISSUE_ACCEPTED], issuer_auth_proof=lambda m, u, b: None)
    client.issue([_commitment()])
    assert "x-certcrypt-issuer-auth" not in transport.calls[0]["headers"]


def test_idempotent_get_retries_transient_failures():
    client, transport = _client(
        [(503, "busy"), (500, "oops"), (200, '{"operation_id":"op-1","state":{"state":"processing"}}')]
    )
    record = client.get_operation("op-1")
    assert record.state_name == "processing"
    assert len(transport.calls) == 3


def test_a_retried_issue_is_the_same_request():
    """A lost response does not mean the node did not accept it, so a retry must
    be one the server can recognize: the same `request_id` and the same signed
    set, never a second emission."""
    client, transport = _client([(503, "busy"), (502, "upstream"), _ISSUE_ACCEPTED])
    client.issue([_commitment()])
    assert len(transport.calls) == 3
    bodies = [c["body"] for c in transport.calls]
    assert bodies[0]["request_id"]
    assert bodies[0] == bodies[1] == bodies[2]


def test_a_caller_supplied_request_id_is_kept():
    client, transport = _client([_ISSUE_ACCEPTED])
    client.issue([_commitment()], request_id="01JREQUEST")
    assert transport.calls[0]["body"]["request_id"] == "01JREQUEST"


def test_non_retryable_status_fails_immediately():
    client, transport = _client([(400, "bad request")])
    with pytest.raises(CertcryptNodeError) as excinfo:
        client.get_operation("op-1")
    assert excinfo.value.status == 400
    assert excinfo.value.body == "bad request"
    assert len(transport.calls) == 1


def test_health_reports_false_instead_of_raising():
    client, _ = _client([(500, "down")] * 5)
    assert client.health() is False


def test_issue_requires_at_least_one_commitment():
    client, _ = _client([])
    with pytest.raises(ValueError):
        client.issue([])


# --------------------------------------------------------------------------
# response shapes
# --------------------------------------------------------------------------


def test_operation_record_normalizes_the_forwarded_server_body():
    """The node answers with either `state` or a bare `status`."""
    client, _ = _client(
        [(200, '{"operation_id":"op-1","status":"independent_ready","independence_proof":"eyJ9"}')]
    )
    record = client.get_operation("op-1")
    assert record.state_name == "independent_ready"
    assert record.is_terminal
    assert record.request_id is None


def test_accepted_for_retry_is_not_terminal():
    """The node has custody and will deliver; re-submitting would emit twice."""
    client, _ = _client(
        [(200, '{"operation_id":"op-1","state":{"state":"accepted_for_retry","error":"upstream"}}')]
    )
    assert client.get_operation("op-1").is_terminal is False


def test_whole_request_outcome_shape():
    client, _ = _client(
        [(200, '{"request_id":"r","results":[],"state":{"state":"rejected","reason_code":"x"}}')]
    )
    response = client.issue([_commitment()])
    assert response.results == []
    assert response.state["state"] == "rejected"


def test_a_pre_evaluation_rejection_is_final_not_retried():
    # The node answers it with HTTP 200; the same set always gets the same answer.
    client, _ = _client(
        [(200, '{"request_id":"r","results":[],"state":{"state":"pre_evaluation_rejected","reason_code":"x","message":"m"}}')]
    )
    # One reply only: the fake fails the test on any further request.
    response = client.issue([_commitment()])
    assert response.state["state"] == "pre_evaluation_rejected"


def test_per_member_results_map_back_to_input():
    client, _ = _client(
        [
            (
                200,
                json.dumps(
                    {
                        "request_id": "r",
                        "submission_set_id": "set-1",
                        "results": [
                            {
                                "operation_id": "op-1",
                                "commitment_index": 0,
                                "state": {"state": "accepted"},
                            }
                        ],
                    }
                ))
        ]
    )
    response = client.issue([_commitment()])
    assert response.submission_set_id == "set-1"
    # Correlation is positional: the label never travels (submission-set/1 §7.3).
    assert response.results[0].commitment_index == 0
    assert response.results[0].state_name == "accepted"


# --------------------------------------------------------------------------
# poll scheduling — a pure function, pinned directly
# --------------------------------------------------------------------------


def _target_ms(stamp: str) -> float:
    """The timestamp the scheduler will parse, computed rather than hardcoded."""
    from datetime import datetime, timezone

    return (
        datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
        * 1000
    )


def test_waits_until_the_window_instead_of_spinning():
    stamp = "2026-05-09T12:00:00Z"
    window = SettlementWindowEstimate("std", "v1", stamp)
    now = _target_ms(stamp) - 60_000  # one minute before the target
    delay, overdue = next_poll_delay_ms(
        attempt=1, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=300_000, rand=lambda: 0.0
    )
    assert delay > 50_000
    assert overdue is False


def test_a_far_future_target_cannot_park_the_poller():
    window = SettlementWindowEstimate("std", "v1", "2099-01-01T00:00:00Z")
    delay, _ = next_poll_delay_ms(
        attempt=1, now_ms=0, window=window, backoff_base_ms=1000, backoff_cap_ms=30_000, rand=lambda: 0.0
    )
    assert delay == 600_000  # one sleep towards a check is at most 10 min, not 6 h


def test_a_passed_target_reports_overdue():
    """Running late must look different from a normal wait."""
    window = SettlementWindowEstimate("std", "v1", "2020-01-01T00:00:00Z")
    delay, overdue = next_poll_delay_ms(
        attempt=3,
        now_ms=1778673600000.0,
        window=window,
        backoff_base_ms=1000,
        backoff_cap_ms=30_000, rand=lambda: 0.0)
    assert overdue is True
    assert delay == 4000  # 1000 * 2^2


_CLOSE = "2026-05-09T12:00:00Z"
_SETTLED = "2026-05-09T12:00:15Z"


def test_with_an_expected_settlement_instant_the_first_check_is_60_percent_of_the_way():
    # Close in 20 s, expected 15 s after it: the early check is at close + 9 s.
    window = SettlementWindowEstimate("std", "v1", _CLOSE, _SETTLED)
    now = _target_ms(_CLOSE) - 20_000  # 20 s before the close, 35 s before settlement
    delay, overdue = next_poll_delay_ms(
        attempt=1, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=60_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (29_000, False)


def test_after_the_early_check_the_next_one_is_the_expected_instant_plus_1s():
    window = SettlementWindowEstimate("std", "v1", _CLOSE, _SETTLED)
    now = _target_ms(_CLOSE) + 9_200  # just after the early check
    delay, overdue = next_poll_delay_ms(
        attempt=2, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=60_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (6_800, False)


def test_each_scheduled_check_is_pushed_back_by_at_most_1s_never_earlier():
    window = SettlementWindowEstimate("std", "v1", _CLOSE, _SETTLED)
    now = _target_ms(_CLOSE) - 20_000

    def at(r: float) -> int:
        return next_poll_delay_ms(
            attempt=1, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=60_000, rand=lambda: r
        )[0]

    assert at(0.0) == 29_000
    assert at(0.5) == 29_500
    assert 29_000 <= at(0.9999) <= 30_000


def test_between_the_close_and_the_expected_settlement_instant_it_is_not_overdue():
    window = SettlementWindowEstimate("std", "v1", _CLOSE, _SETTLED)
    now = _target_ms(_CLOSE) + 10_000  # 10 s after close, 5 s before settlement
    delay, overdue = next_poll_delay_ms(
        attempt=2, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=30_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (6000, False)


def test_past_the_expected_settlement_instant_it_is_overdue():
    window = SettlementWindowEstimate("std", "v1", _CLOSE, _SETTLED)
    now = _target_ms(_SETTLED) + 5_000
    delay, overdue = next_poll_delay_ms(
        attempt=3, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=30_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (4000, True)


def test_an_unparseable_expected_settlement_instant_falls_back_to_the_close():
    window = SettlementWindowEstimate("std", "v1", _CLOSE, "not-a-timestamp")
    now = _target_ms(_CLOSE) - 20_000
    delay, overdue = next_poll_delay_ms(
        attempt=1, now_ms=now, window=window, backoff_base_ms=1000, backoff_cap_ms=30_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (23_000, False)


def test_without_an_estimate_it_backs_off_exponentially():
    delays = [
        next_poll_delay_ms(
            attempt=a, now_ms=0, window=None, backoff_base_ms=1000, backoff_cap_ms=8000, rand=lambda: 0.0
        )[0]
        for a in (1, 2, 3, 4, 5)
    ]
    assert delays == [1000, 2000, 4000, 8000, 8000]


def test_unparseable_target_falls_back_to_backoff():
    window = SettlementWindowEstimate("std", "v1", "not-a-timestamp")
    delay, overdue = next_poll_delay_ms(
        attempt=1, now_ms=0, window=window, backoff_base_ms=1000, backoff_cap_ms=30_000, rand=lambda: 0.0
    )
    assert (delay, overdue) == (1000, False)


# --------------------------------------------------------------------------
# waiting
# --------------------------------------------------------------------------


def _wait_kwargs(clock):
    # The wait reads time from the client's clock (`_client` injects a fake
    # one whose sleeps advance it), so only the schedule is set here.
    return {"interval_ms": 10}


def test_wait_returns_on_the_first_terminal_state():
    clock = [0.0]
    client, transport = _client(
        [
            (200, '{"operation_id":"op-1","state":{"state":"processing"}}'),
            (200, '{"operation_id":"op-1","state":{"state":"independent_ready"}}'),
        ]
    )
    record = client.wait_for_operation("op-1", **_wait_kwargs(clock))
    assert record.state_name == "independent_ready"
    assert len(transport.calls) == 2


def test_a_transient_blip_does_not_abort_the_wait():
    """A network blip while waiting on a real window is expected."""
    clock = [0.0]
    # Four consecutive blips: below the give-up threshold of five, so the wait
    # must ride them out rather than abort.
    client, _ = _client(
        [
            (200, '{"operation_id":"op-1","state":{"state":"processing"}}'),
            (503, "blip"),
            (503, "blip"),
            (503, "blip"),
            (503, "blip"),
            (200, '{"operation_id":"op-1","state":{"state":"independent_ready"}}'),
        ],
        retry_max_attempts=1)
    assert (
        client.wait_for_operation("op-1", **_wait_kwargs(clock)).state_name
        == "independent_ready"
    )


def test_a_404_surfaces_immediately():
    """A wrong operation id is not a blip to wait out."""
    clock = [0.0]
    client, _ = _client([(404, "no such operation")], retry_max_attempts=1)
    with pytest.raises(CertcryptNodeError) as excinfo:
        client.wait_for_operation("op-nope", **_wait_kwargs(clock))
    assert excinfo.value.status == 404


def test_persistent_failures_eventually_give_up():
    clock = [0.0]
    client, _ = _client([(503, "down")] * 5, retry_max_attempts=1)
    with pytest.raises(CertcryptNodeError):
        client.wait_for_operation("op-1", **_wait_kwargs(clock))


def test_a_wait_that_ends_without_a_terminal_state_raises():
    """The bound is reached while the operation is still progressing: that is
    reported as an error naming the last state, never as a record the caller
    could mistake for an outcome. The handle stays valid; poll again later."""
    client, _ = _client(
        [(200, '{"operation_id":"op-1","state":{"state":"processing"}}')] * 3
    )
    with pytest.raises(
        CertcryptNodeError,
        match=r"^operation op-1 did not reach a terminal state after 0s \(last state: processing\)$",
    ):
        client.wait_for_operation("op-1", interval_ms=10, max_attempts=3)


def test_a_wait_bounded_by_time_raises_the_same_way():
    client, _ = _client(
        [(200, '{"operation_id":"op-1","state":{"state":"processing"}}')] * 4
    )
    with pytest.raises(CertcryptNodeError, match="did not reach a terminal state after 3s"):
        client.wait_for_operation("op-1", interval_ms=1000, max_wait_ms=2500)


def test_progress_is_reported_on_every_tick():
    clock = [0.0]
    seen = []
    client, _ = _client(
        [
            (200, '{"operation_id":"op-1","state":{"state":"processing"}}'),
            (200, '{"operation_id":"op-1","state":{"state":"independent_ready"}}'),
        ]
    )
    client.wait_for_operation("op-1", on_progress=seen.append, **_wait_kwargs(clock))
    assert len(seen) == 1
    assert seen[0].node_state == "processing"
    assert seen[0].attempt == 1


def test_the_window_survives_a_blip():
    """A transient failure must not lose the schedule we were waiting on."""
    clock = [0.0]
    seen = []
    client, _ = _client(
        [
            (
                200,
                json.dumps(
                    {
                        "operation_id": "op-1",
                        "state": {"state": "processing"},
                        "settlement_window": {
                            "window_profile": "std",
                            "window_profile_version": "v1",
                            "target_close_by": "2099-01-01T00:00:00Z",
                        },
                    }
                )),
            (503, "blip"),
            (200, '{"operation_id":"op-1","state":{"state":"independent_ready"}}'),
        ],
        retry_max_attempts=1)
    client.wait_for_operation("op-1", on_progress=seen.append, **_wait_kwargs(clock))
    assert seen[-1].window is not None
    assert seen[-1].window.window_profile == "std"


# --------------------------------------------------------------------------
# verification package
# --------------------------------------------------------------------------


def _independent_ready_body(consumed_ids):
    proof = {"consumed_commitment_ids": consumed_ids, "subtree_root": "ab" * 32}
    return json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "independent_ready"},
            "independence_proof": base64.b64encode(
                json.dumps(proof).encode("utf-8")
            ).decode("ascii"),
            "settlement_material": base64.b64encode(b'{"settlement_profile_id":"x"}').decode(
                "ascii"
            ),
        }
    )


def test_build_verification_package_derives_the_inclusion_proof():
    """The node never returns this proof — it is derived client-side."""
    clock = [0.0]
    ids = ["commit-a", "commit-b", "commit-c"]
    client, _ = _client([(200, _independent_ready_body(ids))])
    package = client.build_verification_package(
        "op-1",
        commitment_index=1,
        rules_version="rules/conformance",
        system_id="certcrypt",
        base_certificate={"schema": "certcrypt-certificate"},
        **_wait_kwargs(clock))
    proof = package["commitment_inclusion_proof"]
    assert proof["commitment_id"] == "commit-b"
    assert proof["subtree_size"] == "3"
    assert package["verification_context"] == {
        "rules_version": "rules/conformance",
        "system_id": "certcrypt",
    }
    # The derived proof must reconstruct the subtree root over the same ids.
    from certcrypt.crypto.merkle import verify_inclusion_proof

    assert verify_inclusion_proof(
        proof["commitment_leaf_hash"],
        1,
        proof["commitment_siblings"],
        commitment_subtree_root(ids),
        3)


def test_package_refuses_a_non_ready_operation():
    clock = [0.0]
    client, _ = _client(
        [(200, '{"operation_id":"op-1","state":{"state":"rejected","reason_code":"x"}}')]
    )
    with pytest.raises(CertcryptNodeError, match="not independent_ready"):
        client.build_verification_package(
            "op-1",
            commitment_index=0,
            rules_version="r",
            system_id="s",
            base_certificate={"schema": "certcrypt-certificate"},
            **_wait_kwargs(clock))


def test_package_refuses_empty_consumed_commitment_ids():
    clock = [0.0]
    client, _ = _client([(200, _independent_ready_body([]))])
    with pytest.raises(CertcryptNodeError, match="consumed_commitment_ids"):
        client.build_verification_package(
            "op-1",
            commitment_index=0,
            rules_version="r",
            system_id="s",
            base_certificate={"schema": "certcrypt-certificate"},
            **_wait_kwargs(clock))


# ---------------------------------------------------------------------------
# by-commitment: the lookup that outlives the node
#
# A node's operation id lives in THAT node's journal. A restart with an in-memory
# journal, or an issuer moving to another node, leaves it unable to ask about an
# emission the issuance service still holds. The capacity-evidence digest has no
# such problem — the issuer recomputes it from evidence it signed.
# ---------------------------------------------------------------------------

_REF = "c6132cdf3e82f056d284627dbe47ae603d9b2eea939523ba84dd95797c8f7aee"


def test_get_emission_by_commitment_sends_the_digest_as_the_resource():
    """The load-bearing assertion.

    Binding the read to an id the node hands out would let a node get an issuer to
    sign a read it never asked for: the issuer would be signing over a value whose
    meaning it cannot check.
    """
    client, transport = _client(
        [(200, json.dumps({"operation_id": "op-api", "status": "processing"}))],
        issuer_read_proof=lambda resource: f"proof-for-{resource}",
    )
    rec = client.get_emission_by_commitment(_REF)

    call = transport.calls[0]
    assert call["url"].endswith(f"/v1/emissions/by-commitment/{_REF}")
    assert call["headers"]["x-certcrypt-issuer-read"] == f"proof-for-{_REF}"
    assert rec.status == "processing"


def test_a_retried_read_carries_a_new_issuer_half_every_attempt():
    """The issuance service spends a read challenge on first use, so reusing
    the first attempt's half would turn a retry that got through into a 401."""
    minted = []

    def mint(resource):
        minted.append(resource)
        return f"proof-{len(minted)}"

    client, transport = _client(
        [
            (503, "down"),
            (503, "down"),
            (200, json.dumps({"operation_id": "op-api", "status": "processing"})),
        ],
        issuer_read_proof=mint,
    )
    client.get_emission_by_commitment(_REF)
    assert [c["headers"]["x-certcrypt-issuer-read"] for c in transport.calls] == [
        "proof-1",
        "proof-2",
        "proof-3",
    ]


def test_get_emission_by_commitment_returns_both_artifacts_once_settled():
    """Both or neither: a package missing the settlement material does not verify."""
    client, _ = _client(
        [
            (
                200,
                json.dumps(
                    {
                        "operation_id": "op-api",
                        "status": "independent_ready",
                        "independence_proof": "cHJvb2Y=",
                        "settlement_material": "bWF0ZXJpYWw=",
                    }
                ),
            )
        ]
    )
    rec = client.get_emission_by_commitment(_REF)
    assert rec.status == "independent_ready"
    assert rec.independence_proof == "cHJvb2Y="
    assert rec.settlement_material == "bWF0ZXJpYWw="


def test_get_emission_by_commitment_raises_on_404():
    client, _ = _client([(404, json.dumps({"error": "not_found"}))])
    with pytest.raises(CertcryptNodeError):
        client.get_emission_by_commitment(_REF)


def test_a_server_body_that_says_rejected_is_rejected_not_processing():
    """A server body that says `rejected` is read as `rejected`."""
    from certcrypt.types import OperationRecord

    rejected = OperationRecord.from_wire({"operation_id": "OP-UP", "status": "rejected"})
    assert rejected.state_name == "rejected"
    assert rejected.is_terminal
    assert rejected.state["reason_code"] == "rejected"
    assert rejected.state["message"] == ""

    short = OperationRecord.from_wire({"operation_id": "OP-UP", "status": "insufficient_capacity"})
    assert short.state_name == "insufficient_capacity"
    assert short.is_terminal

    ready = OperationRecord.from_wire({"operation_id": "OP-UP", "status": "independent_ready"})
    assert ready.state == {"state": "independent_ready", "upstream_operation_id": "OP-UP"}

    # An unknown status is not invented into a terminal one.
    other = OperationRecord.from_wire({"operation_id": "OP-UP", "status": "something_new"})
    assert other.state_name == "processing"
    assert not other.is_terminal


def test_a_server_body_that_says_expired_is_expired_and_terminal():
    """submission-set/1 §11.1: an accepted operation whose authorization ran out
    ends `expired` — terminal (folding it into `processing` polls forever), with its
    reason, and never read as `rejected`."""
    from certcrypt.types import OperationRecord

    rec = OperationRecord.from_wire(
        {
            "operation_id": "OP-UP",
            "status": "expired",
            "reason_code": "authorization_expired_before_finality",
            "message": "nothing was consumed",
        }
    )
    assert rec.state == {
        "state": "expired",
        "reason_code": "authorization_expired_before_finality",
        "message": "nothing was consumed",
    }
    assert rec.is_terminal


# --------------------------------------------------------------------------
# submission-set/1 §8.1: the producer refuses to build a set over the bound
# --------------------------------------------------------------------------


def test_issue_sends_a_set_of_exactly_the_bound():
    results = ",".join(
        f'{{"operation_id":"op-{i}","commitment_index":{i},"state":{{"state":"accepted"}}}}'
        for i in range(MAX_SUBMISSION_SET_MEMBERS)
    )
    client, transport = _client([(200, f'{{"request_id":"r","results":[{results}]}}')])
    client.issue([_commitment()] * MAX_SUBMISSION_SET_MEMBERS)
    assert len(transport.calls) == 1
    assert len(transport.calls[0]["body"]["commitments"]) == MAX_SUBMISSION_SET_MEMBERS


def test_issue_refuses_one_over_the_bound_before_sending():
    client, transport = _client([])
    with pytest.raises(SubmissionSetTooLargeError) as excinfo:
        client.issue([_commitment()] * (MAX_SUBMISSION_SET_MEMBERS + 1))
    assert excinfo.value.count == MAX_SUBMISSION_SET_MEMBERS + 1
    assert transport.calls == [], "the over-bound set never reaches the node"


def test_settlement_is_overdue_only_strictly_after_the_scheduled_instant():
    from certcrypt.client import is_settlement_overdue

    window = SettlementWindowEstimate(
        "std", "v1", "2030-01-01T00:00:00Z", expected_settled_by="2030-01-01T00:00:30Z"
    )
    expected_ms = 1893456030000  # 2030-01-01T00:00:30Z
    # Between the close and the expected instant: not overdue.
    assert not is_settlement_overdue(window, expected_ms - 15_000)
    assert not is_settlement_overdue(window, expected_ms)
    assert is_settlement_overdue(window, expected_ms + 1)
    # Without the operator's estimate the close is the instant.
    close_only = SettlementWindowEstimate("std", "v1", "2030-01-01T00:00:00Z")
    assert is_settlement_overdue(close_only, expected_ms - 29_999)
    assert not is_settlement_overdue(None, expected_ms)
