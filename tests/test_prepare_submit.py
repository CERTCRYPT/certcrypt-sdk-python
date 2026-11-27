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

"""`prepare()` / `submit()` — signing a certificate without sending it, so N can
travel in ONE submission set.

Grouping amortizes the per-submission overhead, so the saving is real and the
thing that must not regress is the WIRE: a commitment prepared and submitted
has to reach the node in the same shape `issue()` sends, or grouping would
quietly emit different certificates than the single path — and the difference
would only surface when a third party tried to verify one.

These pin that, the N-in-one-request shape, and the no-reuse invariant that makes
`prepare()` irreversible in unlinkable mode.
"""

import json

import pytest

from certcrypt.artifacts.base_certificate import SubjectInput
from certcrypt.artifacts.capacity_evidence import (
    MAX_SUBMISSION_SET_MEMBERS,
    SubmissionSetTooLargeError,
)
from certcrypt.client import CertcryptNodeClient
from certcrypt.issuer import Certcrypt, InMemoryLeafStore

_SEED = bytes(range(32))
_ROOT_FP = "aa" * 32


class FakeTransport:
    """Records every request body: the only place a wire regression is
    observable from the public surface."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {"method": method, "url": url, "body": json.loads(body) if body else None}
        )
        if not self._responses:
            # pytest.fail is a BaseException: the client cannot mistake it for a
            # transport error and retry it.
            pytest.fail(f"unexpected extra call: {method} {url}")
        status, text = self._responses.pop(0)
        return status, text, {}

    @property
    def issue_bodies(self):
        return [c["body"] for c in self.calls if c["url"].endswith("/v1/issue")]


def _fake_clock():
    """A clock whose sleeps advance it, so a retry never spends real time."""
    now = [0.0]
    return {
        "now_ms": lambda: now[0],
        "sleep": lambda seconds: now.__setitem__(0, now[0] + seconds * 1000),
    }


def _binding(root: str) -> dict:
    return {
        "level1_binding": {
            "system_id": "certcrypt",
            "system_root_fingerprint": _ROOT_FP,
            "rules_version": "rules/conformance",
            "authorized_role": "issuer",
            "authorization_issuer_kid": "kid-1",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "holder_key_set_root": root,
        },
        "level1_signature": {"alg": "stub", "mode": "AND", "signatures": [{"alg": "ML-DSA-65", "sig_b64": "c2ln"}]},
    }


def _issue_ok(count: int):
    """A node answer with one indexed result per submitted member."""
    return (
        200,
        json.dumps(
            {
                "request_id": "req-1",
                "submission_set_id": "set-1",
                "results": [
                    {
                        "operation_id": f"op-{i}",
                        "commitment_index": i,
                        "state": {
                            "state": "accepted",
                            "upstream_operation_id": f"up-{i}",
                        },
                    }
                    for i in range(count)
                ],
            }
        ),
    )


def _activated(responses, **kw):
    transport = FakeTransport(responses)
    client = CertcryptNodeClient(
        "https://node.example", transport=transport, retry_base_ms=0, **_fake_clock()
    )
    sdk = Certcrypt(
        node_base_url="https://node.example",
        keyset_seed=_SEED,
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        pool_id="pool-1",
        holder_id="holder-1",
        client=client,
        signed_level1=None,
        **kw,
    )
    sdk._signed_level1 = _binding(sdk.key_set.root)
    return sdk, transport


def _subject(text: str):
    return [SubjectInput("subject.binary/1", text.encode())]


# --------------------------------------------------------------------------
# the wire must not diverge between the two paths
# --------------------------------------------------------------------------


def test_prepared_commitment_reaches_the_wire_as_issue_sends_it():
    """Preparing then submitting must put on the wire what issue() puts there.

    Fields that are random or clock-derived per emission (nonce, salt) differ by
    design, so both runs are pinned to the same issued_at and subject, and what
    is compared is the commitment STRUCTURE plus the fields a verifier
    reproduces.
    """
    via_issue, t1 = _activated([_issue_ok(1)])
    via_issue.issue(subjects=_subject("hello"), issued_at="2026-01-01T00:00:00Z")

    via_prepare, t2 = _activated([_issue_ok(1)])
    prepared = via_prepare.prepare(
        subjects=_subject("hello"), issued_at="2026-01-01T00:00:00Z"
    )
    via_prepare.submit([prepared])

    assert len(t1.issue_bodies) == 1, "issue() sends exactly one request"
    assert len(t2.issue_bodies) == 1, "prepare()+submit() sends exactly one request"

    one = t1.issue_bodies[0]["commitments"][0]
    two = t2.issue_bodies[0]["commitments"][0]

    assert sorted(one.keys()) == sorted(two.keys())
    assert one["operative"] == two["operative"]

    ev1, ev2 = one["capacity_evidence"], two["capacity_evidence"]
    assert sorted(ev1.keys()) == sorted(ev2.keys())
    assert ev1["profile"] == ev2["profile"]

    # The projected commitment is what a verifier reproduces.
    pc1, pc2 = ev1["projected_commitment"], ev2["projected_commitment"]
    assert pc1["declared_effective_units"] == pc2["declared_effective_units"]
    assert pc1["issued_at"] == pc2["issued_at"]
    assert pc1["expires_at"] == pc2["expires_at"]
    assert pc1["consumed_quantity"] == pc2["consumed_quantity"]


# --------------------------------------------------------------------------
# N in one request — the point of the surface
# --------------------------------------------------------------------------


def test_n_prepared_commitments_travel_in_a_single_request():
    """N certificates, ONE request: N-in-one-request and synchronous, so the
    outbound request count is one no matter how many members travel."""
    sdk, transport = _activated([_issue_ok(3)])

    prepared = [
        sdk.prepare(subjects=_subject("one")),
        sdk.prepare(subjects=_subject("two")),
        sdk.prepare(subjects=_subject("three")),
    ]
    result = sdk.submit(prepared)

    assert len(transport.issue_bodies) == 1, "three certificates cost ONE request"
    assert len(transport.issue_bodies[0]["commitments"]) == 3

    # One handle per member, in input order, each carrying the operation the node
    # assigned to THAT member.
    assert [h.operation_id for h in result.handles] == ["op-0", "op-1", "op-2"]
    assert [h.commitment_index for h in result.handles] == [0, 1, 2]
    assert len(result.response.results) == 3

    # Each handle must reference its OWN emission: a batch where every handle
    # pointed at the same one would resolve three times to one operation and lose
    # the other two.
    assert len({h.independence_ref for h in result.handles}) == 3


def test_each_handle_carries_its_own_certificate():
    """The handle belongs to ONE emission — its certificate and evidence
    must be the ones that emission was signed with, not a neighbor's."""
    sdk, _ = _activated([_issue_ok(2)])
    a = sdk.prepare(subjects=_subject("alpha"))
    b = sdk.prepare(subjects=_subject("beta"))
    result = sdk.submit([a, b])

    assert result.handles[0].base_certificate == a.base_certificate
    assert result.handles[1].base_certificate == b.base_certificate
    assert result.handles[0].base_certificate != result.handles[1].base_certificate


# --------------------------------------------------------------------------
# the no-reuse invariant
# --------------------------------------------------------------------------


def test_unlinkable_prepared_commitments_never_repeat_a_leaf():
    """In unlinkable mode no leaf is ever used twice. A verifier cannot detect a
    repeat — nothing in the artifacts reveals it — so if grouping reused a leaf
    the unlinkability would be lost silently."""
    sdk, _ = _activated(
        [_issue_ok(4)],
        mode="unlinkable",
        tree_size=64,
        leaf_store=InMemoryLeafStore(),
    )

    prepared = [sdk.prepare(subjects=_subject(t)) for t in ("a", "b", "c", "d")]
    leaves = [p.leaf_index for p in prepared]

    assert len(set(leaves)) == len(leaves), f"leaves repeated: {leaves}"
    assert leaves == sorted(leaves), "allocation must be monotone"


def test_stable_mode_reuses_leaf_zero_by_design():
    """Stable mode reuses leaf 0 on purpose: leaf-reuse is a PRIVACY choice, not a
    protocol violation, so grouping in stable mode loses nothing."""
    sdk, _ = _activated([_issue_ok(3)])
    prepared = [sdk.prepare(subjects=_subject(t)) for t in ("a", "b", "c")]
    assert [p.leaf_index for p in prepared] == [0, 0, 0]


# --------------------------------------------------------------------------
# refusals that cost an error instead of a round-trip
# --------------------------------------------------------------------------


def test_submit_refuses_a_set_with_mixed_authorizations():
    """One submission set is one issuer under one authorization. Refused BEFORE
    the request is spent — the commitments are signed either way, but there is no
    reason to also burn the round-trip on a set the node will reject."""
    sdk, transport = _activated([])
    first = sdk.prepare(subjects=_subject("a"))
    second = sdk.prepare(subjects=_subject("b"))
    alien = type(second)(
        commitment=second.commitment,
        base_certificate=second.base_certificate,
        authorization_id="auth-from-somewhere-else",
        leaf_index=second.leaf_index,
        collections=second.collections,
    )

    with pytest.raises(ValueError, match="one issuer under one authorization"):
        sdk.submit([first, alien])
    assert transport.issue_bodies == [], "the mixed set never reaches the node"


def test_submit_refuses_an_empty_batch():
    sdk, _ = _activated([])
    with pytest.raises(ValueError, match="non-empty prepared list"):
        sdk.submit([])


# submission-set/1 §8.1: the producer refuses to build a set over the bound. The
# count is what is checked, so one prepared commitment repeated stands in for N
# distinct ones.


def test_submit_sends_a_set_of_exactly_the_bound():
    sdk, transport = _activated([_issue_ok(MAX_SUBMISSION_SET_MEMBERS)])
    one = sdk.prepare(subjects=_subject("bound"))
    result = sdk.submit([one] * MAX_SUBMISSION_SET_MEMBERS)
    assert len(transport.issue_bodies) == 1
    assert len(transport.issue_bodies[0]["commitments"]) == MAX_SUBMISSION_SET_MEMBERS
    assert len(result.handles) == MAX_SUBMISSION_SET_MEMBERS


def test_submit_refuses_one_over_the_bound_before_sending():
    sdk, transport = _activated([])
    one = sdk.prepare(subjects=_subject("over"))
    with pytest.raises(SubmissionSetTooLargeError) as excinfo:
        sdk.submit([one] * (MAX_SUBMISSION_SET_MEMBERS + 1))
    assert excinfo.value.count == MAX_SUBMISSION_SET_MEMBERS + 1
    assert transport.issue_bodies == [], "the over-bound set never reaches the node"


def test_prepare_validates_exactly_as_issue_does():
    """Both run the same method, so a refusal issue() makes must also come from
    prepare() — before anything is signed."""
    sdk, _ = _activated([])
    with pytest.raises(ValueError, match="non-empty subjects"):
        sdk.prepare(subjects=[])


# --------------------------------------------------------------------------
# issue() must be unchanged
# --------------------------------------------------------------------------


def test_issue_still_returns_a_complete_result():
    """issue() is prepare() + submit() with N=1, so its result must be
    unchanged. This is the regression guard on observable behavior."""
    sdk, transport = _activated([_issue_ok(1)])
    result = sdk.issue(subjects=_subject("hello"))

    assert len(transport.issue_bodies) == 1
    assert result.handle.operation_id == "op-0"
    assert result.handle.upstream_operation_id == "up-0"
    assert result.handle.commitment_index == 0
    assert result.handle.base_certificate, "the handle carries the signed certificate"
    assert result.handle.capacity_evidence, "and its capacity evidence"
    assert result.handle.independence_ref, "and the independence reference"
    assert result.commitment.capacity_evidence
    assert isinstance(result.authorization_id, str) and result.authorization_id
    assert result.collections == []
