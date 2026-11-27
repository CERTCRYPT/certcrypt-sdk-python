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

"""The issuer authenticates every request and signs every read.

A node verifies an issuer OFFLINE: each request carries a self-verifying proof
(`x-certcrypt-issuer-auth`), and each read carries the issuer's half of the read
chain (`x-certcrypt-issuer-read`) over the exact resource read. Without them a
real node answers 401 to a submit, and an operation read can never be reconciled
with the server — the issuer would poll `accepted` forever.
"""

import base64
import re
import json

import pytest

from certcrypt.artifacts.base_certificate import SubjectInput
from certcrypt.client import CertcryptNodeClient
from certcrypt.issuer import Certcrypt, EmissionHandle

_SEED = bytes(range(32))
_ROOT_FP = "aa" * 32


class RecordingTransport:
    """Plays canned replies and records every request with its headers."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": dict(headers)})
        if not self._responses:
            pytest.fail(f"unexpected extra call: {method} {url}")
        status, text = self._responses.pop(0)
        return status, text, {}


def _binding(root: str) -> dict:
    return {
        "level1_binding": {
            "system_id": "certcrypt",
            "system_root_fingerprint": _ROOT_FP,
            "rules_version": "rules/conformance",
            "authorized_role": "issuer",
            "authorization_issuer_kid": "kid-1",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:00:00Z",
            "holder_key_set_root": root,
        },
        "level1_signature": {"alg": "x", "sig": "y"},
    }


def _issuer(responses):
    transport = RecordingTransport(responses)
    client = CertcryptNodeClient(
        "https://node.example",
        transport=transport,
        retry_base_ms=0,
        now_ms=lambda: 0.0,
        sleep=lambda _s: None,
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
    )
    sdk._signed_level1 = _binding(sdk.key_set.root)
    # Record what the leaf signs, so a test can see WHICH resource a proof covers.
    signed = []
    original = sdk.key_set.sign

    def recording_sign(leaf_index, message):
        signed.append(bytes(message).decode("utf-8"))
        return original(leaf_index, message)

    sdk.key_set.sign = recording_sign
    return sdk, transport, signed


def _decode(header: str) -> dict:
    return json.loads(base64.b64decode(header))


_ISSUE_OK = (
    200,
    json.dumps(
        {
            "request_id": "req-1",
            "submission_set_id": "set-1",
            "results": [
                {
                    "operation_id": "op-1",
                    "commitment_index": 0,
                    "state": {"state": "accepted", "upstream_operation_id": "up-1"},
                }
            ],
        }
    ),
)


def _read_of(resource, signed):
    """Whether a read:2 message over `resource` was signed (any challenge)."""
    return any(
        re.fullmatch(rf"certcrypt:read:2\|\d+\.[^|]+\|{re.escape(resource)}", m)
        for m in signed
    )


def test_every_read_carries_a_fresh_single_use_challenge():
    # The issuance service spends a read challenge on first use, so the node
    # that relays a half cannot keep it and read again on its own.
    sdk, transport, _ = _issuer(
        [
            _ISSUE_OK,
            (200, '{"operation_id":"op-1","state":{"state":"processing"}}'),
            (200, '{"operation_id":"op-1","state":{"state":"processing"}}'),
        ]
    )
    result = sdk.issue(subjects=[SubjectInput("subject.binary/1", b"x")])
    sdk.resolve_emission(result.handle)
    sdk.resolve_emission(result.handle)
    halves = [
        _decode(c["headers"]["x-certcrypt-issuer-read"])
        for c in transport.calls
        if "x-certcrypt-issuer-read" in c["headers"]
    ]
    assert len(halves) == 2
    for h in halves:
        assert set(h) == {"signed_level1", "disclosure", "challenge", "possession_b64"}
        millis, nonce = h["challenge"].split(".", 1)
        assert millis.isdigit() and nonce
    assert halves[0]["challenge"] != halves[1]["challenge"], "a challenge is never reused"


def test_every_submit_carries_a_fresh_self_verifying_proof():
    sdk, transport, _ = _issuer([_ISSUE_OK, _ISSUE_OK])
    sdk.issue(subjects=[SubjectInput("subject.binary/1", b"one")])
    sdk.issue(subjects=[SubjectInput("subject.binary/1", b"two")])
    proofs = [_decode(c["headers"]["x-certcrypt-issuer-auth"]) for c in transport.calls]
    for p in proofs:
        assert set(p) == {"signed_level1", "disclosure", "challenge", "possession_b64"}
        millis, nonce = p["challenge"].split(".", 1)
        assert millis.isdigit() and nonce, "the shape the node's freshness check parses"
    assert proofs[0]["challenge"] != proofs[1]["challenge"], "a challenge is single-use"


def test_an_operation_read_signs_the_upstream_id_the_server_routes_on():
    sdk, transport, signed = _issuer(
        [_ISSUE_OK, (200, '{"operation_id":"op-1","state":{"state":"processing"}}')]
    )
    result = sdk.issue(subjects=[SubjectInput("subject.binary/1", b"x")])
    signed.clear()
    sdk.resolve_emission(result.handle)
    read = transport.calls[-1]
    assert read["url"].endswith("/v1/operations/op-1"), "polled by the node-local id"
    assert "x-certcrypt-issuer-read" in read["headers"]
    assert _read_of("up-1", signed), "but the proof covers the upstream id"


def test_a_restored_handle_registers_its_upstream_id_before_reading():
    sdk, transport, signed = _issuer(
        [(200, '{"operation_id":"op-9","state":{"state":"processing"}}')]
    )
    handle = EmissionHandle(
        operation_id="op-9",
        upstream_operation_id="up-9",
        independence_ref="ab" * 32,
        commitment_index=0,
        capacity_evidence={"profile": "zero-data.unlinkable"},
        base_certificate={"schema": "certcrypt-certificate"},
    )
    sdk.resolve_emission(handle)
    assert _read_of("up-9", signed)


def test_a_late_member_is_learned_from_the_first_read_that_shows_it():
    # Submitted while the server was unreachable: the node handed out op-a with
    # no upstream id. The node delivered it later; the node's local record now
    # carries the upstream id, and the next read must sign it.
    sdk, _transport, signed = _issuer(
        [
            (200, '{"operation_id":"op-a","state":{"state":"accepted","upstream_operation_id":"up-a"}}'),
            (200, '{"operation_id":"op-a","state":{"state":"processing"}}'),
        ]
    )
    handle = EmissionHandle(
        operation_id="op-a",
        independence_ref="cd" * 32,
        commitment_index=0,
        capacity_evidence={"profile": "zero-data.unlinkable"},
        base_certificate={"schema": "certcrypt-certificate"},
    )
    sdk.resolve_emission(handle)
    assert _read_of("op-a", signed), "first read: only the local id is known"
    signed.clear()
    sdk.resolve_emission(handle)
    assert _read_of("up-a", signed), "second read: the learned upstream id"


def test_an_injected_client_with_its_own_providers_keeps_them():
    client = CertcryptNodeClient(
        "https://node.example",
        transport=RecordingTransport([]),
        issuer_auth_proof=lambda m, u, b: "mine",
    )
    Certcrypt(
        node_base_url="https://node.example",
        keyset_seed=_SEED,
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        client=client,
    )
    assert client._issuer_auth_proof("GET", "https://node.example/x", b"") == "mine"


def test_the_retry_budget_set_on_the_issuer_reaches_the_node_client():
    # A caller with a tight deadline sets a short budget; the option has to
    # arrive where retrying happens.
    sdk = Certcrypt(
        node_base_url="https://node.example",
        keyset_seed=_SEED,
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        retry_max_elapsed_ms=15_000,
        retry_max_attempts=3,
    )
    assert sdk.client._retry_policy.max_elapsed_ms == 15_000
    assert sdk.client._retry_policy.max_attempts == 3
