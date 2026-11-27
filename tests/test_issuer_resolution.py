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

"""What the issuer does with what it learned and with what it is told later:
the pool activation hands back, the terminal states a resolution can end in, the
verification context a package records, and the recovery read a process that
never emitted still has to authenticate.
"""

import base64
import json
from urllib.parse import urlparse

import pytest

from certcrypt import Certcrypt, CertcryptNodeClient, EmissionHandle, HolderKeySet, SubjectInput

_SEED = "11" * 32
_ROOT_FP = "ab" * 32
_RULES = "rules/conformance"
_KEY_SET_ROOT = HolderKeySet.from_master_seed(_SEED, 1).root


def _binding() -> dict:
    return {
        "level1_binding": {
            "system_id": "certcrypt",
            "rules_version": _RULES,
            "system_root_fingerprint": _ROOT_FP,
            "authorized_role": "issuer",
            "authorization_issuer_kid": "kid-l1",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:00:00Z",
            "holder_key_set_root": _KEY_SET_ROOT,
        },
        "level1_signature": {
            "alg": "composite",
            "mode": "AND",
            "signatures": [{"alg": "ML-DSA-65", "sig_b64": "c2ln"}],
        },
    }


def _activate() -> dict:
    return {
        **_binding(),
        "holder_id": "holder-1",
        "pool_id": "pool-learned",
        "status": "redeemed",
    }


class _Node:
    """A node routed by path; records every call in order."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []
        self.now = 0.0

    def transport(self, method, url, headers, body, timeout):
        self.calls.append(
            {"url": url, "headers": headers, "body": json.loads(body) if body else None}
        )
        for prefix, reply in self.routes.items():
            if prefix in url:
                status, payload = reply(url)
                return status, json.dumps(payload), {}
        pytest.fail(f"unexpected url {url}")

    def client(self):
        def sleep(seconds):
            self.now += seconds * 1000

        return CertcryptNodeClient(
            "http://node.test", transport=self.transport, now_ms=lambda: self.now, sleep=sleep
        )


def _bound_issuer(node, **kw):
    """An issuer already holding a binding, so resolution needs no activation call."""
    return Certcrypt(
        node_base_url="http://node.test",
        keyset_seed=_SEED,
        rules_version=_RULES,
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        pool_id="pool-1",
        holder_id="holder-1",
        signed_level1=_binding(),
        client=node.client(),
        **kw,
    )


def _handle() -> EmissionHandle:
    return EmissionHandle(
        operation_id="op-1",
        independence_ref="ab" * 32,
        commitment_index=0,
        capacity_evidence={"profile": "zero-data.unlinkable"},
        base_certificate={"schema": "certcrypt-certificate"},
    )


def _ready_body() -> dict:
    proof = {"consumed_commitment_ids": ["c-1", "c-2"], "subtree_root": "cd" * 32}
    return {
        "operation_id": "op-1",
        "state": {"state": "independent_ready"},
        "independence_proof": base64.b64encode(json.dumps(proof).encode()).decode(),
        "settlement_material": base64.b64encode(b'{"settlement_profile_id":"x"}').decode(),
    }


# --- the pool activation hands back ----------------------------------------------


def test_a_pool_learned_at_activation_reaches_the_commitment_when_none_is_configured():
    node = _Node(
        {
            "/v1/activate": lambda _u: (200, _activate()),
            "/v1/issue": lambda _u: (
                200,
                {
                    "request_id": "R",
                    "submission_set_id": "S",
                    "results": [
                        {"operation_id": "op-1", "commitment_index": 0, "state": {"state": "accepted"}}
                    ],
                },
            ),
        }
    )
    issuer = Certcrypt(
        node_base_url="http://node.test",
        keyset_seed=_SEED,
        integration_key="int-key-1",
        rules_version=_RULES,
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        client=node.client(),
    )
    res = issuer.issue(subjects=[SubjectInput("subject.text/1", b"hello\n")])
    assert res.commitment.operative == {"holder_id": "holder-1", "pool_id": "pool-learned"}
    sent = next(c for c in node.calls if "/v1/issue" in c["url"])["body"]
    assert sent["commitments"][0]["operative"]["pool_id"] == "pool-learned"


# --- terminal states ------------------------------------------------------------------


@pytest.mark.parametrize(
    "terminal",
    [
        "rejected",
        "insufficient_capacity",
        "replay_detected",
        "pre_evaluation_rejected",
        "submission_failed",
    ],
)
def test_resolve_emission_reports_the_terminal_state_as_rejected(terminal):
    node = _Node(
        {"/v1/operations/": lambda _u: (200, {"operation_id": "op-1", "state": {"state": terminal}})}
    )
    res = _bound_issuer(node).resolve_emission(_handle())
    assert (res.state, res.node_state) == ("rejected", terminal)


def test_resolve_emission_reports_expired_as_expired_with_its_reason():
    node = _Node(
        {
            "/v1/operations/": lambda _u: (
                200,
                {
                    "operation_id": "op-1",
                    "state": {"state": "expired", "reason_code": "commitment_window_expired"},
                },
            )
        }
    )
    res = _bound_issuer(node).resolve_emission(_handle())
    assert (res.state, res.node_state, res.reason_code) == (
        "expired",
        "expired",
        "commitment_window_expired",
    )


def test_resolve_emission_by_commitment_reports_insufficient_capacity_as_rejected():
    node = _Node(
        {
            "/v1/operations/": lambda _u: (404, {"error": "not_found"}),
            "/v1/emissions/by-commitment/": lambda _u: (
                200,
                {"operation_id": "op-1", "status": "insufficient_capacity"},
            ),
        }
    )
    res = _bound_issuer(node).resolve_emission(_handle())
    assert (res.state, res.node_state) == ("rejected", "insufficient_capacity")


def test_a_wait_that_ends_without_a_terminal_state_resolves_as_pending_not_as_an_error():
    node = _Node(
        {"/v1/operations/": lambda _u: (200, {"operation_id": "op-1", "state": {"state": "processing"}})}
    )
    res = _bound_issuer(node).resolve_emission(_handle(), interval_ms=1, max_attempts=2)
    assert res.state == "pending"


# --- the verification context the package records -----------------------------------


def test_the_package_records_this_instances_rules_version_and_system_id_by_default():
    node = _Node({"/v1/operations/": lambda _u: (200, _ready_body())})
    res = _bound_issuer(node).resolve_emission(_handle())
    assert res.state == "independent"
    assert res.verification_package["verification_context"] == {
        "rules_version": _RULES,
        "system_id": "certcrypt",
    }


def test_an_explicit_verification_context_wins_over_the_instances():
    node = _Node({"/v1/operations/": lambda _u: (200, _ready_body())})
    ctx = {"rules_version": "rules/2026-01", "system_id": "other"}
    res = _bound_issuer(node).resolve_emission(_handle(), verification_context=ctx)
    assert res.verification_package["verification_context"] == ctx


# --- recovery reads activate first --------------------------------------------------


def test_list_unresolved_emissions_activates_before_reading_so_the_read_is_signed():
    node = _Node(
        {
            "/v1/activate": lambda _u: (200, _activate()),
            "/v1/emissions/unresolved": lambda _u: (200, {"emissions": [], "truncated": False}),
        }
    )
    issuer = Certcrypt(
        node_base_url="http://node.test",
        keyset_seed=_SEED,
        integration_key="int-key-1",
        rules_version=_RULES,
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        client=node.client(),
    )
    page = issuer.list_unresolved_emissions("2026-01-01T00:00:00Z")
    assert page.emissions == [] and page.truncated is False
    assert [urlparse(c["url"]).path for c in node.calls] == [
        "/v1/activate",
        "/v1/emissions/unresolved",
    ]
    assert node.calls[1]["headers"].get("x-certcrypt-issuer-read")


# --- a persisted handle must say where its member sits --------------------------------


def test_a_persisted_handle_without_a_commitment_index_is_refused():
    """The index is a Merkle position. Defaulting a missing one to 0 would yield
    an inclusion proof that verifies against nothing."""
    data = _handle().to_dict()
    del data["commitment_index"]
    with pytest.raises(KeyError, match="commitment_index"):
        EmissionHandle.from_dict(data)
