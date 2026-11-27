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

"""The `Certcrypt` issuance surface.

The risks here are not cryptographic — that layer is already pinned by conformance
vectors. They are invariants about state:

  - two emissions must never share a leaf (unlinkability depends on it, and no
    verifier can detect a violation because none has global state);
  - a restart must not re-emit (that is what the handle exists for);
  - a certificate must not be minted with an expiry the verifier will reject.

These tests pin those decisions.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from certcrypt.artifacts.base_certificate import SubjectInput
from certcrypt.client import CertcryptNodeClient, CertcryptNodeError
from certcrypt.crypto.collection_merkle import CollectionLeafInput
from certcrypt.issuer import (
    BindingStoreEntry,
    Certcrypt,
    EmissionHandle,
    InMemoryLeafStore,
    SettlementPreferences,
    register_rules_domain,
    _sum_effective_units)

_SEED = bytes(range(32))
_ROOT_FP = "aa" * 32


class FakeTransport:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "body": json.loads(body) if body else None})
        if not self._responses:
            # pytest.fail is a BaseException: the client cannot mistake it for a
            # transport error and retry it.
            pytest.fail(f"unexpected extra call: {method} {url}")
        status, text = self._responses.pop(0)
        return status, text, {}


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


def _activate_ok(holder_id="h", pool_id="p", status="redeemed"):
    """A `POST /v1/activate` success body, in the shape the issuance service returns."""
    b = _binding("r")
    return json.dumps(
        {
            "authorization_id": "00" * 32,
            "holder_key_set_root": "r",
            "level1_binding": b["level1_binding"],
            "level1_signature": b["level1_signature"],
            "holder_id": holder_id,
            "pool_id": pool_id,
            "status": status,
        }
    )


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
    ))


def _issuer(responses, **kw):
    transport = FakeTransport(responses)
    client = CertcryptNodeClient(
        "https://node.example", transport=transport, retry_base_ms=0, **_fake_clock()
    )
    kw.setdefault("signed_level1", None)
    root = HolderRoot = None  # placeholder, resolved below
    sdk = Certcrypt(
        node_base_url="https://node.example",
        keyset_seed=_SEED,
        rules_version=kw.pop("rules_version", "rules/conformance"),
        system_id=kw.pop("system_id", "certcrypt"),
        system_root_fingerprint=kw.pop("system_root_fingerprint", _ROOT_FP),
        pool_id=kw.pop("pool_id", "pool-1"),
        holder_id=kw.pop("holder_id", "holder-1"),
        client=client,
        **kw)
    return sdk, transport


def _activated_issuer(responses, **kw):
    """An issuer already holding a binding, so no activation call is needed."""
    sdk, transport = _issuer(responses, **kw)
    sdk._signed_level1 = _binding(sdk.key_set.root)
    return sdk, transport


def _subjects():
    return [SubjectInput("subject.binary/1", b"invoice bytes")]


# --------------------------------------------------------------------------
# construction
# --------------------------------------------------------------------------


def test_unlinkable_mode_requires_a_leaf_store():
    """Without durable leaf bookkeeping, unlinkability is a claim, not a property."""
    with pytest.raises(ValueError, match="leaf_store"):
        Certcrypt(
            node_base_url="https://node.example",
            keyset_seed=_SEED,
            rules_version="rules/conformance",
            system_id="certcrypt",
            system_root_fingerprint=_ROOT_FP,
            mode="unlinkable")


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError, match="32 bytes"):
        Certcrypt(
            node_base_url="https://node.example",
            keyset_seed=b"\x01" * 31,
            rules_version="rules/conformance",
            system_id="certcrypt",
            system_root_fingerprint=_ROOT_FP)


def test_keyset_root_is_deterministic_from_the_seed():
    a, _ = _issuer([])
    b, _ = _issuer([])
    assert a.keyset_root() == b.keyset_root()


def test_stable_mode_uses_a_single_leaf_tree():
    sdk, _ = _issuer([])
    assert sdk.key_set.tree_size == 1


# --------------------------------------------------------------------------
# activation
# --------------------------------------------------------------------------


def test_activation_learns_holder_and_pool_and_caches_them():
    class Store:
        def __init__(self):
            self.saved = None

        def load(self):
            return None

        def save(self, entry):
            self.saved = entry

    store = Store()
    sdk, transport = _issuer(
        [(200, _activate_ok(holder_id="h-9", pool_id="p-9"))],
        integration_key="key-1",
        pool_id=None,
        holder_id=None,
        binding_store=store)
    sdk.activate()
    assert sdk._holder_id == "h-9"
    assert sdk._pool_id == "p-9"
    assert store.saved.holder_id == "h-9"
    assert transport.calls[0]["body"]["holder_key_set_root"] == sdk.key_set.root


def test_activation_is_idempotent():
    sdk, transport = _issuer(
        [(200, _activate_ok())],
        integration_key="key-1")
    sdk.activate()
    sdk.activate()
    assert len(transport.calls) == 1


def test_a_cached_binding_skips_the_round_trip():
    class Store:
        def load(self):
            return BindingStoreEntry(binding=_binding("r"), holder_id="h", pool_id="p")

        def save(self, entry):
            raise AssertionError("should not save when loading succeeded")

    sdk, transport = _issuer([], integration_key="key-1", binding_store=Store())
    sdk.activate()
    assert transport.calls == []
    assert sdk._holder_id == "h"


def test_a_failing_store_falls_back_to_activation():
    """A cache is an optimization; its failure must never be fatal."""

    class Store:
        def load(self):
            raise RuntimeError("store unavailable")

        def save(self, entry):
            raise RuntimeError("still unavailable")

    sdk, transport = _issuer(
        [(200, _activate_ok())],
        integration_key="key-1",
        binding_store=Store())
    sdk.activate()
    assert len(transport.calls) == 1


def test_no_binding_and_no_integration_key_is_a_clear_error():
    sdk, _ = _issuer([])
    with pytest.raises(CertcryptNodeError, match="integration_key"):
        sdk.ensure_activated()


# --------------------------------------------------------------------------
# issuance
# --------------------------------------------------------------------------


def test_issue_mints_and_submits(monkeypatch):
    sdk, transport = _activated_issuer([_ISSUE_OK])
    result = sdk.issue(subjects=_subjects())

    assert result.handle.operation_id == "op-1"
    assert result.handle.upstream_operation_id == "up-1"
    # The signed certificate travels in the handle: it is what makes the emission
    # verifiable against the original material later.
    assert result.handle.base_certificate["schema"] == "certcrypt-certificate"
    body = transport.calls[0]["body"]
    # The canonical member: exactly what the protocol needs and can verify
    # (submission-set/1 §7.1).
    assert set(body["commitments"][0]) == {"capacity_evidence", "operative"}
    assert body["commitments"][0]["operative"] == {
        "holder_id": "holder-1",
        "pool_id": "pool-1",
    }


def test_issue_requires_a_non_empty_subject_set():
    sdk, _ = _activated_issuer([])
    with pytest.raises(ValueError, match="non-empty"):
        sdk.issue(subjects=[])


def test_issue_refuses_an_empty_system_id():
    """An empty system_id signs fine and every conformant verifier REJECTS it."""
    sdk, _ = _activated_issuer([], system_id="")
    with pytest.raises(ValueError, match="system_id"):
        sdk.issue(subjects=_subjects())


def test_issue_refuses_an_unknown_rules_version_without_an_explicit_ttl():
    """Refused at construction rather than at issue().

    A TTL guard would catch this case only when no TTL was supplied. The
    rules-domain guard catches it in every case, and does so before a signing key is derived or
    capacity is touched — so an artifact never comes into existence to be mistaken
    for a valid one.
    """
    with pytest.raises(ValueError, match="does not implement rules_version"):
        _activated_issuer([_ISSUE_OK], rules_version="rules/invented")


# ---------------------------------------------------------------------------
# Runtime rules-domain registration
#
# A deployment may run under a rules domain it registers at runtime instead of
# one from the SDK's built-in list. The domain then comes from whoever runs the
# SDK.
#
# What these tests pin is that the escape hatch did NOT become a hole: an
# unregistered domain is still refused, and the refusal still lands at
# construction, before a key is derived.
# ---------------------------------------------------------------------------


def test_an_unregistered_rules_domain_is_still_refused():
    """The load-bearing case.

    Adding a registry could have turned the gate into a formality; it did not.
    Registering one domain says nothing about any other.
    """
    register_rules_domain("rules/some-other-deployment")
    with pytest.raises(ValueError, match="does not implement rules_version"):
        _activated_issuer([_ISSUE_OK], rules_version="rules/still-unknown")


def test_a_registered_rules_domain_passes_the_construction_gate():
    register_rules_domain("rules/test-deployment")
    sdk, _ = _activated_issuer([_ISSUE_OK], rules_version="rules/test-deployment")
    assert sdk is not None


def test_registration_refuses_input_that_is_not_a_rules_domain():
    """Not cosmetic: `rules_version` travels inside signed artifacts.

    A malformed one produces a signature over a claim nobody can resolve.
    """
    with pytest.raises(ValueError, match="non-empty"):
        register_rules_domain("")
    with pytest.raises(ValueError, match='must start with "rules/"'):
        register_rules_domain("2026-01")


def test_an_explicit_ttl_does_not_unblock_an_unknown_rules_version():
    """An explicit TTL is not enough to emit under any rules_version.

    Deliberately. The TTL is only the last missing parameter; supplying it does
    not make this SDK an implementation of the rules domain being claimed. Emitting under rules it does not implement
    produces artifacts that verify perfectly and attest to behavior that never
    happened — the one failure no verifier can detect (rules-domain/1 §14.2).
    A deployment that needs another domain registers it with
    `register_rules_domain` and states the TTL.
    """
    with pytest.raises(ValueError, match="does not implement rules_version"):
        _activated_issuer(
            [_ISSUE_OK], rules_version="rules/invented", commitment_ttl_seconds=3600
        )


def test_expires_at_follows_the_domain_ttl():
    sdk, _ = _activated_issuer([_ISSUE_OK])
    result = sdk.issue(
        subjects=_subjects(), issued_at="2026-05-09T12:00:00Z"
    )
    # rules/conformance TTL is 30 days.
    assert (
        result.commitment.capacity_evidence["projected_commitment"]["expires_at"]
        == "2026-06-08T12:00:00Z"
    )


def test_unlinkable_mode_consumes_a_fresh_leaf_per_emission():
    """Reusing a leaf makes two commitments linkable by key."""
    store = InMemoryLeafStore()
    sdk, _ = _activated_issuer(
        [_ISSUE_OK, _ISSUE_OK], mode="unlinkable", tree_size=8, leaf_store=store
    )
    first = sdk.issue(subjects=_subjects())
    second = sdk.issue(subjects=_subjects())
    assert first.handle.capacity_evidence["operation_key"]["leaf_index"] == 0
    assert second.handle.capacity_evidence["operation_key"]["leaf_index"] == 1


def test_each_emission_gets_a_fresh_salt_and_nonce():
    sdk, _ = _activated_issuer([_ISSUE_OK, _ISSUE_OK])
    a = sdk.issue(subjects=_subjects())
    b = sdk.issue(subjects=_subjects())
    assert (
        a.handle.capacity_evidence["operation_salt_hex"]
        != b.handle.capacity_evidence["operation_salt_hex"]
    )
    assert (
        a.handle.base_certificate["payload"]["anchor"]["nonce_hex"]
        != b.handle.base_certificate["payload"]["anchor"]["nonce_hex"]
    )


def test_collections_are_returned_and_must_be_persisted():
    sdk, _ = _activated_issuer([_ISSUE_OK])
    result = sdk.issue(
        subjects=[
            SubjectInput(
                "subject.collection/1",
                leaves=[
                    CollectionLeafInput("subject.binary/1", b"a"),
                    CollectionLeafInput("subject.binary/1", b"b"),
                ])
        ])
    assert len(result.collections) == 1
    assert len(result.collections[0].leaf_hashes) == 2
    assert result.handle.collections == result.collections


def test_settlement_preferences_are_operational_only():
    """They must never reach the signed evidence."""
    sdk, _ = _activated_issuer([_ISSUE_OK])
    result = sdk.issue(
        subjects=_subjects(),
        settlement_preferences=SettlementPreferences("fast"))
    assert "fast" not in json.dumps(result.commitment.capacity_evidence)


# --------------------------------------------------------------------------
# effective units
# --------------------------------------------------------------------------


def test_effective_units_count_subjects_and_collection_cardinality():
    assert _sum_effective_units(_subjects()) == "1"
    assert (
        _sum_effective_units(
            [
                SubjectInput("subject.binary/1", b"a"),
                SubjectInput("subject.text/1", b"b\r\n"),
            ]
        )
        == "2"
    )
    assert (
        _sum_effective_units(
            [
                SubjectInput(
                    "subject.collection/1",
                    leaves=[CollectionLeafInput("subject.binary/1", b"x")] * 3)
            ]
        )
        == "3"
    )


def test_effective_units_read_declared_cardinality_from_material():
    material = json.dumps({"declared_cardinality": "7"}).encode("utf-8")
    assert (
        _sum_effective_units([SubjectInput("subject.collection/1", material)]) == "7"
    )


def test_malformed_collection_counts_as_one():
    """The node re-derives and rejects a mismatch; never crash the issuance here."""
    assert _sum_effective_units([SubjectInput("subject.collection/1", b"not json")]) == "1"


# --------------------------------------------------------------------------
# resolve_emission
# --------------------------------------------------------------------------


def _handle() -> EmissionHandle:
    return EmissionHandle(
        operation_id="op-1",
        independence_ref="ab" * 32,
        commitment_index=0,
        capacity_evidence={"profile": "zero-data.unlinkable"},
        base_certificate={"schema": "certcrypt-certificate"})


def test_resolve_reports_pending_without_re_emitting():
    sdk, transport = _activated_issuer(
        [(200, '{"operation_id":"op-1","state":{"state":"processing"}}')]
    )
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert all(c["method"] == "GET" for c in transport.calls)


def test_pending_surfaces_the_settlement_window():
    """A reconciler schedules on this instead of polling blindly.

    Without it an integrator can only guess when to call back.
    """
    body = json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "processing"},
            "settlement_window": {
                "window_profile": "std",
                "window_profile_version": "v1",
                "target_close_by": "2099-01-01T00:00:00Z",
            },
        }
    )
    sdk, _ = _activated_issuer([(200, body)])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert resolution.settlement_window is not None
    assert resolution.settlement_window.target_close_by == "2099-01-01T00:00:00Z"
    # The target is in the future, so the operation is not late.
    assert resolution.overdue is False


def test_pending_reports_overdue_once_the_window_has_passed():
    """"Running late" must be distinguishable from "not ready yet"."""
    body = json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "processing"},
            "settlement_window": {
                "window_profile": "std",
                "window_profile_version": "v1",
                "target_close_by": "2020-01-01T00:00:00Z",
            },
        }
    )
    sdk, _ = _activated_issuer([(200, body)])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert resolution.overdue is True


def _pending_body(target, expected):
    return json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "processing"},
            "settlement_window": {
                "window_profile": "std",
                "window_profile_version": "v1",
                "target_close_by": target,
                "expected_settled_by": expected,
            },
        }
    )


def test_pending_surfaces_the_expected_settlement_instant():
    body = _pending_body("2099-01-01T00:00:00Z", "2099-01-01T00:00:15Z")
    sdk, _ = _activated_issuer([(200, body)])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert resolution.settlement_window.expected_settled_by == "2099-01-01T00:00:15Z"
    assert resolution.overdue is False


def test_pending_is_not_overdue_between_the_close_and_the_expected_settlement_instant():
    """A window that has closed but is still being anchored is on time."""
    now = datetime.now(timezone.utc)
    close = (now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expected = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sdk, _ = _activated_issuer([(200, _pending_body(close, expected))])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert resolution.overdue is False


def test_pending_reports_overdue_once_the_expected_settlement_instant_has_passed():
    body = _pending_body("2020-01-01T00:00:00Z", "2020-01-01T00:00:15Z")
    sdk, _ = _activated_issuer([(200, body)])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "pending"
    assert resolution.overdue is True


def test_pending_without_a_window_is_not_overdue():
    """No estimate is not the same as a missed one."""
    sdk, _ = _activated_issuer(
        [(200, '{"operation_id":"op-1","state":{"state":"processing"}}')]
    )
    resolution = sdk.resolve_emission(_handle())
    assert resolution.settlement_window is None
    assert resolution.overdue is False


def test_the_window_carries_only_scheduling_fields():
    """The parsed window exposes exactly the scheduling fields, nothing else."""
    body = json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "processing"},
            "settlement_window": {
                "window_profile": "std",
                "window_profile_version": "v1",
                "target_close_by": "2099-01-01T00:00:00Z",
                "vendor_note": "unexpected",
            },
        }
    )
    sdk, _ = _activated_issuer([(200, body)])
    window = sdk.resolve_emission(_handle()).settlement_window
    assert sorted(vars(window)) == [
        "expected_settled_by",
        "target_close_by",
        "window_profile",
        "window_profile_version",
    ]


def test_resolve_reports_rejected_terminally():
    sdk, _ = _activated_issuer(
        [(200, '{"operation_id":"op-1","state":{"state":"rejected","reason_code":"x"}}')]
    )
    assert sdk.resolve_emission(_handle()).state == "rejected"


def test_resolve_builds_the_package_when_ready():
    import base64 as b64

    proof = {"consumed_commitment_ids": ["c-1", "c-2"], "subtree_root": "cd" * 32}
    body = json.dumps(
        {
            "operation_id": "op-1",
            "state": {"state": "independent_ready"},
            "independence_proof": b64.b64encode(json.dumps(proof).encode()).decode(),
            "settlement_material": b64.b64encode(b'{"settlement_profile_id":"x"}').decode(),
        }
    )
    sdk, _ = _activated_issuer([(200, body), (200, body)])
    resolution = sdk.resolve_emission(_handle())
    assert resolution.state == "independent"
    package = resolution.verification_package
    assert package["commitment_inclusion_proof"]["commitment_id"] == "c-1"
    assert package["base_certificate"]["schema"] == "certcrypt-certificate"
    assert resolution.independence_ref == "ab" * 32


def test_handle_round_trips_through_serialization():
    """A handle is persisted as an opaque blob and read back after a restart."""
    handle = _handle()
    restored = EmissionHandle.from_dict(json.loads(json.dumps(handle.to_dict())))
    assert restored.operation_id == handle.operation_id
    assert restored.independence_ref == handle.independence_ref
    assert restored.base_certificate == handle.base_certificate


def test_handle_carries_no_secret():
    """It sits next to the certificate, so it must be safe to store."""
    blob = json.dumps(_handle().to_dict())
    assert "secret" not in blob.lower()
    assert "seed" not in blob.lower()


def test_settlement_preferences_use_the_nodes_snake_case_contract():
    """The node deserializes `window_profile`/`fallback_policy` under exactly
    these names. camelCase keys deserialize to
    None and the emission silently falls back to the default window, so the
    issuer's elected profile is lost with no error. Pin the key names."""
    wire = SettlementPreferences("close_6h", "slower_allowed").to_wire()
    assert wire == {
        "window_profile": "close_6h",
        "fallback_policy": "slower_allowed",
    }
    assert "windowProfile" not in wire and "fallbackPolicy" not in wire


def test_issue_actually_sends_the_elected_window():
    """`issuer.issue()` accepted settlement_preferences and dropped it: the only
    submit call passed commitments alone, so to_wire() was never reached."""
    import inspect

    from certcrypt import client as client_mod

    sig = inspect.signature(client_mod.CertcryptNodeClient.issue)
    assert "settlement_preferences" in sig.parameters, (
        "client.issue() must accept the preferences, or issuer.issue() has "
        "nowhere to forward them and the elected window is silently dropped"
    )

    transport = FakeTransport([_ISSUE_OK])
    c = client_mod.CertcryptNodeClient(
        base_url="http://n", transport=transport, **_fake_clock()
    )

    class _C:
        def to_wire(self):
            return {"x": 1}

    c.issue([_C()], settlement_preferences=SettlementPreferences("close_6h"))
    assert transport.calls[0]["body"]["settlement_preferences"] == {
        "window_profile": "close_6h",
        "fallback_policy": "reject",
    }
