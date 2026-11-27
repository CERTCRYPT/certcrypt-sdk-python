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

"""`POST /v1/activate`: the request this SDK sends and how it reads the answer.

The request schema is closed: a body with one field too many or too few does not
match it. These tests pin
the exact field set, the signed possession message, the validity window, the
response parsing (including the idempotent `already_consumed_same_root` replay),
the resolution order (memory, then store, then network) and the error codes an
operator has to act on. The ML-DSA-65 possession signature is hedged, so it is
verified rather than compared.
"""

import base64
import json

import pytest

from certcrypt import ActivationResult, BindingStoreEntry, Certcrypt, CertcryptNodeClient
from certcrypt.client import CertcryptNodeError
from certcrypt.crypto.merkle import compute_leaf_hash, verify_inclusion_proof
from certcrypt.crypto.ml_dsa import verify_ml_dsa65
from certcrypt.issuer import FAR_FUTURE

_SEED = bytes(range(32))
_ROOT_FP = "aa" * 32
_KEY = "integration-key-1"

#: The keyset root of `_SEED` (tree size 1). Pinned so a change in key
#: derivation shows up here as well as in the key-derivation vectors.
_ROOT = "d25b43f473b0b724dfe20a98268a9171a9cb8f2de976337abb6cf939ba311fee"

#: The server's activation request, field for field. Unknown fields are denied.
_ACTIVATE_FIELDS = [
    "code",
    "holder_key_set_root",
    "key_set_disclosure",
    "key_set_possession_b64",
    "rules_version",
    "system_root_fingerprint",
    "valid_until",
]
_DISCLOSURE_FIELDS = ["leaf_index", "public_key_b64", "inclusion_proof", "tree_size"]

_LEVEL1_BINDING = {
    "system_id": "certcrypt",
    "rules_version": "rules/conformance",
    "system_root_fingerprint": _ROOT_FP,
    "authorized_role": "issuer",
    "authorization_issuer_kid": "kid-1",
    # Fixed by the issuance service and read from the answer, never sent.
    "valid_from": "2026-10-25T12:00:00Z",
    "valid_until": FAR_FUTURE,
    "holder_key_set_root": _ROOT,
}
_LEVEL1_SIGNATURE = {
    "alg": "composite",
    "mode": "AND",
    "signatures": [{"alg": "ML-DSA-65", "sig_b64": "c2ln"}],
}


def _activate_body(status="redeemed", holder_id="holder-bound", pool_id="pool-bound", **extra):
    body = {
        "authorization_id": "11" * 32,
        "holder_key_set_root": _ROOT,
        "level1_binding": _LEVEL1_BINDING,
        "level1_signature": _LEVEL1_SIGNATURE,
        "holder_id": holder_id,
        "pool_id": pool_id,
        "status": status,
    }
    body.update(extra)
    return json.dumps(body)


class _Transport:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "raw": body,
                "body": json.loads(body) if body else None,
            }
        )
        if not self._responses:
            pytest.fail(f"unexpected extra call: {method} {url}")
        status, text = self._responses.pop(0)
        return status, text, {}


class _Store:
    def __init__(self, entry=None, fail_load=False):
        self.entry = entry
        self.fail_load = fail_load
        self.saved = []

    def load(self):
        if self.fail_load:
            raise RuntimeError("store unavailable")
        return self.entry

    def save(self, entry):
        self.saved.append(entry)


def _issuer(responses, **kw):
    transport = _Transport(responses)
    client = CertcryptNodeClient("https://node.example", transport=transport, retry_base_ms=0)
    sdk = Certcrypt(
        node_base_url="https://node.example",
        keyset_seed=kw.pop("keyset_seed", _SEED),
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint=_ROOT_FP,
        integration_key=kw.pop("integration_key", _KEY),
        client=client,
        **kw,
    )
    return sdk, transport


# --------------------------------------------------------------------------
# the request
# --------------------------------------------------------------------------


def test_the_request_carries_exactly_the_fields_the_server_accepts():
    sdk, transport = _issuer([(200, _activate_body())])
    sdk.activate()

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://node.example/v1/activate"
    # Exact set AND order, as the receiving service accepts them.
    assert list(call["body"]) == _ACTIVATE_FIELDS
    assert list(call["body"]["key_set_disclosure"]) == _DISCLOSURE_FIELDS
    # A field outside the specified set is never sent.
    assert "integration_key" not in call["body"]
    # No issuer proof exists before activation, and none is sent.
    assert "x-certcrypt-issuer-auth" not in call["headers"]


def test_the_request_values():
    sdk, transport = _issuer([(200, _activate_body())])
    sdk.activate()
    body = transport.calls[0]["body"]

    assert sdk.keyset_root() == _ROOT
    assert body["code"] == _KEY
    assert body["holder_key_set_root"] == _ROOT
    assert body["rules_version"] == "rules/conformance"
    assert body["system_root_fingerprint"] == _ROOT_FP
    assert body["key_set_disclosure"] == sdk.key_set.disclosure(0).to_wire()


def test_the_disclosure_is_a_member_of_the_root_being_bound():
    sdk, transport = _issuer([(200, _activate_body())])
    sdk.activate()
    d = transport.calls[0]["body"]["key_set_disclosure"]

    leaf = compute_leaf_hash(base64.b64decode(d["public_key_b64"]))
    assert verify_inclusion_proof(
        leaf, d["leaf_index"], d["inclusion_proof"], _ROOT, d["tree_size"]
    )


def test_possession_is_signed_over_the_exact_activate_message():
    sdk, transport = _issuer([(200, _activate_body())])
    sdk.activate()
    body = transport.calls[0]["body"]
    pk = base64.b64decode(body["key_set_disclosure"]["public_key_b64"])
    sig = base64.b64decode(body["key_set_possession_b64"])

    message = f"certcrypt:activate:1|{_KEY}|{_ROOT}".encode("utf-8")
    assert message == (
        b"certcrypt:activate:1|integration-key-1|"
        b"d25b43f473b0b724dfe20a98268a9171a9cb8f2de976337abb6cf939ba311fee"
    )
    assert verify_ml_dsa65(pk, message, sig)
    # Both halves are bound: the signature is worthless for another code or root.
    assert not verify_ml_dsa65(pk, f"certcrypt:activate:1|other|{_ROOT}".encode(), sig)
    assert not verify_ml_dsa65(pk, f"certcrypt:activate:1|{_KEY}|{'00' * 32}".encode(), sig)
    # And for the read domain the same key also signs.
    assert not verify_ml_dsa65(pk, f"certcrypt:read:2|{_KEY}|{_ROOT}".encode(), sig)


def test_the_request_never_carries_a_start_and_replays_are_identical():
    """The issuance service fixes `valid_from` (the activation instant, never
    before the Level-1 key) and answers a replay with the bound authorization,
    so the request has nothing to choose and a restart sends the same body."""
    first, t1 = _issuer([(200, _activate_body())])
    second, t2 = _issuer([(200, _activate_body(status="already_consumed_same_root"))])
    first.activate()
    second.activate()
    a, b = t1.calls[0]["body"], t2.calls[0]["body"]

    assert "valid_from" not in a and "valid_from" not in b
    assert a["valid_until"] == b["valid_until"] == "2100-01-01T00:00:00Z"
    # Everything but the hedged signature is byte-identical on replay.
    strip = lambda d: {k: v for k, v in d.items() if k != "key_set_possession_b64"}
    assert strip(a) == strip(b)


def test_a_configured_valid_until_is_sent_verbatim():
    sdk, transport = _issuer(
        [(200, _activate_body())],
        valid_until="2036-01-01T00:00:00Z",
    )
    sdk.activate()
    body = transport.calls[0]["body"]
    assert body["valid_until"] == "2036-01-01T00:00:00Z"


# --------------------------------------------------------------------------
# the response
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["redeemed", "already_consumed_same_root"])
def test_both_success_statuses_yield_the_binding(status):
    """`already_consumed_same_root` is the cold-restart path: the same key
    presented with the same root. It is a success, not a conflict."""
    sdk, _ = _issuer([(200, _activate_body(status=status))])
    binding = sdk.activate()

    assert binding == {"level1_binding": _LEVEL1_BINDING, "level1_signature": _LEVEL1_SIGNATURE}
    assert sdk.binding() == binding


def test_client_activate_parses_the_response():
    transport = _Transport([(200, _activate_body(status="already_consumed_same_root"))])
    client = CertcryptNodeClient("https://node.example", transport=transport)
    res = client.activate(
        code="c",
        holder_key_set_root=_ROOT,
        key_set_disclosure={"leaf_index": 0},
        key_set_possession_b64="",
        rules_version="rules/conformance",
        system_root_fingerprint=_ROOT_FP,
        valid_until=FAR_FUTURE,
    )
    assert res == ActivationResult(
        signed_level1={"level1_binding": _LEVEL1_BINDING, "level1_signature": _LEVEL1_SIGNATURE},
        holder_id="holder-bound",
        pool_id="pool-bound",
        status="already_consumed_same_root",
    )


def test_the_bound_holder_overrides_a_configured_one_and_the_pool_does_not():
    sdk, _ = _issuer([(200, _activate_body())], holder_id="configured", pool_id="configured-pool")
    sdk.activate()
    assert sdk._holder_id == "holder-bound"
    assert sdk._pool_id == "configured-pool"


def test_a_missing_pool_is_learned():
    sdk, _ = _issuer([(200, _activate_body())])
    sdk.activate()
    assert sdk._pool_id == "pool-bound"


def test_a_response_without_the_binding_is_refused():
    body = json.loads(_activate_body())
    del body["level1_signature"]
    sdk, _ = _issuer([(200, json.dumps(body))])
    with pytest.raises(CertcryptNodeError, match="level1_signature"):
        sdk.activate()
    assert sdk.binding() is None


# --------------------------------------------------------------------------
# a 200 that is not an activation
#
# Four refusals, in this order: not a JSON object; a required field absent or
# empty; a field of the wrong type; a status other than the two successes. Each
# raises CertcryptNodeError with no HTTP status, and nothing is cached or
# persisted.
# --------------------------------------------------------------------------

_REQUIRED = ["level1_binding", "level1_signature", "holder_id", "pool_id"]
_EMPTY_VALUES = [None, "", {}, [], False, 0]


def _assert_refused_and_nothing_kept(text, message):
    store = _Store()
    sdk, transport = _issuer([(200, text), (200, text)], binding_store=store, holder_id="configured")
    with pytest.raises(CertcryptNodeError) as info:
        sdk.activate()
    assert str(info.value) == message
    assert info.value.status is None, "the request succeeded; the answer is what is wrong"
    assert sdk.binding() is None, "nothing cached in memory"
    assert store.saved == [], "nothing persisted"
    assert sdk._holder_id == "configured", "nothing half-adopted"
    # The next call goes back to the network instead of reusing a broken binding.
    with pytest.raises(CertcryptNodeError):
        sdk.activate()
    assert len(transport.calls) == 2


def _with(**changes):
    body = json.loads(_activate_body())
    body.update(changes)
    return json.dumps(body)


def _without(field):
    body = json.loads(_activate_body())
    del body[field]
    return json.dumps(body)


@pytest.mark.parametrize("field", _REQUIRED)
def test_a_200_without_a_required_field_is_refused(field):
    _assert_refused_and_nothing_kept(_without(field), f"activate returned no {field}")


@pytest.mark.parametrize("value", _EMPTY_VALUES, ids=repr)
@pytest.mark.parametrize("field", _REQUIRED)
def test_a_200_with_an_empty_required_field_is_refused(field, value):
    _assert_refused_and_nothing_kept(_with(**{field: value}), f"activate returned no {field}")


def test_every_missing_field_is_named_in_a_fixed_order():
    _assert_refused_and_nothing_kept(
        json.dumps({"status": "redeemed"}),
        "activate returned no level1_binding, level1_signature, holder_id, pool_id",
    )


@pytest.mark.parametrize("text", ["<html>bad gateway</html>", "[]", "null", '"ok"', ""])
def test_a_200_whose_body_is_not_a_json_object_is_refused(text):
    _assert_refused_and_nothing_kept(text, "activate returned no JSON object")


_SIG_COMPONENT = {"alg": "ML-DSA-65", "sig_b64": "c2ln"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("level1_binding", "a string"),
        ("level1_binding", ["a", "list"]),
        ("level1_binding", 7),
        ("level1_signature", "c2ln"),
        ("level1_signature", ["c2ln"]),
        ("level1_signature", {"alg": "composite", "mode": "AND", "signatures": []}),
        ("level1_signature", {"alg": "composite", "mode": "AND", "signatures": ["c2ln"]}),
        ("level1_signature", {"mode": "AND", "signatures": [_SIG_COMPONENT]}),
        ("level1_signature", {"alg": "composite", "signatures": [_SIG_COMPONENT]}),
        ("level1_signature", {"alg": "composite", "mode": "AND"}),
        ("level1_signature", {"alg": "composite", "mode": "AND", "signatures": [{"alg": "ML-DSA-65"}]}),
        ("level1_signature", {"alg": "composite", "mode": "AND", "signatures": [{"sig_b64": "c2ln"}]}),
        (
            "level1_signature",
            {"alg": "composite", "mode": "AND", "signatures": [{**_SIG_COMPONENT, "low_s": "yes"}]},
        ),
        (
            "level1_signature",
            {"alg": "composite", "mode": "AND", "signatures": [{**_SIG_COMPONENT, "encoding": 1}]},
        ),
        ("holder_id", 7),
        ("holder_id", True),
        ("holder_id", {"id": "h"}),
        ("pool_id", ["pool"]),
    ],
    ids=lambda v: v if isinstance(v, str) else json.dumps(v)[:40],
)
def test_a_200_with_a_field_of_the_wrong_type_is_refused(field, value):
    _assert_refused_and_nothing_kept(
        _with(**{field: value}), f"activate returned a malformed {field}"
    )


def test_every_malformed_field_is_named_in_a_fixed_order():
    _assert_refused_and_nothing_kept(
        _with(
            level1_binding="x",
            level1_signature="y",
            holder_id=1,
            pool_id=2,
        ),
        "activate returned a malformed level1_binding, level1_signature, holder_id, pool_id",
    )


@pytest.mark.parametrize(
    "status",
    [None, "", "rejected", "already_consumed", "REDEEMED", 1, ["redeemed"]],
    ids=repr,
)
def test_a_200_with_an_unrecognized_status_is_refused(status):
    _assert_refused_and_nothing_kept(
        _with(status=status), "activate returned an unrecognized status"
    )


def test_a_200_without_a_status_is_refused():
    _assert_refused_and_nothing_kept(_without("status"), "activate returned an unrecognized status")


def test_a_full_composite_signature_with_its_optional_members_is_accepted():
    signature = {
        "alg": "certcrypt-composite-p256-mldsa65-v1",
        "mode": "AND",
        "signatures": [
            {"alg": "ECDSA-P256-SHA3-256", "encoding": "raw-rs-64", "low_s": True, "sig_b64": "cg=="},
            {"alg": "ML-DSA-65", "sig_b64": "cQ=="},
        ],
    }
    sdk, _ = _issuer([(200, _with(level1_signature=signature))])
    assert sdk.activate()["level1_signature"] == signature


# --------------------------------------------------------------------------
# resolution order and persistence
# --------------------------------------------------------------------------


def test_activation_saves_the_binding_and_its_identifiers():
    store = _Store()
    sdk, _ = _issuer([(200, _activate_body())], binding_store=store)
    sdk.activate()

    assert store.saved == [
        BindingStoreEntry(
            binding={"level1_binding": _LEVEL1_BINDING, "level1_signature": _LEVEL1_SIGNATURE},
            holder_id="holder-bound",
            pool_id="pool-bound",
        )
    ]


def test_memory_first_then_store_then_network():
    cached = BindingStoreEntry(
        binding={"level1_binding": _LEVEL1_BINDING, "level1_signature": _LEVEL1_SIGNATURE},
        holder_id="holder-cached",
        pool_id="pool-cached",
    )
    store = _Store(entry=cached)
    sdk, transport = _issuer([], binding_store=store)

    sdk.activate()  # store hit: no network
    sdk.activate()  # memory hit: the store is not consulted again either
    assert transport.calls == []
    assert store.saved == []
    assert sdk._holder_id == "holder-cached"
    assert sdk._pool_id == "pool-cached"


def test_a_failing_store_load_falls_back_to_the_network():
    store = _Store(fail_load=True)
    sdk, transport = _issuer([(200, _activate_body())], binding_store=store)
    sdk.activate()
    assert len(transport.calls) == 1
    assert len(store.saved) == 1


def test_a_failing_store_save_is_not_fatal():
    class Store(_Store):
        def save(self, entry):
            raise RuntimeError("read-only")

    sdk, _ = _issuer([(200, _activate_body())], binding_store=Store())
    assert sdk.activate()["level1_binding"] == _LEVEL1_BINDING


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    ["integration_key_replaced", "key_set_root_already_bound"],
)
def test_named_refusals_surface_their_code_and_are_not_retried(code):
    problem = json.dumps({"error": code, "message": "refused", "request_id": None})
    sdk, transport = _issuer([(409, problem)])
    with pytest.raises(CertcryptNodeError) as info:
        sdk.activate()

    assert info.value.status == 409
    assert info.value.code == code
    assert str(info.value).startswith("activate failed: HTTP 409")
    assert len(transport.calls) == 1, "a refusal is never retried"
    assert sdk.binding() is None


def test_a_transient_failure_is_not_retried_either():
    sdk, transport = _issuer([(503, json.dumps({"error": "unavailable", "message": "x"}))])
    with pytest.raises(CertcryptNodeError) as info:
        sdk.activate()
    assert info.value.status == 503
    assert len(transport.calls) == 1


def test_no_binding_and_no_key_is_a_clear_error():
    sdk, transport = _issuer([], integration_key=None)
    with pytest.raises(CertcryptNodeError, match="integration_key"):
        sdk.activate()
    assert transport.calls == []
