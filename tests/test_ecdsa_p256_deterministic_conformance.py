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

"""The ECDSA P-256 signature itself, against the contract.

Conformance family `ecdsa-p256-deterministic`: SHA3-256 prehash, RFC 6979
nonce with HMAC-SHA3-256, low-s, raw r||s. Every verifier accepts any valid
low-s signature, so a nonce that drifts never fails a verification; it only
makes this SDK's signatures stop being reproducible. Exact equality is the only
check that sees it, so every signature here is compared byte for byte.
"""

import base64
import json
from pathlib import Path

import pytest

from certcrypt import derive_issuer_key
from certcrypt.crypto.composite import CompositeSigningKey, composite_sign_p256
from certcrypt.crypto.ecdsa_p256 import (
    private_key_from_scalar,
    public_key_sec1_uncompressed_b64,
    sign_ecdsa_p256_raw,
    signing_key_from_seed,
    verify_ecdsa_p256_raw,
)
from certcrypt.crypto.ml_dsa import keygen_ml_dsa65

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "ecdsa-p256-deterministic"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not _VECTORS.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_VECTORS})"
    ),
)


def _doc() -> dict:
    return json.loads(_VECTORS.read_text("utf-8"))


def _vectors() -> list:
    return _doc()["vectors"] if _VECTORS.exists() else []


def _composite_cases() -> list:
    return _doc()["composite_cases"] if _VECTORS.exists() else []


def _key_of(k: dict):
    """The key a vector names, derived the way this SDK derives it in use."""
    if k["source"] == "issuer-key-derivation":
        return derive_issuer_key(k["master_seed_hex"], "conformance").p256_private
    if k["source"] == "key-derivation":
        return signing_key_from_seed(bytes.fromhex(k["seed_hex"]))
    if k["source"] == "scalar":
        return private_key_from_scalar(bytes.fromhex(k["scalar_hex"]))
    raise ValueError(f"unknown key source {k['source']}")


def test_the_profile_is_the_one_this_sdk_implements():
    assert _doc()["profile"] == "ecdsa-p256-deterministic/1"


def test_every_key_derives_the_contracts_public_key():
    for ref, k in _doc()["keys"].items():
        assert public_key_sec1_uncompressed_b64(_key_of(k)) == k["expected_pub_p256_b64"], ref
        # The written-out scalar is the same key: signing from it must not differ.
        scalar_key = private_key_from_scalar(bytes.fromhex(k["scalar_hex"]))
        assert public_key_sec1_uncompressed_b64(scalar_key) == k["expected_pub_p256_b64"], ref


@pytest.mark.parametrize("v", _vectors(), ids=lambda v: v["name"])
def test_every_signature_matches_the_contract_byte_for_byte(v):
    k = _doc()["keys"][v["key"]]
    msg = bytes.fromhex(v["message_hex"])
    if "message_utf8" in v:
        assert v["message_utf8"].encode("utf-8") == msg
    sig = sign_ecdsa_p256_raw(_key_of(k), msg)
    assert sig.hex() == v["expected_sig_hex"]
    assert base64.b64encode(sig).decode("ascii") == v["expected_sig_b64"]
    assert verify_ecdsa_p256_raw(k["expected_pub_p256_b64"], msg, sig)
    # Signing again changes nothing: there is no nonce left to vary.
    assert sign_ecdsa_p256_raw(_key_of(k), msg) == sig


def test_both_low_s_branches_are_exercised():
    flags = [v["expected_low_s_applied"] for v in _vectors()]
    assert True in flags and False in flags


@pytest.mark.parametrize("c", _composite_cases(), ids=lambda c: c["name"])
def test_the_composite_ecdsa_component_goes_on_the_wire_exactly(c):
    doc = _doc()
    # ML-DSA-65 is not pinned by this family; any secret key serves.
    _, mldsa_secret = keygen_ml_dsa65(bytes(32))
    wire = composite_sign_p256(
        c["payload_canon_digest_hex"],
        CompositeSigningKey(p256_private=_key_of(doc["keys"][c["key"]]), mldsa_secret=mldsa_secret),
    )
    assert wire["alg"] == c["composite_alg_id"]
    assert wire["signatures"][0] == c["expected_ecdsa_component"]
