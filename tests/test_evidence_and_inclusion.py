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

"""Capacity evidence and commitment inclusion.

Both modules break the protocol's usual "canonical means JCS" rule in one place
each, and both tests below exist to pin that:

  - the commitment leaf preimage is ordered JSON in INSERTION order;
  - the projected commitment is signed in INSERTION order, while the evidence
    digest that binds it uses JCS.

Reaching for the JCS helper in either spot produces artifacts that look
well-formed and verify against nothing.
"""

import base64
import json
from pathlib import Path

import pytest

from certcrypt.artifacts.capacity_evidence import (
    COMMITMENT_VERSION,
    ZERO_DATA_PROFILE,
    StableIdentifiers,
    assemble_evidence,
    evidence_digest_hex,
    projected_commitment_signing_bytes)
from certcrypt.artifacts.commitment_inclusion import (
    COMMITMENT_LEAF_VERSION,
    build_commitment_inclusion_proof,
    commitment_leaf_hash,
    commitment_subtree_root)
from certcrypt.artifacts.holder_keyset import HolderKeySet
from certcrypt.crypto.digest import digest_hex_bytes
from certcrypt.crypto.jcs import jcs_canonicalize_string
from certcrypt.crypto.merkle import compute_leaf_hash, verify_inclusion_proof
from certcrypt.crypto.ml_dsa import verify_ml_dsa65
from certcrypt.crypto.pseudonym import derive_pseudonym

_PRIMITIVES = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
)
_EVIDENCE_VECTORS = _PRIMITIVES / "capacity-evidence" / "vectors.json"


# --------------------------------------------------------------------------
# commitment inclusion
# --------------------------------------------------------------------------


def test_leaf_preimage_is_insertion_ordered_not_jcs():
    """`{"v":…,"commitment_id":…}` — alphabetical order would invert the members.

    JCS would emit commitment_id first, changing every leaf hash and breaking
    every proof, with nothing about the output looking wrong.
    """
    cid = "commit-1"
    expected_preimage = (
        '{"v":"' + COMMITMENT_LEAF_VERSION + '","commitment_id":"' + cid + '"}'
    )
    assert commitment_leaf_hash(cid) == compute_leaf_hash(
        expected_preimage.encode("utf-8")
    )
    # The JCS form is a different hash — asserted so a future refactor to the
    # "obvious" helper fails loudly here.
    jcs_form = jcs_canonicalize_string({"v": COMMITMENT_LEAF_VERSION, "commitment_id": cid})
    assert commitment_leaf_hash(cid) != compute_leaf_hash(jcs_form.encode("utf-8"))


def test_inclusion_proof_shape_and_self_verification():
    ids = [f"commit-{i}" for i in range(5)]  # odd width
    root = commitment_subtree_root(ids)
    for i in range(len(ids)):
        proof = build_commitment_inclusion_proof(ids, i)
        assert proof["commitment_id"] == ids[i]
        # Numeric fields travel as strings on the wire.
        assert proof["commitment_index"] == str(i)
        assert proof["subtree_size"] == "5"
        assert verify_inclusion_proof(
            proof["commitment_leaf_hash"],
            i,
            proof["commitment_siblings"],
            root,
            len(ids))


def test_commitment_order_is_load_bearing():
    """Re-sorting the ids produces a proof that verifies against nothing."""
    ids = ["b", "a", "c"]
    assert commitment_subtree_root(ids) != commitment_subtree_root(sorted(ids))


def test_inclusion_rejects_empty_and_out_of_range():
    with pytest.raises(ValueError):
        build_commitment_inclusion_proof([], 0)
    with pytest.raises(ValueError):
        commitment_subtree_root([])
    with pytest.raises(IndexError):
        build_commitment_inclusion_proof(["a", "b"], 2)


# --------------------------------------------------------------------------
# capacity evidence
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    not _EVIDENCE_VECTORS.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_EVIDENCE_VECTORS})"
    ))
def test_signing_bytes_match_published_vector():
    """The signed byte form is pinned by the contract, not inferred."""
    vector = json.loads(_EVIDENCE_VECTORS.read_text("utf-8"))
    got = projected_commitment_signing_bytes(vector["projected_commitment"])
    assert got.decode("utf-8") == vector["expected_signing_bytes_utf8"]
    assert digest_hex_bytes(got) == vector["expected_signing_bytes_digest"]


def test_signing_bytes_use_insertion_order_not_jcs():
    pc = {"commitment_version": COMMITMENT_VERSION, "a_last_alphabetically": "x"}
    signed = projected_commitment_signing_bytes(pc).decode("utf-8")
    assert signed.index("commitment_version") < signed.index("a_last_alphabetically")
    # JCS would put a_last_alphabetically first.
    assert signed != jcs_canonicalize_string(pc)


def test_evidence_digest_uses_jcs():
    evidence = {"z": "1", "a": "2"}
    assert evidence_digest_hex(evidence) == digest_hex_bytes(
        jcs_canonicalize_string(evidence).encode("utf-8")
    )


def _signed_level1(key_set: HolderKeySet) -> dict:
    return {
        "level1_binding": {
            "system_id": "certcrypt",
            "system_root_fingerprint": "aa" * 32,
            "rules_version": "rules/conformance",
            "authorized_role": "issuer",
            "authorization_issuer_kid": "kid-1",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "holder_key_set_root": key_set.root,
        },
        "level1_signature": {"alg": "stub", "mode": "AND", "signatures": [{"alg": "ML-DSA-65", "sig_b64": "c2ln"}]},
    }


@pytest.fixture
def key_set():
    return HolderKeySet.from_master_seed(bytes(range(32)), 4)


def _assemble(key_set, **kw):
    return assemble_evidence(
        signed_level1=kw.pop("signed_level1", _signed_level1(key_set)),
        certificate_commitment_digest=kw.pop("certificate_commitment_digest", "cc" * 32),
        consumed_quantity=kw.pop("consumed_quantity", "5.00"),
        declared_effective_units=kw.pop("declared_effective_units", "1"),
        issued_at=kw.pop("issued_at", "2026-05-09T12:00:00Z"),
        expires_at=kw.pop("expires_at", "2026-05-10T12:00:00Z"),
        stable=kw.pop(
            "stable", StableIdentifiers("holder-1", "pool-1", "authorization-1")
        ),
        key_set=key_set,
        leaf_index=kw.pop("leaf_index", 0),
        operation_salt=kw.pop("operation_salt", b"\x11" * 32))


def test_evidence_shape(key_set):
    ev = _assemble(key_set)
    assert ev["profile"] == ZERO_DATA_PROFILE
    assert ev["operation_salt_hex"] == "11" * 32
    assert ev["projected_commitment"]["commitment_version"] == COMMITMENT_VERSION
    assert ev["operation_key"]["leaf_index"] == 0
    assert ev["operation_key"]["tree_size"] == 4


def test_stable_identifiers_never_appear_in_the_evidence(key_set):
    """The point of the projection: no stable id may survive into the artifact."""
    ev = _assemble(key_set)
    blob = json.dumps(ev)
    for stable_id in ("holder-1", "pool-1", "authorization-1"):
        assert stable_id not in blob


def test_pseudonyms_match_the_derivation(key_set):
    salt = b"\x11" * 32
    ev = _assemble(key_set, operation_salt=salt)
    pc = ev["projected_commitment"]
    assert pc["holder_pseudonym"] == derive_pseudonym(salt, "holder", "holder-1")
    assert pc["pool_pseudonym"] == derive_pseudonym(salt, "pool", "pool-1")
    assert pc["authorization_pseudonym"] == derive_pseudonym(
        salt, "authorization", "authorization-1"
    )


def test_a_fresh_salt_makes_the_same_issuer_unlinkable(key_set):
    a = _assemble(key_set, operation_salt=b"\x11" * 32)
    b = _assemble(key_set, operation_salt=b"\x22" * 32, leaf_index=1)
    assert (
        a["projected_commitment"]["holder_pseudonym"]
        != b["projected_commitment"]["holder_pseudonym"]
    )


def test_commitment_signature_verifies_under_the_disclosed_leaf(key_set):
    ev = _assemble(key_set, leaf_index=2)
    pub = base64.b64decode(ev["operation_key"]["public_key_b64"])
    assert verify_ml_dsa65(
        pub,
        projected_commitment_signing_bytes(ev["projected_commitment"]),
        base64.b64decode(ev["commitment_signature_b64"]))


def test_disclosed_leaf_proves_membership_in_the_authorized_root(key_set):
    ev = _assemble(key_set, leaf_index=3)
    disclosure = ev["operation_key"]
    leaf_hash = compute_leaf_hash(base64.b64decode(disclosure["public_key_b64"]))
    assert verify_inclusion_proof(
        leaf_hash,
        disclosure["leaf_index"],
        disclosure["inclusion_proof"],
        ev["projected_authorization"]["holder_key_set_root"],
        disclosure["tree_size"])


def test_key_set_root_must_match_the_authorization(key_set):
    """Fail early rather than let the verifier reject a well-formed artifact."""
    wrong = _signed_level1(key_set)
    wrong["level1_binding"]["holder_key_set_root"] = "ff" * 32
    with pytest.raises(ValueError, match="does not match the authorized"):
        _assemble(key_set, signed_level1=wrong)


def test_leaf_index_out_of_range_is_refused(key_set):
    with pytest.raises(IndexError):
        _assemble(key_set, leaf_index=99)


def test_verify_inclusion_proof_fails_closed_on_shape():
    leaves = [compute_leaf_hash(bytes([k]) * 32) for k in range(4)]
    from certcrypt.crypto.merkle import compute_merkle_root, generate_inclusion_proof

    root = compute_merkle_root(leaves)
    proof = generate_inclusion_proof(leaves, 0)
    assert verify_inclusion_proof(leaves[0], 0, proof, root, 4)
    # Index at or past the tree, empty tree, non-integer index.
    assert not verify_inclusion_proof(leaves[3], 4, generate_inclusion_proof(leaves, 3), root, 4)
    assert not verify_inclusion_proof(leaves[0], 0, proof, root, 0)
    assert not verify_inclusion_proof(leaves[0], True, proof, root, 4)
    # Siblings that are not 64 lowercase hex, and an uppercase root.
    assert not verify_inclusion_proof(leaves[0], 0, [proof[0].upper(), proof[1]], root, 4)
    assert not verify_inclusion_proof(leaves[0], 0, ["zz" * 32, proof[1]], root, 4)
    assert not verify_inclusion_proof(leaves[0], 0, proof, root.upper(), 4)
