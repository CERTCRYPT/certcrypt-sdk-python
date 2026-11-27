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

"""Pseudonyms and the holder operation-key tree, against published vectors.

Two separate byte contracts meet here, and the tests keep them apart on purpose:

  - the pseudonym framing, where a missing length prefix would let two different
    identities collide onto one pseudonym;
  - the holder-keyset Merkle, which uses 0x00/0x01 discriminators and is NOT the
    collection fold (that one uses ASCII tags and length prefixes). Swapping them
    produces a root that is wrong in a way no length check catches.
"""

import base64
import json
from pathlib import Path

import pytest

from certcrypt.artifacts.holder_keyset import HolderKeySet, OperationKey
from certcrypt.crypto.merkle import (
    compute_leaf_hash,
    compute_merkle_root,
    generate_inclusion_proof,
    verify_inclusion_proof)
from certcrypt.crypto.pseudonym import derive_pseudonym

_PRIMITIVES = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
)

pytestmark = pytest.mark.skipif(
    not _PRIMITIVES.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_PRIMITIVES})"
    ))


def _load(name: str) -> dict:
    return json.loads((_PRIMITIVES / name / "vectors.json").read_text("utf-8"))


def _pseudonym_vectors():
    path = _PRIMITIVES / "pseudonym" / "vectors.json"
    if not path.exists():
        return []
    return [pytest.param(v, id=v["name"]) for v in _load("pseudonym")["vectors"]]


@pytest.mark.parametrize("vector", _pseudonym_vectors())
def test_pseudonym_matches_vector(vector):
    got = derive_pseudonym(
        vector["operation_salt_utf8"].encode("utf-8"),
        vector["domain"],
        vector["stable_id"])
    assert got == vector["expected_pseudonym_hex"]


def test_framing_prevents_field_boundary_collisions():
    """Without the 8-byte length prefixes, ("ab","c") and ("a","bc") collide.

    The salt and the stable id are concatenated into one digest, so unframed
    absorption would let two distinct identities project onto one pseudonym —
    silently, and only for some inputs.
    """
    assert derive_pseudonym(b"ab", "holder", "c") != derive_pseudonym(
        b"a", "holder", "bc"
    )


def test_domain_separates_namespaces():
    salt, sid = b"salt", "same-id"
    values = {derive_pseudonym(salt, d, sid) for d in ("holder", "pool", "authorization")}
    assert len(values) == 3


def test_salt_scopes_the_pseudonym_to_one_operation():
    """The same stable id must not project to the same value twice."""
    assert derive_pseudonym(b"op-1", "holder", "acme") != derive_pseudonym(
        b"op-2", "holder", "acme"
    )


def _keyset_leaf_hashes(vector) -> list[str]:
    return [
        compute_leaf_hash(bytes.fromhex(leaf["public_key_bytes_hex"]))
        for leaf in sorted(vector["leaves"], key=lambda leaf: int(leaf["leaf_index"]))
    ]


def test_holder_keyset_leaf_hashes_match_vector():
    """Each leaf hash is pinned individually, not only through the root.

    A root can agree by luck of the fold; a per-leaf mismatch says exactly which
    preimage rule drifted.
    """
    vector = _load("holder-keyset")
    for leaf, got in zip(
        sorted(vector["leaves"], key=lambda leaf: int(leaf["leaf_index"])),
        _keyset_leaf_hashes(vector)):
        assert got == leaf["expected_leaf_hash"], leaf["leaf_index"]


def test_holder_keyset_root_matches_vector():
    vector = _load("holder-keyset")
    leaf_hashes = _keyset_leaf_hashes(vector)
    assert compute_merkle_root(leaf_hashes) == vector["expected_root"]
    assert len(leaf_hashes) == int(vector["tree_size"])


def test_holder_keyset_inclusion_proofs_match_vector():
    vector = _load("holder-keyset")
    leaf_hashes = _keyset_leaf_hashes(vector)
    for entry in vector["inclusion_proofs"]:
        index = int(entry["leaf_index"])
        expected = entry["sibling_hashes"]
        assert generate_inclusion_proof(leaf_hashes, index) == expected, index
        assert verify_inclusion_proof(
            leaf_hashes[index], index, expected, vector["expected_root"], len(leaf_hashes)
        )


def test_every_leaf_proof_reconstructs_the_root():
    hashes = [compute_leaf_hash(bytes([i])) for i in range(7)]  # odd width
    root = compute_merkle_root(hashes)
    for i in range(len(hashes)):
        proof = generate_inclusion_proof(hashes, i)
        assert verify_inclusion_proof(hashes[i], i, proof, root, len(hashes)), i


def test_verify_rejects_a_proof_with_leftover_siblings():
    """Unconsumed siblings mean the proof does not describe this tree."""
    hashes = [compute_leaf_hash(bytes([i])) for i in range(4)]
    root = compute_merkle_root(hashes)
    proof = generate_inclusion_proof(hashes, 0)
    assert not verify_inclusion_proof(hashes[0], 0, proof + ["ab" * 32], root, 4)


def test_master_seed_derivation_is_deterministic():
    seed = bytes(range(32))
    a = HolderKeySet.from_master_seed(seed, 4)
    b = HolderKeySet.from_master_seed(seed.hex(), 4)
    assert a.root == b.root
    assert a.root == HolderKeySet.root_from_master_seed(seed, 4)


def test_master_seed_size_changes_the_root():
    seed = bytes(range(32))
    assert HolderKeySet.from_master_seed(seed, 2).root != HolderKeySet.from_master_seed(
        seed, 4
    ).root


def test_master_seed_must_be_32_bytes():
    for bad in (b"\x01" * 31, b"\x01" * 33, "aa"):
        with pytest.raises(ValueError):
            HolderKeySet.from_master_seed(bad, 2)


def test_size_must_be_a_positive_integer():
    for bad in (0, -1, True):
        with pytest.raises(ValueError):
            HolderKeySet.from_master_seed(bytes(32), bad)


def test_disclosure_reconstructs_the_root():
    ks = HolderKeySet.from_master_seed(bytes(range(32)), 5)  # odd width
    for i in range(ks.tree_size):
        d = ks.disclosure(i)
        assert d.leaf_index == i
        assert d.tree_size == 5
        leaf_hash = compute_leaf_hash(base64.b64decode(d.public_key_b64))
        assert verify_inclusion_proof(leaf_hash, i, d.inclusion_proof, ks.root, 5)


def test_disclosure_wire_shape():
    d = HolderKeySet.from_master_seed(bytes(range(32)), 2).disclosure(0)
    wire = d.to_wire()
    assert sorted(wire) == ["inclusion_proof", "leaf_index", "public_key_b64", "tree_size"]


def test_leaf_index_out_of_range():
    ks = HolderKeySet.from_master_seed(bytes(range(32)), 2)
    for bad in (-1, 2):
        with pytest.raises(IndexError):
            ks.key(bad)


def test_signing_uses_the_disclosed_leaf_key():
    """A signature must verify under the key the disclosure reveals."""
    from certcrypt.crypto.ml_dsa import verify_ml_dsa65

    ks = HolderKeySet.from_master_seed(bytes(range(32)), 3)
    msg = b"projected commitment bytes"
    sig = ks.sign(1, msg)
    pub = base64.b64decode(ks.disclosure(1).public_key_b64)
    assert verify_ml_dsa65(pub, msg, sig)
    # And not under a different leaf: keys are per-operation and non-reused.
    other = base64.b64decode(ks.disclosure(0).public_key_b64)
    assert not verify_ml_dsa65(other, msg, sig)


def test_empty_key_set_is_refused():
    with pytest.raises(ValueError):
        HolderKeySet([])


def test_from_keys_recomputes_the_same_root():
    ks = HolderKeySet.from_master_seed(bytes(range(32)), 3)
    rebuilt = HolderKeySet.from_keys([ks.key(i) for i in range(ks.tree_size)])
    assert rebuilt.root == ks.root
