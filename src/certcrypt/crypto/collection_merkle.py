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

"""`collection.merkle-sha3-256/1` — the collection fold, issuer side.

    leaf_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:leaf")
        || u64be(len(salt))            || salt
        || u64be(len(leaf_profile))    || leaf_profile
        || u64be(len(leaf_canonical))  || leaf_canonical
    node_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:node") || L || R

Root: one leaf yields its own hash; otherwise pair left-to-right and promote a
lone right-edge hash unchanged until one remains. An empty tree is invalid.

The salt is what makes a collection root operation-specific: it is the
certificate anchor's `nonce_hex` as ASCII bytes, so the same leaf set yields a
different root in every operation. That is the property that lets leaf hashes
travel in a `verification_package` without becoming stable global identifiers of
content.

The length prefixes are what stop two different leaf sets from sharing a
preimage: without them, a profile ending in bytes that the canonical form begins
with would be ambiguous.
"""

from dataclasses import dataclass

from .canonical_subject import canonical_bytes_for_subject
from .digest import digest_hex_bytes

__all__ = [
    "COLLECTION_MERKLE_SCHEME",
    "collection_leaf_hash",
    "collection_node_hash",
    "collection_merkle_root",
    "collection_inclusion_proof",
    "CollectionLeafInput",
    "BuiltCollection",
    "build_collection",
]

COLLECTION_MERKLE_SCHEME = "collection.merkle-sha3-256/1"

_LEAF_TAG = b"CERTCRYPT:collection.merkle-sha3-256/1:leaf"
_NODE_TAG = b"CERTCRYPT:collection.merkle-sha3-256/1:node"


def _u64be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def collection_leaf_hash(
    collection_salt: bytes, leaf_profile: str, leaf_canonical_bytes: bytes
) -> str:
    """`leaf_hash` for one leaf, as lowercase hex.

    An empty salt raises: the scheme requires one, and accepting none would
    silently reproduce the unsalted construction — a root that is stable across
    operations, which is exactly what the salt exists to prevent.
    """
    if len(collection_salt) == 0:
        raise ValueError(
            "collection.merkle-sha3-256/1: a non-empty collection salt is required"
        )
    profile_bytes = leaf_profile.encode("utf-8")
    return digest_hex_bytes(
        _LEAF_TAG
        + _u64be(len(collection_salt))
        + collection_salt
        + _u64be(len(profile_bytes))
        + profile_bytes
        + _u64be(len(leaf_canonical_bytes))
        + leaf_canonical_bytes
    )


def collection_node_hash(left_hex: str, right_hex: str) -> str:
    """`node_hash` for two child hashes (lowercase hex in, lowercase hex out)."""
    return digest_hex_bytes(_NODE_TAG + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _fold_once(level: list[str]) -> list[str]:
    """One fold step: pair left-to-right, promote a lone right edge unchanged."""
    out: list[str] = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            out.append(collection_node_hash(level[i], level[i + 1]))
        else:
            out.append(level[i])
    return out


def collection_merkle_root(leaf_hashes: list[str]) -> str:
    """The collection root over an ordered list of leaf hashes."""
    if len(leaf_hashes) == 0:
        raise ValueError("collection.merkle-sha3-256/1: empty tree is invalid")
    level = list(leaf_hashes)
    while len(level) > 1:
        level = _fold_once(level)
    return level[0]


def collection_inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[str]:
    """Sibling path for one leaf, bottom-up.

    A node that is the lone right edge of an odd level is promoted unchanged and
    therefore contributes NO sibling — the case a careless implementation gets
    wrong, and the reason the conformance vectors include odd cardinalities.
    """
    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise IndexError(f"leaf index {leaf_index} out of range")
    siblings: list[str] = []
    level = list(leaf_hashes)
    idx = leaf_index
    while len(level) > 1:
        lone = idx == len(level) - 1 and len(level) % 2 == 1
        if not lone:
            siblings.append(level[idx + 1] if idx % 2 == 0 else level[idx - 1])
        level = _fold_once(level)
        idx //= 2
    return siblings


@dataclass(frozen=True)
class CollectionLeafInput:
    """One leaf's input: the profile it is declared under and its raw bytes."""

    profile: str
    data: bytes


@dataclass(frozen=True)
class BuiltCollection:
    """A built collection: the descriptor the certificate commits to, plus hashes."""

    #: The four-member descriptor, ready to be canonicalized as the subject value.
    descriptor: dict
    #: Leaf hashes in leaf order — the same values the descriptor's leaves carry.
    leaf_hashes: list[str]


def build_collection(
    collection_salt: bytes, leaves: list[CollectionLeafInput]
) -> BuiltCollection:
    """Build a collection subject from its ordered leaves.

    This is the operation an issuer cannot do before emitting: the salt is the
    certificate's own nonce, so the root is only computable once that nonce
    exists. The SDK therefore builds the collection during issuance, not before.

    Each leaf carries its OWN profile — a collection may mix texts, binaries and
    emails. Every leaf is canonicalized under its own profile before hashing,
    exactly as the verifier does when it recomputes the root from delivered
    material; that is why the profile must travel signed inside the descriptor
    rather than alongside it.
    """
    if len(leaves) == 0:
        raise ValueError("subject.collection/1: a collection needs at least one leaf")

    leaf_hashes = [
        collection_leaf_hash(
            collection_salt,
            leaf.profile,
            canonical_bytes_for_subject(leaf.profile, leaf.data),
        )
        for leaf in leaves
    ]

    return BuiltCollection(
        descriptor={
            "commitment_scheme": COLLECTION_MERKLE_SCHEME,
            "root": collection_merkle_root(leaf_hashes),
            "declared_cardinality": str(len(leaves)),
            "leaves": [
                {"profile": leaf.profile, "commitment_digest_hex": leaf_hashes[i]}
                for i, leaf in enumerate(leaves)
            ],
        },
        leaf_hashes=leaf_hashes,
    )
