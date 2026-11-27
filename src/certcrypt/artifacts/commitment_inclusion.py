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

"""Commitment inclusion proof — the `commitment_id → subtree_root` level.

The verifier does NOT receive this artifact from the node: it is derived
client-side from data already in the `independence_proof` (`consumed_commitment_ids`
plus `subtree_root`). This module lets the SDK assemble it so an issuer can build
a complete `verification_package`.

**The one place the usual rule is inverted.** Everywhere else in the protocol the
canonical form is JCS (RFC 8785), which sorts keys alphabetically. Here the leaf
preimage is ordered JSON in INSERTION order — `{"v":…,"commitment_id":…}` — with
no whitespace. Alphabetical ordering would put `commitment_id` first, change
every leaf hash, and every inclusion proof would fail to verify. `_ordered_json_bytes`
exists precisely so nobody reaches for the JCS helper here by reflex.
"""

import json

from ..crypto.merkle import (
    compute_leaf_hash,
    compute_merkle_root,
    generate_inclusion_proof,
)

__all__ = [
    "COMMITMENT_LEAF_VERSION",
    "commitment_leaf_hash",
    "build_commitment_inclusion_proof",
    "commitment_subtree_root",
]

#: Version tag of the commitment sub-tree leaf preimage.
COMMITMENT_LEAF_VERSION = "ccab1-commit"


def _ordered_json_bytes(ordered_fields: list[tuple[str, str]]) -> bytes:
    """JSON preserving field insertion order, no whitespace.

    NOT JCS: see the module docstring. Deliberately minimal — only string values
    are needed for the commitment leaf preimage, so there is no number
    serialization to get wrong.
    """
    parts = [
        json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        + ":"
        + json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        for key, value in ordered_fields
    ]
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def commitment_leaf_hash(commitment_id: str) -> str:
    """`SHA3-256(0x00 || orderedJson({v, commitment_id}))`."""
    return compute_leaf_hash(
        _ordered_json_bytes(
            [("v", COMMITMENT_LEAF_VERSION), ("commitment_id", commitment_id)]
        )
    )


def build_commitment_inclusion_proof(
    commitment_ids: list[str], commitment_index: int
) -> dict:
    """Build the `commitment → subtree_root` proof for one commitment.

    The leaf order is the canonical one: `consumed_commitment_ids` as the
    independence proof carries it. Passing a re-sorted list would produce a proof
    that verifies against nothing.

    The numeric fields travel as strings, matching the wire shape the verifier
    consumes.
    """
    if len(commitment_ids) == 0:
        raise ValueError("commitment inclusion proof requires at least one commitment id")
    if commitment_index < 0 or commitment_index >= len(commitment_ids):
        raise IndexError(
            f"commitment_index {commitment_index} out of range "
            f"({len(commitment_ids)} commitments)"
        )

    leaf_hashes = [commitment_leaf_hash(cid) for cid in commitment_ids]
    return {
        "commitment_id": commitment_ids[commitment_index],
        "commitment_leaf_hash": leaf_hashes[commitment_index],
        "commitment_index": str(commitment_index),
        "commitment_siblings": generate_inclusion_proof(leaf_hashes, commitment_index),
        "subtree_size": str(len(leaf_hashes)),
    }


def commitment_subtree_root(commitment_ids: list[str]) -> str:
    """Subtree root over the accepted commitments, for an optional self-check."""
    if len(commitment_ids) == 0:
        raise ValueError("subtree root requires at least one commitment id")
    return compute_merkle_root([commitment_leaf_hash(cid) for cid in commitment_ids])
