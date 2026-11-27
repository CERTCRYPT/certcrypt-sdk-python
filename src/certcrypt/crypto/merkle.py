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

"""SHA3-256 Merkle tree for `holder-keyset.merkle-sha3-256/1`.

The SDK builds the exact same
`holder_key_set_root` and inclusion proofs the verifier checks::

    leaf hash = SHA3-256(0x00 || leaf_preimage_bytes)
    node hash = SHA3-256(0x01 || left_bytes || right_bytes)

with the odd-rightmost child promoted unchanged.

**This is not the collection fold.** `collection_merkle` uses ASCII domain tags
and 8-byte length prefixes; this one uses single-byte 0x00/0x01 discriminators.
They are different constructions over the same digest and are not
interchangeable — using one where the other belongs produces a root that is
wrong in a way no length check catches. The two live in separate modules for
exactly that reason.

The 0x00/0x01 prefixes are what stop a leaf preimage being reinterpreted as an
internal node (second-preimage resistance for the tree itself).
"""

import re

from .digest import digest_hex_bytes

__all__ = [
    "compute_leaf_hash",
    "compute_merkle_root",
    "generate_inclusion_proof",
    "verify_inclusion_proof",
]

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def compute_leaf_hash(preimage_bytes: bytes) -> str:
    """Leaf hash: SHA3-256(0x00 || preimage_bytes), lowercase hex."""
    return digest_hex_bytes(_LEAF_PREFIX + preimage_bytes)


def _compute_node_hash(left_hex: str, right_hex: str) -> str:
    """Internal node hash: SHA3-256(0x01 || left_bytes || right_bytes)."""
    return digest_hex_bytes(
        _NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    )


def _fold_once(level: list[str]) -> list[str]:
    out: list[str] = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            out.append(_compute_node_hash(level[i], level[i + 1]))
        else:
            out.append(level[i])
    return out


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """Merkle root over leaf hashes; a single leaf is its own root."""
    if len(leaf_hashes) == 0:
        raise ValueError("cannot compute Merkle root of empty leaf set")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    level = list(leaf_hashes)
    while len(level) > 1:
        level = _fold_once(level)
    return level[0]


def generate_inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[str]:
    """Sibling hashes for a leaf, bottom-up.

    A lone right-edge node at an odd level is promoted unchanged and contributes
    no sibling.
    """
    if len(leaf_hashes) <= 1:
        return []
    siblings: list[str] = []
    level = list(leaf_hashes)
    idx = leaf_index
    while len(level) > 1:
        has_sibling = idx % 2 == 1 or idx + 1 < len(level)
        if has_sibling:
            siblings.append(level[idx + 1] if idx % 2 == 0 else level[idx - 1])
        level = _fold_once(level)
        idx //= 2
    return siblings


def verify_inclusion_proof(
    leaf_hash: str,
    leaf_index: int,
    sibling_hashes: list[str],
    expected_root: str,
    tree_size: int,
) -> bool:
    """Verify an inclusion proof against a root.

    Mirrors the verifier so the SDK can self-check what it produced before
    shipping it — a disclosure that does not reconstruct its own root is a bug
    worth catching here rather than at the far end.
    """
    # Fail-closed on shape before the fold: an index past the tree would fold as
    # an alias of a real one, and a sibling that is not 64 lowercase hex is not
    # another spelling of a valid proof.
    def _uint(x: object) -> bool:
        return isinstance(x, int) and not isinstance(x, bool) and x >= 0

    if not _uint(tree_size) or tree_size < 1:
        return False
    if not _uint(leaf_index) or leaf_index >= tree_size:
        return False
    if not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in (leaf_hash, expected_root)):
        return False
    if not isinstance(sibling_hashes, list) or not all(
        isinstance(h, str) and _HEX64.fullmatch(h) for h in sibling_hashes
    ):
        return False
    current = leaf_hash
    sibling_index = 0
    idx = leaf_index
    width = tree_size
    while width > 1:
        has_sibling = idx % 2 == 1 or idx + 1 < width
        if has_sibling:
            if sibling_index >= len(sibling_hashes):
                return False
            sibling = sibling_hashes[sibling_index]
            sibling_index += 1
            current = (
                _compute_node_hash(current, sibling)
                if idx % 2 == 0
                else _compute_node_hash(sibling, current)
            )
        idx //= 2
        width = (width + 1) // 2
    # Every supplied sibling must have been consumed: leftovers mean the proof
    # does not describe this tree.
    return sibling_index == len(sibling_hashes) and current == expected_root
