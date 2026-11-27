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

"""Holder operation-key tree (`holder-keyset.merkle-sha3-256/1`), issuer side.

The holder commits to a Merkle root over a set of per-operation keys
(`holder_key_set_root`). The Level-2 authorization is signed over that root
**once**; thereafter the holder signs each projected commitment with a DISTINCT,
non-reused leaf key and discloses that leaf plus its inclusion proof. Two
commitments from the same holder share only the root: no operation key repeats.
The root itself travels in clear, so a party holding two artifacts of one key
set can recognize them as such; what stays unlinkable is the protocol surface
(capacity.evidence/1 §9).

Non-reuse is an emission invariant the verifier cannot enforce — it has no global
state. The holder is responsible for never handing the same `leaf_index` to two
commitments. This module provides the keys and the disclosure; the no-reuse
bookkeeping lives in the caller's `LeafStore`.
"""

import base64
import hashlib
from dataclasses import dataclass

from ..crypto.merkle import (
    compute_leaf_hash,
    compute_merkle_root,
    generate_inclusion_proof,
)
from ..crypto.ml_dsa import keygen_ml_dsa65, sign_ml_dsa65

__all__ = ["OperationKey", "OperationKeyDisclosure", "HolderKeySet"]


@dataclass(frozen=True)
class OperationKey:
    """One per-operation signing keypair. The secret stays in holder custody."""

    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class OperationKeyDisclosure:
    """Reveals one operation public key, its index, the tree size and its proof.

    Field names match the wire shape the verifier consumes.
    """

    leaf_index: int
    public_key_b64: str
    inclusion_proof: list[str]
    tree_size: int

    def to_wire(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "public_key_b64": self.public_key_b64,
            "inclusion_proof": list(self.inclusion_proof),
            "tree_size": self.tree_size,
        }


class HolderKeySet:
    """N operation keys, their leaf hashes, and the committed Merkle root.

    Secret keys are held in memory and never serialized by this class.
    """

    def __init__(self, keys: list[OperationKey]) -> None:
        if len(keys) == 0:
            raise ValueError("holder key set must have at least one operation key")
        self._keys = list(keys)
        self._leaf_hashes = [compute_leaf_hash(k.public_key) for k in self._keys]
        #: The value the Level-2 authorization commits to.
        self.root = compute_merkle_root(self._leaf_hashes)

    @classmethod
    def generate(cls, size: int) -> "HolderKeySet":
        """Generate a fresh key set of `size` per-operation keys."""
        return cls([OperationKey(*keygen_ml_dsa65()) for _ in range(size)])

    @classmethod
    def from_keys(cls, keys: list[OperationKey]) -> "HolderKeySet":
        """Rebuild from already-generated keys, recomputing leaves and root."""
        return cls(list(keys))

    @classmethod
    def from_master_seed(cls, master_seed: bytes | str, size: int) -> "HolderKeySet":
        """Derive the full operation-key tree deterministically from one seed.

        This is the canonical "seed plus large tree" issuer custody model: the
        issuer keeps only the 32-byte seed secret, and the whole tree — including
        the root the Level-1 authorization commits to — is reproducible from it,
        so the same seed always yields the same root on any machine.

        Per-leaf seed = SHA3-256(master_seed || utf8("op-key/<index>")). An
        issuer, the tooling and onboarding must all agree on the root, so this
        derivation lives in the SDK rather than being re-implemented per
        integration.
        """
        seed = bytes.fromhex(master_seed) if isinstance(master_seed, str) else bytes(master_seed)
        if len(seed) != 32:
            raise ValueError("holder key set master seed must be 32 bytes (64 hex chars)")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValueError("holder key set size must be a positive integer")

        keys: list[OperationKey] = []
        for i in range(size):
            leaf_seed = hashlib.sha3_256(seed + f"op-key/{i}".encode("utf-8")).digest()
            keys.append(OperationKey(*keygen_ml_dsa65(leaf_seed)))
        return cls(keys)

    @classmethod
    def root_from_master_seed(cls, master_seed: bytes | str, size: int) -> str:
        """The `holder_key_set_root` for a seed, without retaining the keys.

        This is the value an issuer supplies at onboarding to mint its Level-1
        authorization.
        """
        return cls.from_master_seed(master_seed, size).root

    @property
    def tree_size(self) -> int:
        return len(self._keys)

    def key(self, leaf_index: int) -> OperationKey:
        """The operation key at `leaf_index`, for signing exactly one commitment."""
        if leaf_index < 0 or leaf_index >= len(self._keys):
            raise IndexError(
                f"leaf_index {leaf_index} out of range (tree_size {len(self._keys)})"
            )
        return self._keys[leaf_index]

    def disclosure(self, leaf_index: int) -> OperationKeyDisclosure:
        """The inclusion-proof disclosure binding `leaf_index` to the root."""
        k = self.key(leaf_index)
        return OperationKeyDisclosure(
            leaf_index=leaf_index,
            public_key_b64=base64.b64encode(k.public_key).decode("ascii"),
            inclusion_proof=generate_inclusion_proof(self._leaf_hashes, leaf_index),
            tree_size=len(self._keys),
        )

    def sign(self, leaf_index: int, msg: bytes) -> bytes:
        """Sign `msg` with the leaf at `leaf_index`.

        The caller is responsible for never reusing a leaf — see the non-reuse
        invariant in the module docstring.
        """
        return sign_ml_dsa65(self.key(leaf_index).secret_key, msg)
