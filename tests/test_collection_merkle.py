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

"""The collection fold against the published conformance vectors.

The vectors deliberately include odd cardinalities (3 and 5 leaves) and a
1024-leaf tree. Odd widths are where the fold is easy to get wrong: the lone
right-edge node is promoted unchanged and contributes NO sibling to the proof.
An implementation that emitted a sibling there — or that duplicated the lone node
and hashed it with itself, which is the other common shortcut — would produce a
different root and a proof that verifies against nothing.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.collection_merkle import (
    COLLECTION_MERKLE_SCHEME,
    CollectionLeafInput,
    build_collection,
    collection_inclusion_proof,
    collection_leaf_hash,
    collection_merkle_root,
    collection_node_hash)

_VECTOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "collection-merkle"
)

pytestmark = pytest.mark.skipif(
    not _VECTOR_DIR.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_VECTOR_DIR})"
    ))


def _vector_files():
    if not _VECTOR_DIR.exists():
        return []
    return sorted(p for p in _VECTOR_DIR.glob("vector-*.json"))


def _load(path: Path):
    return json.loads(path.read_text("utf-8"))


def _leaf_hashes(vector) -> list[str]:
    salt = bytes.fromhex(vector["collection_salt_hex"])
    profile = vector["leaf_profile"]
    return [
        collection_leaf_hash(salt, profile, bytes.fromhex(leaf_hex))
        for leaf_hex in vector["leaves_hex"]
    ]


@pytest.mark.parametrize("path", _vector_files(), ids=lambda p: p.stem)
def test_root_matches_vector(path):
    vector = _load(path)
    assert vector["commitment_scheme"] == COLLECTION_MERKLE_SCHEME
    hashes = _leaf_hashes(vector)
    assert len(hashes) == int(vector["declared_cardinality"])
    assert collection_merkle_root(hashes) == vector["root"]


@pytest.mark.parametrize("path", _vector_files(), ids=lambda p: p.stem)
def test_inclusion_proofs_match_vector(path):
    vector = _load(path)
    hashes = _leaf_hashes(vector)
    for entry in vector["inclusion_proofs"]:
        index = int(entry["leaf_index"])
        expected = entry.get("sibling_hashes", entry.get("siblings"))
        assert collection_inclusion_proof(hashes, index) == expected, (
            f"{path.stem} leaf {index}"
        )


@pytest.mark.parametrize("path", _vector_files(), ids=lambda p: p.stem)
def test_every_proof_reconstructs_the_root(path):
    """Replaying a proof bottom-up must land on the published root.

    This is the property a holder relies on when handing out one element of a
    collection without the rest.
    """
    vector = _load(path)
    hashes = _leaf_hashes(vector)
    for index in range(len(hashes)):
        siblings = iter(collection_inclusion_proof(hashes, index))
        acc = hashes[index]
        idx = index
        width = len(hashes)
        # Walk the levels the same way the fold does. A lone right-edge node at
        # an odd width is promoted unchanged and consumes NO sibling — advancing
        # the index without that check is what breaks replay on odd trees.
        while width > 1:
            if not (idx == width - 1 and width % 2 == 1):
                sibling = next(siblings)
                acc = (
                    collection_node_hash(acc, sibling)
                    if idx % 2 == 0
                    else collection_node_hash(sibling, acc)
                )
            idx //= 2
            width = (width + 1) // 2
        assert acc == vector["root"], f"{path.stem} leaf {index}"


def test_single_leaf_root_is_its_own_hash():
    assert collection_merkle_root(["ab" * 32]) == "ab" * 32


def test_empty_tree_is_invalid():
    with pytest.raises(ValueError):
        collection_merkle_root([])


def test_empty_salt_is_refused():
    """An empty salt would silently reproduce the unsalted construction."""
    with pytest.raises(ValueError):
        collection_leaf_hash(b"", "subject.binary/1", b"x")


def test_leaf_index_out_of_range():
    with pytest.raises(IndexError):
        collection_inclusion_proof(["ab" * 32, "cd" * 32], 2)


def test_build_collection_descriptor_shape():
    built = build_collection(
        b"\x01" * 32,
        [
            CollectionLeafInput("subject.binary/1", b"one"),
            CollectionLeafInput("subject.text/1", b"two\r\n"),
            CollectionLeafInput("subject.binary/1", b"three"),
        ])
    d = built.descriptor
    assert d["commitment_scheme"] == COLLECTION_MERKLE_SCHEME
    assert d["declared_cardinality"] == "3"
    assert [leaf["commitment_digest_hex"] for leaf in d["leaves"]] == built.leaf_hashes
    assert d["root"] == collection_merkle_root(built.leaf_hashes)
    # Each leaf keeps its own declared profile: a collection may mix profiles,
    # and the verifier canonicalizes each leaf under the one it declares.
    assert [leaf["profile"] for leaf in d["leaves"]] == [
        "subject.binary/1",
        "subject.text/1",
        "subject.binary/1",
    ]


def test_build_collection_descriptor_satisfies_its_own_precondition():
    """The descriptor must be canonicalizable as a subject.collection/1 value."""
    from certcrypt.crypto.subject_json_preconditions import (
        assert_collection_precondition)

    built = build_collection(
        b"\x02" * 32, [CollectionLeafInput("subject.binary/1", b"only")]
    )
    assert_collection_precondition(built.descriptor)


def test_salt_makes_the_root_operation_specific():
    """The same leaf set under a different salt must not reproduce the root."""
    leaves = [CollectionLeafInput("subject.binary/1", b"same")]
    a = build_collection(b"\x01" * 32, leaves)
    b = build_collection(b"\x02" * 32, leaves)
    assert a.descriptor["root"] != b.descriptor["root"]


def test_empty_collection_is_refused():
    with pytest.raises(ValueError):
        build_collection(b"\x01" * 32, [])
