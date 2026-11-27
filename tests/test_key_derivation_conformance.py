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

"""One seed materializing the whole composite identity, against the contract.

This is the root of every signature this SDK produces. A divergence here is not a
wrong digest somewhere downstream — it is a different IDENTITY, signing artifacts
that resolve to a key nobody else derives from the same seed. Nothing later
detects it, because everything later is internally consistent with the wrong key.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from certcrypt.crypto.ecdsa_p256 import P256_DERIVE_INFO, signing_key_from_seed
from certcrypt.crypto.ml_dsa import keygen_ml_dsa65

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "key-derivation"
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


def _uncompressed(sk) -> bytes:
    return b"\x04" + sk.get_verifying_key().to_string()


@pytest.mark.parametrize(
    "vector", _doc()["vectors"] if _VECTORS.exists() else [], ids=lambda v: v["label"]
)
def test_the_seed_derives_the_contracts_p256_half(vector):
    """HKDF-SHA3-256 with its own info string, oversampled and reduced mod n."""
    sk = signing_key_from_seed(bytes.fromhex(vector["seed_hex"]))
    assert _uncompressed(sk).hex() == vector["p256_public_key_sec1_uncompressed_hex"], (
        f"key-derivation '{vector['label']}': P-256 uncompressed SEC1 diverged — the "
        "HKDF info string, the oversampling, or the mod-n reduction"
    )
    # Both encodings are pinned because they are different byte strings, and the
    # fingerprint below depends on which one you feed it.
    compressed = sk.get_verifying_key().to_string("compressed")
    assert compressed.hex() == vector["p256_public_key_sec1_compressed_hex"], (
        f"key-derivation '{vector['label']}': P-256 compressed SEC1 diverged"
    )


@pytest.mark.parametrize(
    "vector", _doc()["vectors"] if _VECTORS.exists() else [], ids=lambda v: v["label"]
)
def test_the_seed_derives_the_contracts_mldsa_half(vector):
    """The seed IS the FIPS 204 input: used verbatim as xi, with no KDF."""
    public_key, _secret = keygen_ml_dsa65(bytes.fromhex(vector["seed_hex"]))
    assert base64.b64encode(public_key).decode("ascii") == vector[
        "mldsa65_public_key_b64"
    ], (
        f"key-derivation '{vector['label']}': ML-DSA-65 public key diverged — the seed "
        "must be used verbatim, with no domain separation"
    )


@pytest.mark.parametrize(
    "vector", _doc()["vectors"] if _VECTORS.exists() else [], ids=lambda v: v["label"]
)
def test_the_composite_fingerprint_is_recomputed_not_trusted(vector):
    """Classical component FIRST, uncompressed.

    This is the `system_root_fingerprint` an implementation must recompute rather
    than accept, so a swapped root cannot pass as the published one. Feeding it
    the compressed form yields a different value — which is why both encodings are
    pinned above.
    """
    seed = bytes.fromhex(vector["seed_hex"])
    classical = _uncompressed(signing_key_from_seed(seed))
    pqc, _secret = keygen_ml_dsa65(seed)
    got = hashlib.sha3_256(classical + pqc).hexdigest()
    assert got == vector["composite_root_fingerprint"], (
        f"key-derivation '{vector['label']}': composite fingerprint diverged — "
        "component order, or the compressed SEC1 form used where the uncompressed "
        "one belongs"
    )


def test_the_domain_separation_string_is_the_contracts():
    """The info string is what keeps the two halves from deriving into each other."""
    assert P256_DERIVE_INFO == b"certcrypt/composite/p256/v1"
    assert "certcrypt/composite/p256/v1" in _doc()["rules"]["p256"], (
        "the contract's stated rule no longer names this info string"
    )
