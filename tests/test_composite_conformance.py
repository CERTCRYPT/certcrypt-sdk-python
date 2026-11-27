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

"""The composite M′ framing, against the contract.

This SDK is where the signature is MADE. If its framing drifts, every certificate
it mints is signed over a message no verifier reconstructs — and this SDK's own
tests keep passing, because it verifies nothing.

M′ is the last step both components share. The ECDSA component over M′ is
pinned too, by `ecdsa-p256-deterministic` (RFC 6979); ML-DSA here is hedged and
cannot be, so for that half M′ is where the byte contract stops.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.composite import composite_m_prime

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "composite-m-prime"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not _VECTORS.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_VECTORS})"
    ),
)

PROFILE_P256_MLDSA65 = "certcrypt-composite-p256-mldsa65-v1"
PROFILE_ED25519_MLDSA65 = "certcrypt-composite-ed25519-mldsa65-v1"


def _vectors():
    return json.loads(_VECTORS.read_text("utf-8"))["vectors"]


@pytest.mark.parametrize("vector", _vectors() if _VECTORS.exists() else [])
def test_m_prime_matches_the_contract(vector):
    """M′ is reproduced byte-for-byte, separators included."""
    m = composite_m_prime(vector["composite_alg_id"], vector["payload_canon_digest_hex"])
    assert m.hex() == vector["expected_m_prime_hex"], (
        f"composite-m-prime '{vector['label']}': framing diverged — domain prefix, "
        "separators, or the order of the parts"
    )
    assert len(m) == vector["expected_m_prime_len"], (
        f"composite-m-prime '{vector['label']}': length diverged"
    )


def test_the_profile_changes_m_prime():
    """The property the profile is in the framing FOR.

    Without it, a signature this SDK makes under one profile could be
    reinterpreted under another.
    """
    digest = "a" * 64
    assert composite_m_prime(PROFILE_P256_MLDSA65, digest) != composite_m_prime(
        PROFILE_ED25519_MLDSA65, digest
    ), "omitting the profile from the framing makes a signature reinterpretable across profiles"


def test_the_digest_is_framed_as_text_not_raw_bytes():
    """The natural wrong guess: the hex string DENOTES 32 bytes.

    An implementation may reach for those instead; M′ would then be 32 bytes
    shorter and verify nowhere.
    """
    vector = _vectors()[0]
    digest = vector["payload_canon_digest_hex"]
    m = composite_m_prime(vector["composite_alg_id"], digest)
    assert m.endswith(digest.encode("ascii")), "M′ must end with the digest as ASCII text"
    assert len(m) > len(bytes.fromhex(digest)), (
        "M′ must contain the digest's 64 hex characters, not its 32 raw bytes"
    )
