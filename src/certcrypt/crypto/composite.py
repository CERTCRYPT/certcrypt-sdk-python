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

"""Composite signature signing (CERTCRYPT Composite Signature Profile).

Every component signs the SAME domain-separated message M', and the composite
verifies iff ALL components verify (AND). Binding the profile id into M' stops a
component being lifted out and replayed under another profile::

    M' = ASCII("CERTCRYPT-Composite-Signature-v1") || 0x00
         || ASCII(composite_alg_id) || 0x00 || ASCII(payload_canon_digest_hex)

Canonical profile `certcrypt-composite-p256-mldsa65-v1`: ECDSA-P256-SHA3-256
(classical, FIRST — order is load-bearing) + ML-DSA-65 (PQC). The ECDSA component
signs SHA3-256(M'); ML-DSA signs M' directly, empty context, no pre-hash. The M'
bytes are load-bearing cross-language.

There is no API here to sign one component alone. A composite is valid only as
the AND of all of them, so exposing a single-component signer would hand out a
way to produce something that looks like a signature but carries no
post-quantum half.
"""

import base64
from dataclasses import dataclass

from .ecdsa_p256 import sign_ecdsa_p256_raw
from .ml_dsa import sign_ml_dsa65

__all__ = [
    "COMPOSITE_DOMAIN_PREFIX",
    "PROFILE_P256_MLDSA65",
    "ALG_ECDSA_P256",
    "ALG_MLDSA65",
    "CompositeSigningKey",
    "composite_m_prime",
    "composite_sign_p256",
]

COMPOSITE_DOMAIN_PREFIX = "CERTCRYPT-Composite-Signature-v1"
PROFILE_P256_MLDSA65 = "certcrypt-composite-p256-mldsa65-v1"
ALG_ECDSA_P256 = "ECDSA-P256-SHA3-256"
ALG_MLDSA65 = "ML-DSA-65"


@dataclass
class CompositeSigningKey:
    """The issuer's composite signing key (P-256 classical + ML-DSA-65 PQC)."""

    p256_private: object  # ecdsa.SigningKey
    mldsa_secret: bytes


def composite_m_prime(composite_alg_id: str, payload_canon_digest_hex: str) -> bytes:
    """Build the domain-separated message M' every component signs.

    The 0x00 separators are what keep the fields unambiguous: without them, a
    profile id ending in hex characters could be confused with the start of the
    digest.
    """
    return (
        COMPOSITE_DOMAIN_PREFIX.encode("ascii")
        + b"\x00"
        + composite_alg_id.encode("ascii")
        + b"\x00"
        + payload_canon_digest_hex.encode("ascii")
    )


def composite_sign_p256(
    payload_canon_digest_hex: str, key: CompositeSigningKey
) -> dict:
    """Produce a composite signature under the canonical P-256+ML-DSA-65 profile.

    Components are ordered classical-first, which is load-bearing: a verifier
    reads them positionally. The ECDSA component carries `encoding:"raw-rs-64"`
    and `low_s: true`; ML-DSA carries neither.
    """
    m_prime = composite_m_prime(PROFILE_P256_MLDSA65, payload_canon_digest_hex)

    ecdsa_sig = sign_ecdsa_p256_raw(key.p256_private, m_prime)
    mldsa_sig = sign_ml_dsa65(key.mldsa_secret, m_prime)

    return {
        "alg": PROFILE_P256_MLDSA65,
        "mode": "AND",
        "signatures": [
            {
                "alg": ALG_ECDSA_P256,
                "encoding": "raw-rs-64",
                "low_s": True,
                "sig_b64": base64.b64encode(ecdsa_sig).decode("ascii"),
            },
            {
                "alg": ALG_MLDSA65,
                "sig_b64": base64.b64encode(mldsa_sig).decode("ascii"),
            },
        ],
    }
