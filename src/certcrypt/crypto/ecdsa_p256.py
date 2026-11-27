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

"""ECDSA P-256 signing — the classical component of the composite profile.

Wire contract (must interoperate with every other implementation):

  - curve P-256 / secp256r1, hash **SHA3-256** over the message (NOT SHA-2);
  - signature encoding `raw-rs-64`: r || s, 64 bytes (32+32), big-endian, NOT DER;
  - **low-s is normative**: the producer MUST emit s ≤ n/2, and the verifier
    rejects high-s outright. ECDSA admits both s and n-s for the same message,
    so a signer that skipped this would emit a valid-looking signature that every
    conformant verifier refuses — roughly half the time, which is worse than
    always.
  - public key on the wire: SEC1 uncompressed (65B, 0x04 prefix), base64.

Signatures are RFC 6979 deterministic here, with H = SHA3-256 for the nonce's
HMAC as well, as the conformance family `ecdsa-p256-deterministic` pins byte for
byte. An implementation that signs with a random nonce produces different
bytes over the same message — both are valid, and each verifies under the
other. Determinism is the stronger property and costs nothing, so this SDK
keeps it.
"""

import hashlib
import hmac

from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

__all__ = [
    "P256_N",
    "P256_HALF_N",
    "P256_DERIVE_INFO",
    "signing_key_from_seed",
    "generate_ecdsa_p256_key",
    "private_key_from_scalar",
    "scalar_from_seed_material",
    "public_key_sec1_uncompressed_b64",
    "sign_ecdsa_p256_raw",
    "verify_ecdsa_p256_raw",
]

#: secp256r1 group order n, and n/2 (the low-s ceiling, inclusive).
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_HALF_N = P256_N >> 1


def generate_ecdsa_p256_key() -> SigningKey:
    """Generate a fresh P-256 signing key (dev/test; production keys via KMS)."""
    return SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha3_256)


def scalar_from_seed_material(material: bytes) -> bytes:
    """Fold arbitrary seed-derived bytes into a valid P-256 scalar in [1, n).

    Reduces mod (n-1) and adds 1, so the result is never 0 and never ≥ n.
    Deterministic: the same seed always yields the same signing identity, with no
    stored key material.
    """
    v = int.from_bytes(material, "big") % (P256_N - 1)
    return (v + 1).to_bytes(32, "big")


def private_key_from_scalar(scalar: bytes) -> SigningKey:
    """Build a P-256 signing key deterministically from a 32-byte scalar.

    Callers MUST pass a scalar already reduced into [1, n) — see
    `scalar_from_seed_material`, which folds arbitrary seed bytes into range.
    """
    if len(scalar) != 32:
        raise ValueError(f"P-256 scalar must be 32 bytes (got {len(scalar)})")
    d = int.from_bytes(scalar, "big")
    if d <= 0 or d >= P256_N:
        raise ValueError("P-256 scalar out of range [1, n) — reduce it first")
    return SigningKey.from_secret_exponent(d, curve=NIST256p, hashfunc=hashlib.sha3_256)


#: Domain-separation info string for deriving the P-256 half of a composite key
#: from a 32-byte master seed.
#:
#: Load-bearing, and pinned by the conformance contract
#: (`fixtures/primitives/key-derivation`): whatever derives the published key and
#: every SDK MUST derive byte-identically, or the public key published in the manifest
#: is not the one this seed produces.
P256_DERIVE_INFO = b"certcrypt/composite/p256/v1"


def _hkdf_sha3_256(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with SHA3-256, no salt.

    Written out rather than taken from a dependency: the SHA3 variant is not what
    most HKDF packages default to, and this derivation is part of the byte
    contract. Fifteen lines that a reader can check against RFC 5869 beat a
    dependency whose hash choice is a constructor argument someone can change.
    """
    hash_len = 32
    prk = hmac.new(b"\x00" * hash_len, ikm, hashlib.sha3_256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(
            prk, block + info + bytes([counter]), hashlib.sha3_256
        ).digest()
        okm += block
        counter += 1
    return okm[:length]


def signing_key_from_seed(seed: bytes) -> SigningKey:
    """Deterministic P-256 signing key from a 32-byte master seed.

    HKDF-SHA3-256 with explicit domain separation, expanded to 48 bytes and
    reduced mod n. The oversampling past the 32-byte field is what removes the
    modular bias of reducing exactly 256 bits; a result of 0 maps to 1, so the
    scalar is always in [1, n-1].

    The SAME seed also derives the ML-DSA-65 half (FIPS 204 KeyGen, seed used
    verbatim). The distinct HKDF `info` is what keeps the two derivations
    separated, so one custodied seed can materialize the whole composite identity
    without either component leaking into the other.

    Note the difference from `scalar_from_seed_material`, which folds arbitrary
    bytes with `% (n-1) + 1`. That is a different reduction and yields a different
    key: it is the one `derive_issuer_key` uses for the issuer's certificate-signing
    key (conformance family `issuer-key-derivation`). This function reproduces the
    `key-derivation` family.
    """
    if len(seed) != 32:
        raise ValueError(f"master seed must be 32 bytes (got {len(seed)})")
    okm = _hkdf_sha3_256(seed, P256_DERIVE_INFO, 48)
    scalar = int.from_bytes(okm, "big") % P256_N
    if scalar == 0:
        scalar = 1
    return SigningKey.from_secret_exponent(
        scalar, curve=NIST256p, hashfunc=hashlib.sha3_256
    )


def public_key_sec1_uncompressed_b64(key: SigningKey | VerifyingKey) -> str:
    """Export the public key as SEC1 uncompressed (65B, 0x04-prefixed) base64."""
    import base64

    vk = key.get_verifying_key() if isinstance(key, SigningKey) else key
    point = vk.to_string()  # 64 bytes: X || Y
    if len(point) != 64:
        raise ValueError(f"P-256 public point must be 64 bytes (got {len(point)})")
    return base64.b64encode(b"\x04" + point).decode("ascii")


def _normalize_low_s(sig64: bytes) -> bytes:
    """Replace s with n - s when s > n/2, leaving r untouched.

    Both forms verify mathematically; only the low form is admissible on the
    wire.
    """
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if s > P256_HALF_N:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_ecdsa_p256_raw(key: SigningKey, message: bytes) -> bytes:
    """Sign `message`, returning a `raw-rs-64` low-s signature.

    SHA3-256 is applied to the message here, matching what the verifier expects —
    a binding that used SHA-256 would produce 64 plausible bytes that never
    verify.
    """
    sig = key.sign_deterministic(
        message, hashfunc=hashlib.sha3_256, sigencode=sigencode_string
    )
    if len(sig) != 64:
        raise ValueError(f"expected raw-rs-64 signature (64 bytes), got {len(sig)}")
    return _normalize_low_s(sig)


def verify_ecdsa_p256_raw(public_key_b64: str, message: bytes, sig: bytes) -> bool:
    """Local self-check verify, mirroring the verifier's ECDSA primitive.

    The production trust verdict is the composite check in the verifier toolkit;
    this enforces the same primitive rules (SHA3-256, raw-rs-64, low-s required)
    so a self-check cannot pass on a signature the verifier would reject.
    """
    import base64

    if len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "big")
    if s == 0 or s > P256_HALF_N:
        return False  # high-s is inadmissible even though it verifies
    r = int.from_bytes(sig[:32], "big")
    if r == 0 or r >= P256_N:
        return False

    raw = base64.b64decode(public_key_b64)
    if len(raw) != 65 or raw[0] != 0x04:
        return False
    try:
        vk = VerifyingKey.from_string(raw[1:], curve=NIST256p, hashfunc=hashlib.sha3_256)
        return vk.verify(
            sig, message, hashfunc=hashlib.sha3_256, sigdecode=sigdecode_string
        )
    except Exception:
        return False
