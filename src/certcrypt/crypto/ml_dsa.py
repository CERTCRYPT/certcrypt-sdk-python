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

"""ML-DSA-65 (FIPS 204) signing — the post-quantum component.

Backed by `dilithium-py` (the
same library the conformance generator uses to produce the published goldens).

Byte contract — every implementation MUST agree on this:

  - **empty context**: no context string is passed to sign;
  - **pure ML-DSA-65** (FIPS 204), not the pre-hash variant.

Inside a composite signature the component is named `ML-DSA-65`
(`composite.ALG_MLDSA65`).

The signature is randomized ("hedged") by default in FIPS 204, so two signatures
over the same message differ — and both verify. Do not assert signature equality
across runs; assert that what this SDK produces verifies under the other
bindings, which is what the tests do.
"""

from dilithium_py.ml_dsa import ML_DSA_65

__all__ = [
    "ML_DSA_65_ALG_ID",
    "sign_ml_dsa65",
    "verify_ml_dsa65",
    "keygen_ml_dsa65",
]

#: A label for pure ML-DSA-65 under FIPS 204. No artifact this SDK emits carries
#: it: a composite signature names its component `ML-DSA-65`.
ML_DSA_65_ALG_ID = "ml-dsa-65-fips204-v1"


def sign_ml_dsa65(secret_key: bytes, msg: bytes) -> bytes:
    """Sign `msg` with an ML-DSA-65 secret key.

    Empty context, no pre-hash — the arguments are deliberately not exposed, so a
    caller cannot produce a signature the other bindings will not accept.
    """
    return ML_DSA_65.sign(secret_key, msg)


def verify_ml_dsa65(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an ML-DSA-65 signature.

    Provided for local self-checks and tests; the production verification path
    lives in the verifier toolkit.
    """
    return ML_DSA_65.verify(public_key, msg, sig)


def keygen_ml_dsa65(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair, returning `(public_key, secret_key)`.

    For development and tests: in normal use the operation-key tree is derived
    from the issuer's own master seed, so keys are never generated ad hoc.
    """
    if seed is None:
        return ML_DSA_65.keygen()
    return ML_DSA_65.key_derive(seed)
