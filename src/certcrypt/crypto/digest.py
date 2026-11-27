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

"""SHA3-256 digesting over the standard library.

The issuer computes the same
deterministic identifiers (commitment_id, submission_set_id) the verifier and the
server recompute (sha3_256_hex over JCS canonical bytes).

SHA3-256 is the digest under every commitment in the spec. It comes from
`hashlib`, which is FIPS 202 SHA-3 — not Keccak. The distinction matters: the two
differ in their padding and produce different digests for the same input.
"""

import hashlib

__all__ = ["digest_hex_bytes", "digest_hex_text", "digest_bytes"]


def digest_hex_bytes(data: bytes) -> str:
    """SHA3-256 of `data`, as lowercase hex."""
    return hashlib.sha3_256(data).hexdigest()


def digest_hex_text(text: str) -> str:
    """SHA3-256 of `text` encoded as UTF-8, as lowercase hex."""
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def digest_bytes(data: bytes) -> bytes:
    """SHA3-256 of `data`, as raw bytes."""
    return hashlib.sha3_256(data).digest()
