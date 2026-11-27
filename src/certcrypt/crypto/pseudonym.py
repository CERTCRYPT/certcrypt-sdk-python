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

"""Operation-scoped pseudonyms.

Pinned by the conformance family `pseudonym`::

    pseudonym(field) = SHA3-256(
        frame(operation_salt) || frame(domain_tag) || frame(stable_id)
    )

Each field is absorbed with an 8-byte big-endian length prefix so field
boundaries are unambiguous — without the framing, ("ab", "c") and ("a", "bc")
would collide, and two different identities would project to one pseudonym.

The hash is SHA3-256 (FIPS 202 fixed-output), not SHAKE-256: the output is a
fixed 32 bytes, so the XOF buys nothing.

The salt is per-operation and public, which is what scopes the pseudonym: the
same stable id projects to a different value in every operation, so two
commitments cannot be linked by comparing their pseudonyms.
"""

import hashlib
from typing import Literal

__all__ = ["PseudonymDomain", "derive_pseudonym"]

PseudonymDomain = Literal["holder", "pool", "authorization"]


def _frame(field: bytes) -> bytes:
    """Absorb a field with an 8-byte big-endian length prefix."""
    return len(field).to_bytes(8, "big") + field


def derive_pseudonym(
    operation_salt: bytes, domain: PseudonymDomain, stable_id: str
) -> str:
    """Derive an operation-scoped pseudonym, as lowercase hex.

    `operation_salt` is the public per-operation salt carried in the evidence;
    `domain` separates namespaces; `stable_id` is the identifier being projected
    and never appears in clear in the evidence.
    """
    h = hashlib.sha3_256()
    h.update(_frame(operation_salt))
    h.update(_frame(domain.encode("utf-8")))
    h.update(_frame(stable_id.encode("utf-8")))
    return h.hexdigest()
