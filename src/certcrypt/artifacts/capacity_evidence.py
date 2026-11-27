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

"""Zero-data capacity evidence.

The issuer projects its stable identifiers (holder, pool, authorization) to
operation-scoped pseudonyms, signs the projected commitment with a disclosed
per-operation leaf key, and carries the pre-signed Level-1 anchor verbatim. The
stable identifiers themselves never appear in the evidence, so they never reach
a verifier — that is what "zero-data" means here. (The submission member's
`operative` carries `holder_id` and `pool_id` in clear to the node, for routing
only; see submission-set/1 §7.2.)

**Two different byte forms live in this module, and mixing them breaks things:**

  - `projected_commitment_signing_bytes` uses INSERTION order — the projected
    commitment in its exact declared field order. This is what the leaf key
    signs.
  - `evidence_digest_hex` uses JCS (sorted keys). This is what the independence
    proof binds.

Python dicts preserve insertion order (guaranteed since 3.7), so building the
projected commitment as a literal and serializing it gives the declared order.
That is a language guarantee the signed bytes depend on, which is why it is
written down here rather than left implicit.
"""

import base64
import json
from dataclasses import dataclass
from typing import Any

from ..crypto.digest import digest_hex_text
from ..crypto.jcs import jcs_canonicalize_string
from ..crypto.pseudonym import derive_pseudonym
from .holder_keyset import HolderKeySet

__all__ = [
    "ZERO_DATA_PROFILE",
    "COMMITMENT_VERSION",
    "MAX_SUBMISSION_SET_MEMBERS",
    "SubmissionSetTooLargeError",
    "StableIdentifiers",
    "assert_submission_set_within_bound",
    "projected_commitment_signing_bytes",
    "evidence_digest_hex",
    "assemble_evidence",
]

ZERO_DATA_PROFILE = "zero-data.unlinkable"
COMMITMENT_VERSION = "capacity.commitment/1"

#: Maximum members in one `submission-set/1`.
#:
#: A client-side fail-fast guard, not a security boundary: a caller controls its
#: own process. It exists so an over-sized set is refused BEFORE any signing or
#: network call, instead of costing operation-key leaves and a round trip to
#: learn the same thing. The authoritative enforcement is the node assembler and
#: the submit endpoint, which reject an over-cardinality set fail-closed.
#:
#: The value is pinned by the conformance contract
#: (`fixtures/primitives/submission-set-limits`), and
#: `tests/test_artifact_shape_conformance.py` holds this constant to it. It is 64,
#: kept well below the count at which a zero-data set would approach the 2 MiB
#: HTTP submit body limit the contract states, so the cap is reachable over the wire with margin for
#: per-member evidence growth.
MAX_SUBMISSION_SET_MEMBERS = 64


class SubmissionSetTooLargeError(ValueError):
    """Raised when a submission set would exceed the cardinality bound.

    Carries the offending count and the bound, so a caller batching work can
    split without re-deriving either.
    """

    def __init__(self, count: int) -> None:
        super().__init__(
            f"submission set exceeds the maximum of {MAX_SUBMISSION_SET_MEMBERS} "
            f"members (got {count}); the set is rejected as a whole "
            "(submission-set/1)"
        )
        self.count = count
        self.max = MAX_SUBMISSION_SET_MEMBERS


def assert_submission_set_within_bound(member_count: int) -> None:
    """Assert a member count is within the `submission-set/1` bound.

    The bound is inclusive: exactly `MAX_SUBMISSION_SET_MEMBERS` is admissible.
    An empty set is refused too — it has no submission to close over, and its id
    would still compute, so nothing downstream would catch the emptiness.
    """
    if member_count < 1:
        raise ValueError(
            "a submission set must carry at least one member; an empty set has "
            "nothing to close over (submission-set/1)"
        )
    if member_count > MAX_SUBMISSION_SET_MEMBERS:
        raise SubmissionSetTooLargeError(member_count)


@dataclass(frozen=True)
class StableIdentifiers:
    """The identifiers the issuer holds privately and projects to pseudonyms."""

    holder_id: str
    pool_id: str
    authorization_id: str


def projected_commitment_signing_bytes(pc: dict) -> bytes:
    """The bytes the per-operation leaf key signs.

    The projected commitment in its exact declared field order — insertion order,
    NOT JCS. Sorting the keys here would change what was signed while leaving the
    evidence looking well-formed.
    """
    return json.dumps(pc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def evidence_digest_hex(evidence: dict) -> str:
    """The canonical evidence digest bound into the `independence_proof`.

    JCS (sorted keys) plus SHA3-256 — the other byte form, deliberately.
    """
    return digest_hex_text(jcs_canonicalize_string(evidence))


def assemble_evidence(
    *,
    signed_level1: dict,
    certificate_commitment_digest: str,
    consumed_quantity: str,
    declared_effective_units: str,
    issued_at: str,
    expires_at: str,
    stable: StableIdentifiers,
    key_set: HolderKeySet,
    leaf_index: int,
    operation_salt: bytes,
) -> dict:
    """Assemble zero-data capacity evidence for one commitment.

    Fails early if the key set root does not match the authorized
    `holder_key_set_root`: the leaf-membership check the verifier performs would
    fail anyway, and failing here names the cause instead of leaving a rejected
    artifact to be diagnosed at the far end.

    `leaf_index` MUST NOT be reused across commitments, and `operation_salt` MUST
    be fresh per operation — reusing either makes two commitments linkable, which
    is exactly what the projection exists to prevent. Neither invariant is
    enforceable here: this module has no memory of previous operations.
    """
    level1_binding: dict[str, Any] = signed_level1["level1_binding"]
    level1_signature = signed_level1["level1_signature"]

    if key_set.root != level1_binding["holder_key_set_root"]:
        raise ValueError(
            f"key set root ({key_set.root}) does not match the authorized "
            f"holder_key_set_root ({level1_binding['holder_key_set_root']})"
        )

    holder_pseudonym = derive_pseudonym(operation_salt, "holder", stable.holder_id)
    pool_pseudonym = derive_pseudonym(operation_salt, "pool", stable.pool_id)
    authorization_pseudonym = derive_pseudonym(
        operation_salt, "authorization", stable.authorization_id
    )

    # Field order below IS the signed order — see the module docstring.
    projected_commitment = {
        "commitment_version": COMMITMENT_VERSION,
        "system_id": level1_binding["system_id"],
        "system_root_fingerprint": level1_binding["system_root_fingerprint"],
        "rules_version": level1_binding["rules_version"],
        "authorization_pseudonym": authorization_pseudonym,
        "holder_pseudonym": holder_pseudonym,
        "pool_pseudonym": pool_pseudonym,
        "certificate_commitment_digest": certificate_commitment_digest,
        "consumed_quantity": consumed_quantity,
        "declared_effective_units": declared_effective_units,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }

    signature = key_set.sign(
        leaf_index, projected_commitment_signing_bytes(projected_commitment)
    )
    disclosure = key_set.disclosure(leaf_index)

    projected_authorization = {
        "system_id": level1_binding["system_id"],
        "rules_version": level1_binding["rules_version"],
        "system_root_fingerprint": level1_binding["system_root_fingerprint"],
        "authorized_role": level1_binding["authorized_role"],
        "authorization_issuer_kid": level1_binding["authorization_issuer_kid"],
        "valid_from": level1_binding["valid_from"],
        "valid_until": level1_binding["valid_until"],
        "holder_key_set_root": level1_binding["holder_key_set_root"],
        "level1_binding": level1_binding,
        "level1_signature": level1_signature,
        "authorization_pseudonym": authorization_pseudonym,
        "holder_pseudonym": holder_pseudonym,
    }

    return {
        "profile": ZERO_DATA_PROFILE,
        "operation_salt_hex": operation_salt.hex(),
        "projected_authorization": projected_authorization,
        "projected_commitment": projected_commitment,
        "operation_key": disclosure.to_wire(),
        "commitment_signature_b64": base64.b64encode(signature).decode("ascii"),
    }
