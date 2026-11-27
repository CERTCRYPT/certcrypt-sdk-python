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

"""CERTCRYPT SDK for Python — issuer side.

Every byte this SDK produces is pinned by the CERTCRYPT conformance families,
so a certificate minted here verifies under any
CERTCRYPT verifier, in any language — that is the property the whole design
exists to produce, and it is pinned by tests that hand what this SDK produces to
the reference verifier.

**Server-side only.** The issuer seed is the issuer's identity: anyone holding it
can issue as you. It must never reach a browser bundle or a client device.

What is deliberately NOT exported: single signature components. A composite is
valid only as the AND of all of them, so exposing one would hand out a way to
produce something that looks like a signature but carries no post-quantum half.
"""

__version__ = "1.0.0"

from .artifacts.base_certificate import (
    IssuerKey,
    MintedCertificate,
    ResolvedCollection,
    SubjectInput,
    assemble_base_certificate,
    assemble_context_snapshot_certificate,
    compute_expires_at,
    derive_issuer_key,
    generate_issuer_key,
    generate_nonce_hex,
    issuer_key_fingerprint_hex,
    resolve_collection_subjects,
)
from .artifacts.capacity_evidence import (
    ZERO_DATA_PROFILE,
    StableIdentifiers,
    assemble_evidence,
    evidence_digest_hex,
    MAX_SUBMISSION_SET_MEMBERS,
    SubmissionSetTooLargeError,
    assert_submission_set_within_bound,
)
from .artifacts.commitment_inclusion import (
    COMMITMENT_LEAF_VERSION,
    build_commitment_inclusion_proof,
    commitment_subtree_root,
)
from .artifacts.holder_keyset import HolderKeySet, OperationKey, OperationKeyDisclosure
from .artifacts.rfc3339 import to_rfc3339_seconds
from .artifacts.base_certificate import (
    assemble_unsigned_payload,
    compute_anchor_commitment,
    compute_subject_commitment,
    payload_canon_digest_hex,
    subject_local_digest_hex,
)
from .artifacts.capacity_evidence import projected_commitment_signing_bytes
from .artifacts.commitment_inclusion import commitment_leaf_hash
from .client import (
    ActivationResult,
    CertcryptNodeClient,
    CertcryptNodeError,
    DeadLetter,
    WaitProgress,
)
from .crypto.collection_merkle import (
    COLLECTION_MERKLE_SCHEME,
    BuiltCollection,
    collection_inclusion_proof,
    collection_leaf_hash,
    collection_merkle_root,
    collection_node_hash,
)
from .crypto.composite import PROFILE_P256_MLDSA65, composite_m_prime, composite_sign_p256
from .issuer import (
    SUPPORTED_RULES_VERSIONS,
    register_rules_domain,
    BindingStore,
    BindingStoreEntry,
    Certcrypt,
    EmissionHandle,
    EmissionResolution,
    InMemoryLeafStore,
    IssueResult,
    PreparedCommitment,
    SubmitResult,
    IssuerMode,
    LeafStore,
    SettlementPreferences,
)
# The transport-retry policy in `retry.py`, exported so
# an integrator wrapping its own transport can apply the same decisions.
from .retry import (
    RETRY_AFTER_MAX_MS,
    RETRY_AFTER_MIN_MS,
    RETRY_DEFAULTS,
    RetryDecision,
    RetryPolicy,
    TransportOutcome,
    decide_retry,
    parse_retry_after,
)
from .crypto.canonical_subject import (
    SUBJECT_AI_DECISION,
    SUBJECT_BINARY,
    SUBJECT_COLLECTION,
    SUBJECT_CONTEXT_SNAPSHOT,
    SUBJECT_EMAIL,
    SUBJECT_TEXT,
    SUPPORTED_SUBJECT_PROFILES,
    UnsupportedProfileError,
    canonical_bytes_for_subject,
)
from .crypto.collection_merkle import CollectionLeafInput, build_collection
from .crypto.digest import digest_bytes, digest_hex_bytes, digest_hex_text
from .crypto.ai_decision import (
    AiDecisionMaterialInput,
    BuiltAiDecisionPart,
    BuiltAiDecisionSubject,
    build_ai_decision_part,
    build_ai_decision_subject,
)
from .crypto.jcs import jcs_canonicalize_bytes, jcs_canonicalize_string
from .crypto.subject_json_preconditions import SubjectPreconditionError
from .types import (
    IssueResponse,
    LooseCommitment,
    MemberResult,
    OperationRecord,
    SettlementProgress,
    SettlementWindowEstimate,
    UnresolvedEmission,
    UnresolvedEmissions,
)

__all__ = [
    "SUPPORTED_RULES_VERSIONS",
    "register_rules_domain",
    "__version__",
    # The issuance surface
    "Certcrypt",
    "IssuerMode",
    "IssueResult",
    "PreparedCommitment",
    "SubmitResult",
    "EmissionHandle",
    "EmissionResolution",
    "SettlementPreferences",
    "LeafStore",
    "InMemoryLeafStore",
    "BindingStore",
    "BindingStoreEntry",
    # Issuance building blocks
    "SubjectInput",
    "AiDecisionMaterialInput",
    "BuiltAiDecisionPart",
    "BuiltAiDecisionSubject",
    "build_ai_decision_part",
    "build_ai_decision_subject",
    "IssuerKey",
    "MintedCertificate",
    "assemble_base_certificate",
    # CCVP/1: a context snapshot certificate, and the composite key fingerprint
    # its entries and a certificate's declared context name.
    "assemble_context_snapshot_certificate",
    "issuer_key_fingerprint_hex",
    "derive_issuer_key",
    "generate_issuer_key",
    "generate_nonce_hex",
    "compute_expires_at",
    "resolve_collection_subjects",
    "ResolvedCollection",
    "assemble_unsigned_payload",
    "payload_canon_digest_hex",
    "compute_subject_commitment",
    "compute_anchor_commitment",
    "subject_local_digest_hex",
    # Collections
    "CollectionLeafInput",
    "BuiltCollection",
    "build_collection",
    "COLLECTION_MERKLE_SCHEME",
    "collection_leaf_hash",
    "collection_node_hash",
    "collection_merkle_root",
    "collection_inclusion_proof",
    "build_commitment_inclusion_proof",
    "commitment_leaf_hash",
    "commitment_subtree_root",
    "COMMITMENT_LEAF_VERSION",
    # Composite signing
    "PROFILE_P256_MLDSA65",
    "MAX_SUBMISSION_SET_MEMBERS",
    "SubmissionSetTooLargeError",
    "assert_submission_set_within_bound",
    "composite_m_prime",
    "composite_sign_p256",
    "projected_commitment_signing_bytes",
    # Capacity evidence
    "ZERO_DATA_PROFILE",
    "StableIdentifiers",
    "assemble_evidence",
    "evidence_digest_hex",
    "HolderKeySet",
    "OperationKey",
    "OperationKeyDisclosure",
    # Node
    "ActivationResult",
    "CertcryptNodeClient",
    "CertcryptNodeError",
    "WaitProgress",
    "DeadLetter",
    "LooseCommitment",
    "IssueResponse",
    "MemberResult",
    "OperationRecord",
    "SettlementWindowEstimate",
    "SettlementProgress",
    # Recovery: what an integration still has open. `truncated` MUST be checked —
    # a truncated page read as complete becomes a re-emission.
    "UnresolvedEmission",
    "UnresolvedEmissions",
    # Transport retry
    "decide_retry",
    "parse_retry_after",
    "RETRY_DEFAULTS",
    "RETRY_AFTER_MIN_MS",
    "RETRY_AFTER_MAX_MS",
    "RetryPolicy",
    "RetryDecision",
    "TransportOutcome",
    # Byte-contract primitives a caller legitimately needs
    "canonical_bytes_for_subject",
    "SUPPORTED_SUBJECT_PROFILES",
    "SUBJECT_BINARY",
    "SUBJECT_TEXT",
    "SUBJECT_EMAIL",
    "SUBJECT_COLLECTION",
    "SUBJECT_AI_DECISION",
    "SUBJECT_CONTEXT_SNAPSHOT",
    "digest_bytes",
    "digest_hex_bytes",
    "digest_hex_text",
    "jcs_canonicalize_bytes",
    "jcs_canonicalize_string",
    "to_rfc3339_seconds",
    # Errors a caller branches on
    "UnsupportedProfileError",
    "SubjectPreconditionError",
]
