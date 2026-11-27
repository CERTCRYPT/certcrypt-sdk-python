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

"""The package's public surface: what an integrator may import, and what it must
not be able to.

A composite signature is valid only as the AND of its two components, so no
single-component signer, keygen or verifier is exported: with one in hand, a
caller could produce something shaped like a signature with no post-quantum
half. The helpers and wire identifiers below are exported because recomputing a
digest or recognizing an artifact needs exactly these bytes and names.
"""

import certcrypt


def test_no_single_signature_component_is_exported():
    for name in (
        "keygen_ml_dsa65",
        "sign_ml_dsa65",
        "verify_ml_dsa65",
        "generate_ecdsa_p256_key",
        "sign_ecdsa_p256_raw",
        "private_key_from_pkcs8",
        "public_key_b64_from_private",
    ):
        assert name not in certcrypt.__all__, f"{name} must not be exported"
        assert not hasattr(certcrypt, name), f"{name} must not be importable from the package"


def test_the_helper_set_is_exported():
    for name in (
        "build_collection",
        "resolve_collection_subjects",
        "digest_bytes",
        "digest_hex_bytes",
        "digest_hex_text",
        "jcs_canonicalize_bytes",
        "jcs_canonicalize_string",
        "compute_expires_at",
        "derive_issuer_key",
        "assemble_context_snapshot_certificate",
        "issuer_key_fingerprint_hex",
        "build_ai_decision_part",
        "build_ai_decision_subject",
    ):
        assert name in certcrypt.__all__, f"{name} must be exported"
        assert callable(getattr(certcrypt, name))


def test_the_wire_identifiers_are_exported_with_their_values():
    assert {
        "ZERO_DATA_PROFILE": certcrypt.ZERO_DATA_PROFILE,
        "COMMITMENT_LEAF_VERSION": certcrypt.COMMITMENT_LEAF_VERSION,
        "PROFILE_P256_MLDSA65": certcrypt.PROFILE_P256_MLDSA65,
        "COLLECTION_MERKLE_SCHEME": certcrypt.COLLECTION_MERKLE_SCHEME,
        "SUBJECT_CONTEXT_SNAPSHOT": certcrypt.SUBJECT_CONTEXT_SNAPSHOT,
    } == {
        "ZERO_DATA_PROFILE": "zero-data.unlinkable",
        "COMMITMENT_LEAF_VERSION": "ccab1-commit",
        "PROFILE_P256_MLDSA65": "certcrypt-composite-p256-mldsa65-v1",
        "COLLECTION_MERKLE_SCHEME": "collection.merkle-sha3-256/1",
        "SUBJECT_CONTEXT_SNAPSHOT": "subject.context-snapshot/1",
    }
    for name in (
        "ZERO_DATA_PROFILE",
        "COMMITMENT_LEAF_VERSION",
        "PROFILE_P256_MLDSA65",
        "COLLECTION_MERKLE_SCHEME",
        "SUBJECT_CONTEXT_SNAPSHOT",
    ):
        assert name in certcrypt.__all__


def test_every_implemented_subject_profile_is_listed_as_supported():
    assert certcrypt.SUPPORTED_SUBJECT_PROFILES == [
        "subject.binary/1",
        "subject.text/1",
        "subject.email/1",
        "subject.collection/1",
        "subject.ai-decision/1",
        "subject.context-snapshot/1",
    ]
