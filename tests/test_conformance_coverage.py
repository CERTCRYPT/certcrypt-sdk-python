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

"""Which primitive families this SDK accounts for, and why.

The parity tests answer "do the bytes match?". This file answers the question
that comes before it: "is anyone checking this family at all?". A family can be
added to the contract without any implementation reading it, and nothing fails,
because nothing requires anyone to. A contract can outgrow its consumers in
silence, and only a check like this one makes that loud.

This SDK is on the ISSUER side of the role table in the conformance README: it
mints certificates and capacity evidence. Verifier-only families do not apply,
and holding it to them would make conformance unachievable rather than stricter.
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PRIMITIVES = _REPO_ROOT.parent / "certcrypt-conformance" / "fixtures" / "primitives"

#: Families this SDK covers, each naming the test that reads its vector.
ACCOUNTED_FOR: dict[str, str] = {
    "capacity-evidence": "tests/test_evidence_and_inclusion.py",
    "ccvp-consistency": "tests/test_context_snapshot_certificate.py",
    "artifact-shape": "tests/test_artifact_shape_conformance.py",
    "composite-m-prime": "tests/test_composite_conformance.py",
    "original-material": "tests/test_artifact_shape_conformance.py",
    "submission-set": "tests/test_artifact_shape_conformance.py",
    "submission-set-limits": "tests/test_artifact_shape_conformance.py",
    "collection-merkle": "tests/test_collection_merkle.py",
    "holder-keyset": "tests/test_pseudonym_and_keyset.py",
    "key-derivation": "tests/test_key_derivation_conformance.py",
    "pseudonym": "tests/test_pseudonym_and_keyset.py",
    "subject-ai-decision": "tests/test_canonical_subject.py",
    "subject-binary": "tests/test_digest.py",
    "subject-collection": "tests/test_canonical_subject.py",
    "subject-context-snapshot": "tests/test_context_snapshot_conformance.py",
    "subject-email": "tests/test_canonical_subject.py",
    "subject-text": "tests/test_canonical_subject.py",
    "issuer-key-derivation": "tests/test_issuer_key_derivation_conformance.py",
    "ecdsa-p256-deterministic": "tests/test_ecdsa_p256_deterministic_conformance.py",
    "strict-json": "tests/test_strict_json_conformance.py",
}

#: Families in the contract that do not apply here, each with the reason.
#:
#: Entries marked ``GAP:`` are constructions this SDK DOES perform and does not
#: yet check. They are named rather than quietly absent: an acknowledged gap is a
#: task, an unlisted one is a surprise.
OUT_OF_SCOPE: dict[str, str] = {
    "independence-proof-signature": "composed and signed by the issuance service",
    "manifest-resolution": "resolution is the verifier's and the node's",
    "operator-receipt": "signed by a transporting node, not by an issuer SDK",
    "operator-domain-binding": "an SDK never signs or registers domain-binding statements: the node does",
    "rules-domain": "the domain table is consumed through the artifacts, not resolved here",
    "settlement-preimages": "assembled by the settlement side",
    "verification-package": (
        "an end-to-end golden whose proof and settlement material the system domain "
        "signs; this SDK assembles a package from those artifacts, it does not mint them"
    ),
    "composite-verification": "verifier-side: this SDK signs composites, it does not verify them",
    "level1-binding": (
        "the issuer receives a signed binding and carries it verbatim into the "
        "evidence; it neither reconstructs its bytes nor verifies its signature, so "
        "there is nothing here to hold to the vector. It becomes in scope the day an "
        "SDK checks the binding it was handed"
    ),
}


def test_every_claimed_family_exists_in_the_contract():
    """A family renamed upstream would leave a dead claim that keeps passing."""
    if not _PRIMITIVES.is_dir():
        return  # absence is reported by the sibling guard in conftest, loudly
    for family, test_file in ACCOUNTED_FOR.items():
        assert (_PRIMITIVES / family).is_dir(), (
            f"this SDK claims to cover '{family}' (via {test_file}), which the contract "
            "does not have — renamed or removed upstream, so the claim is now false"
        )


def test_every_claimed_test_file_exists():
    """An entry naming a deleted test would report coverage nothing provides."""
    for family, test_file in ACCOUNTED_FOR.items():
        assert (_REPO_ROOT / test_file).is_file(), (
            f"'{family}' claims to be covered by {test_file}, which does not exist — "
            "the coverage claim names nothing"
        )


def test_a_new_contract_family_must_be_classified():
    """A family the contract grows must be classified, not ignored.

    Someone has to look at a new vector and say which side it falls on. That
    decision is cheap; discovering months later that nobody made it is not.
    """
    if not _PRIMITIVES.is_dir():
        return
    classified = set(ACCOUNTED_FOR) | set(OUT_OF_SCOPE)
    unclassified = sorted(
        d.name for d in _PRIMITIVES.iterdir() if d.is_dir() and d.name not in classified
    )
    assert unclassified == [], (
        f"the contract carries families this SDK has not classified: {unclassified}. "
        "Add each to ACCOUNTED_FOR with the test that reads it, or to OUT_OF_SCOPE with "
        "the reason it does not apply. A family nobody classifies is a family nobody checks."
    )


def test_no_family_is_both_accounted_for_and_out_of_scope():
    """A family in both lists reads as covered to one reader and excused to another."""
    overlap = sorted(set(ACCOUNTED_FOR) & set(OUT_OF_SCOPE))
    assert overlap == [], f"{overlap} are both accounted for and out of scope"


def test_the_acknowledged_gaps_are_still_named():
    """Closing a gap means MOVING it to ACCOUNTED_FOR, never deleting the entry.

    Deleting it would erase the gap from the record without anything having been
    checked, which is the silence this whole file exists to break.
    """
    # "GAP:" or "GAP (implementation):" — the second marks a gap that cannot be
    # closed by reading the vector, because the construction is not implemented
    # here at all. Both are gaps and both must stay on the record.
    gaps = sorted(f for f, why in OUT_OF_SCOPE.items() if why.startswith("GAP"))
    assert gaps == [], (
        "the recorded gaps changed: close one by moving it to ACCOUNTED_FOR, never by "
        "removing it"
    )
