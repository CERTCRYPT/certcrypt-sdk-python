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

"""The preimages this SDK signs and the material it commits to, against the contract.

Three things a producer gets to be wrong about on its own, with nothing local
noticing:

- the FIELD SET of a signed preimage. One field too many and the digest is
  perfectly correct over the wrong object; the failure surfaces only when a
  verifier reconstructs the full preimage.
- the subject commitment construction, which is the ASCII concatenation of two
  hex STRINGS rather than of the binary digests they denote.
- the submission-set id, recomputed over the set with its own id removed.

None of them is checked by this SDK's other tests, because this SDK never
recomputes its own output.
"""

import json
from pathlib import Path

import pytest

from certcrypt.artifacts.base_certificate import compute_subject_commitment
from certcrypt.artifacts.capacity_evidence import (
    MAX_SUBMISSION_SET_MEMBERS,
    SubmissionSetTooLargeError,
    assert_submission_set_within_bound,
    projected_commitment_signing_bytes,
)
from certcrypt.crypto.digest import digest_hex_bytes
from certcrypt.crypto.jcs import jcs_canonicalize_bytes

_PRIMITIVES = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
)

pytestmark = pytest.mark.skipif(
    not _PRIMITIVES.is_dir(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_PRIMITIVES})"
    ),
)


def _vectors(family: str) -> dict:
    return json.loads((_PRIMITIVES / family / "vectors.json").read_text("utf-8"))


def test_projected_commitment_field_set_matches_the_contract():
    """Both directions: no field missing, no field extra.

    Round-tripped through this SDK's own emitter, so what is compared is what it
    would actually sign — not the fixture echoed back.
    """
    shape = _vectors("artifact-shape")
    evidence = _vectors("capacity-evidence")

    entry = next(
        a
        for a in shape["artifacts"]
        if a["artifact"] == "capacity.evidence/1 — projected commitment"
    )
    emitted = list(
        json.loads(
            projected_commitment_signing_bytes(
                evidence["projected_commitment"]
            ).decode("utf-8")
        )
    )
    assert emitted == entry["fields"], (
        "the projected commitment this SDK signs differs from the contract's field set — "
        "a field added or dropped changes the signed bytes while every digest stays "
        "internally correct"
    )


def test_projected_commitment_bytes_match_the_contract():
    """The shape check cannot see field ORDER, and this artifact is insertion-ordered."""
    evidence = _vectors("capacity-evidence")
    got = projected_commitment_signing_bytes(evidence["projected_commitment"])
    assert got.decode("utf-8") == evidence["expected_signing_bytes_utf8"], (
        "projected commitment signing bytes diverged — JCS vs insertion order, "
        "or field order"
    )


def test_subject_commitments_match_the_contract():
    v = _vectors("original-material")
    for s in v["subjects"]:
        got = compute_subject_commitment(
            v["nonce_hex"], s["expected_subject_local_digest_hex"]
        )
        assert got == s["expected_commitment_digest_hex"], (
            f"subject {s['index']} ({s['profile']}): commitment diverged — the "
            "construction is SHA3-256 over the ASCII of the two hex strings, not over "
            "the bytes they denote"
        )


def test_hashing_the_raw_digest_bytes_gives_a_different_commitment():
    """The named mistake, reproduced so the distinction stays pinned.

    If these ever coincided, the test above would stop discriminating between the
    right construction and the wrong one.
    """
    v = _vectors("original-material")
    s = v["subjects"][0]
    raw = bytes.fromhex(v["nonce_hex"]) + bytes.fromhex(
        s["expected_subject_local_digest_hex"]
    )
    assert digest_hex_bytes(raw) != s["expected_commitment_digest_hex"], (
        "hashing the raw bytes must NOT produce the contract's commitment"
    )


def test_submission_set_id_recomputes_to_the_contract_value():
    v = _vectors("submission-set")
    artifact = _PRIMITIVES / "submission-set" / v["submission_set_artifact_path"]
    if not artifact.is_file():
        pytest.skip(f"the contract carries no {v['submission_set_artifact_path']}")

    full = json.loads(artifact.read_text("utf-8"))
    # A set cannot commit to a value derived from itself, so the id is the digest
    # of the set with the id field removed.
    no_id = {k: val for k, val in full.items() if k != "submission_set_id"}
    assert digest_hex_bytes(jcs_canonicalize_bytes(no_id)) == v[
        "expected_submission_set_id"
    ], "submission_set_id diverged — the no-id view, or JCS vs insertion order"


def test_the_member_cap_is_the_contracts():
    """Not a digest: a number that decides ADMISSION.

    An SDK capping at one value and a service at another disagree about whether a
    set is well-formed, and the disagreement surfaces as a rejection nobody can
    reproduce.
    """
    limits = _vectors("submission-set-limits")
    assert (
        MAX_SUBMISSION_SET_MEMBERS == limits["member_cap"]["max_submission_set_members"]
    ), "this SDK's member cap differs from the contract's"


@pytest.mark.parametrize(
    "case", _vectors("submission-set-limits")["cardinality_cases"] if _PRIMITIVES.is_dir() else [],
    ids=lambda c: c["name"],
)
def test_cardinality_cases_resolve_as_the_contract_says(case):
    """Every boundary the contract enumerates, including the two that bite.

    Exactly at the cap is admissible (a `<` instead of `<=` would reject a set
    every other implementation accepts) and the empty set is refused where it is
    assembled.
    """
    n = case["member_count"]
    if case["expected_outcome"] == "admitted":
        assert_submission_set_within_bound(n)
    else:
        with pytest.raises((SubmissionSetTooLargeError, ValueError)):
            assert_submission_set_within_bound(n)


def test_the_system_id_signed_into_preimages_is_the_contracts():
    """It sits inside signed bytes, so a divergent value is a different digest."""
    limits = _vectors("submission-set-limits")
    evidence = _vectors("capacity-evidence")
    assert (
        evidence["projected_commitment"]["system_id"]
        == limits["system_constants"]["system_id"]["value"]
    ), "the contract's own vectors disagree about system_id"
