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

"""The JSON-object subject profiles, against the contract.

`subject.context-snapshot/1` canonical bytes, and for the three JSON-object
profiles the precondition's shared surface: every ``negative_cases`` entry is
refused and every ``positive_cases`` entry is accepted with its pinned canonical
bytes. A subject canonicalized differently produces a different subject digest,
hence a different commitment, hence a certificate that resolves to nothing a
verifier can reproduce.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.canonical_subject import (
    SUBJECT_CONTEXT_SNAPSHOT,
    canonical_bytes_for_subject,
)
from certcrypt.crypto.digest import digest_hex_bytes
from certcrypt.crypto.jcs import jcs_canonicalize_bytes
from certcrypt.crypto.subject_json_preconditions import (
    SubjectPreconditionError,
    assert_ai_decision_precondition,
    assert_collection_precondition,
    assert_context_snapshot_precondition,
)

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "subject-context-snapshot"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not _VECTORS.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_VECTORS})"
    ),
)


def _doc() -> dict:
    return json.loads(_VECTORS.read_text("utf-8"))


@pytest.mark.parametrize(
    "vector", _doc()["vectors"] if _VECTORS.exists() else [], ids=lambda v: v["name"]
)
def test_context_snapshot_canonical_bytes_match_the_contract(vector):
    material = json.dumps(vector["snapshot_object"]).encode("utf-8")
    canonical = canonical_bytes_for_subject(SUBJECT_CONTEXT_SNAPSHOT, material)
    assert canonical.decode("utf-8") == vector["expected_canonical_utf8"], (
        f"context-snapshot '{vector['name']}': canonical bytes diverged"
    )
    assert digest_hex_bytes(canonical) == vector["subject_local_digest_hex"], (
        f"context-snapshot '{vector['name']}': subject digest diverged"
    )


def test_the_profile_id_is_the_contracts():
    assert SUBJECT_CONTEXT_SNAPSHOT == _doc()["profile"], (
        "the profile id is carried in the certificate, so a divergent one is not a mislabel"
    )


_PRIMITIVES = _VECTORS.parents[1]

_JSON_PROFILES = [
    ("subject-collection", "collection_subject", assert_collection_precondition),
    ("subject-ai-decision", "decision_record", assert_ai_decision_precondition),
    ("subject-context-snapshot", "snapshot_object", assert_context_snapshot_precondition),
]


@pytest.mark.parametrize("folder,key,precondition", _JSON_PROFILES, ids=lambda x: x if isinstance(x, str) else "")
def test_negative_cases_are_refused_and_positive_cases_accepted(folder, key, precondition):
    doc = json.loads((_PRIMITIVES / folder / "vectors.json").read_text("utf-8"))
    negatives = doc.get("negative_cases", [])
    assert negatives, f"{folder} carries no negative_cases"
    for case in negatives:
        with pytest.raises(SubjectPreconditionError):
            precondition(case[key])
    for case in doc.get("positive_cases", []):
        precondition(case[key])
        canonical = jcs_canonicalize_bytes(case[key])
        assert canonical.decode("utf-8") == case["expected_canonical_bytes_utf8"], case["name"]
        assert digest_hex_bytes(canonical) == case["expected_digest_hex"], case["name"]
