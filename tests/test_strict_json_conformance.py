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

"""Strict JSON parsing, against the contract (`strict-json`).

Which documents parse, which are refused, and which JSON subject materials are
refused before canonicalization. A material a verifier refuses must never
reach a commitment this SDK signs.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.canonical_subject import canonical_bytes_for_subject
from certcrypt.crypto.strict_json import StrictJsonError, strict_json_loads

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "strict-json"
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
    "case", _doc()["cases"] if _VECTORS.exists() else [], ids=lambda c: c["name"]
)
def test_strict_json_case(case):
    try:
        strict_json_loads(case["json_text"])
        got = "ACCEPT"
    except StrictJsonError:
        got = "REJECTED"
    assert got == case["expected"]


@pytest.mark.parametrize(
    "case",
    _doc()["profile_material_cases"] if _VECTORS.exists() else [],
    ids=lambda c: c["name"],
)
def test_json_subject_material_with_a_repeated_member_never_canonicalizes(case):
    try:
        canonical_bytes_for_subject(case["profile"], case["material_utf8"].encode("utf-8"))
        got = "ACCEPT"
    except Exception:  # noqa: BLE001 - any refusal counts; the vector pins the outcome
        got = "REJECTED"
    assert got == case["expected_outcome"]
