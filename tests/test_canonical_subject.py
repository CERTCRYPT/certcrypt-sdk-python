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

"""`canonical_bytes(subject)` against the published conformance vectors.

These vectors carry `canonical_hex`, so the assertion is on the canonical BYTES
rather than only on their digest. That matters: two different canonicalizations
can hash to different values without telling you which byte moved, and the
edge cases here — a lone CR, a folded header with a HTAB, an empty body — are
exactly where an implementation drifts.

The vectors live in `certcrypt-conformance` and are not vendored: the contract is
versioned separately and a copy would drift. Absent the sibling checkout these
tests skip with a message naming what to check out.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.canonical_subject import (
    SUBJECT_AI_DECISION,
    SUBJECT_BINARY,
    SUBJECT_COLLECTION,
    SUBJECT_EMAIL,
    SUBJECT_TEXT,
    UnsupportedProfileError,
    canonical_bytes_for_subject)
from certcrypt.crypto.digest import digest_hex_bytes
from certcrypt.crypto.subject_json_preconditions import SubjectPreconditionError

_PRIMITIVES = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
)

pytestmark = pytest.mark.skipif(
    not _PRIMITIVES.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_PRIMITIVES})"
    ))


def _load(name: str):
    return json.loads((_PRIMITIVES / name / "vectors.json").read_text("utf-8"))["vectors"]


def _byte_profile_cases():
    """(profile, vector) for the raw-byte profiles, which share a vector shape."""
    for name, profile in (("subject-text", SUBJECT_TEXT), ("subject-email", SUBJECT_EMAIL)):
        path = _PRIMITIVES / name / "vectors.json"
        if not path.exists():
            continue
        for vector in _load(name):
            yield pytest.param(profile, vector, id=f"{name}:{vector['name']}")


@pytest.mark.parametrize("profile,vector", list(_byte_profile_cases()))
def test_raw_byte_profiles_match_canonical_bytes(profile, vector):
    got = canonical_bytes_for_subject(profile, bytes.fromhex(vector["input_hex"]))
    assert got.hex() == vector["canonical_hex"]
    assert digest_hex_bytes(got) == vector["subject_local_digest_hex"]


def test_binary_is_byte_identity():
    """`subject.binary/1` canonical bytes ARE the input bytes — no transformation.

    Pinned on the cases a well-meaning implementation would "fix": a BOM, an
    embedded NUL, and a lone CR that the text profile would rewrite to CRLF.
    """
    for raw in (b"", b"\xef\xbb\xbfhello", b"a\x00b", b"line\rnext", b"\xff\xfe"):
        assert canonical_bytes_for_subject(SUBJECT_BINARY, raw) == raw


def test_collection_matches_expected_canonical_utf8():
    for vector in _load("subject-collection"):
        material = json.dumps(vector["collection_subject"]).encode("utf-8")
        got = canonical_bytes_for_subject(SUBJECT_COLLECTION, material)
        assert got.decode("utf-8") == vector["expected_canonical_utf8"]
        assert digest_hex_bytes(got) == vector["expected_subject_local_digest_hex"]


def test_ai_decision_matches_expected_canonical_utf8():
    for vector in _load("subject-ai-decision"):
        material = json.dumps(vector["decision_record"]).encode("utf-8")
        got = canonical_bytes_for_subject(SUBJECT_AI_DECISION, material)
        assert got.decode("utf-8") == vector["expected_canonical_utf8"]
        assert digest_hex_bytes(got) == vector["expected_subject_local_digest_hex"]


def test_ai_decision_rejects_utf8_bom():
    with pytest.raises(SubjectPreconditionError, match="must not begin with a UTF-8 BOM"):
        canonical_bytes_for_subject(SUBJECT_AI_DECISION, b"\xef\xbb\xbf{}")


def test_json_subjects_canonicalize_the_value_not_the_source_bytes():
    """Member order and whitespace in the source must not reach the digest."""
    vector = _load("subject-collection")[0]
    subject = vector["collection_subject"]
    compact = json.dumps(subject, separators=(",", ":"), sort_keys=True)
    spaced = json.dumps(subject, indent=4, sort_keys=False)
    assert canonical_bytes_for_subject(
        SUBJECT_COLLECTION, compact.encode("utf-8")
    ) == canonical_bytes_for_subject(SUBJECT_COLLECTION, spaced.encode("utf-8"))


def test_unsupported_profile_fails_closed():
    """An unknown profile must raise, never fall back to another profile."""
    with pytest.raises(UnsupportedProfileError) as excinfo:
        canonical_bytes_for_subject("subject.invented/9", b"x")
    assert excinfo.value.profile == "subject.invented/9"


def test_json_subject_rejects_non_conformant_value():
    # A JSON number anywhere breaks the string-only discipline.
    bad = json.dumps({"profile": SUBJECT_AI_DECISION, "decided_at": 1}).encode("utf-8")
    with pytest.raises(SubjectPreconditionError):
        canonical_bytes_for_subject(SUBJECT_AI_DECISION, bad)


def test_json_subject_rejects_invalid_utf8():
    """Invalid UTF-8 must raise rather than decode to U+FFFD.

    Substituting the replacement character would produce a digest for material
    that nobody — including this SDK on a later run — can reproduce.
    """
    with pytest.raises(UnicodeDecodeError):
        canonical_bytes_for_subject(SUBJECT_COLLECTION, b'{"a":"\xff\xfe"}')
