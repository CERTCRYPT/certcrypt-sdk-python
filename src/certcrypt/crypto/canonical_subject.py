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

"""`canonical_bytes(subject)` dispatch by subject profile, issuer side.

The issuer derives
the SAME `subject_local_digest_hex = SHA3-256(canonical_bytes)` the verifier
recomputes from the original material. Any one-byte divergence breaks the
subject commitment cross-language. Pinned by the conformance fixtures under
`fixtures/primitives/subject-*`.

Supported profiles: `subject.binary/1`, `subject.text/1`, `subject.email/1`,
`subject.collection/1`, `subject.ai-decision/1`, and
`subject.context-snapshot/1`. An unsupported profile MUST
fail closed — the caller maps `UnsupportedProfileError` to that outcome rather
than falling back to another profile.

The subject canonicalization context is opaque bytes at the CCCP layer, so
`subject.text/1` and `subject.email/1` operate on the RAW bytes and never decode
or re-encode through a platform string. That is deliberate: routing text through
`str` would invite the platform to normalize line endings, strip a BOM, or
substitute U+FFFD for invalid UTF-8, and each of those silently changes the
committed digest.
"""

from typing import Any

from .jcs import jcs_canonicalize_bytes
from .strict_json import strict_json_loads
from .subject_json_preconditions import (
    SubjectPreconditionError,
    assert_context_snapshot_precondition,
    assert_ai_decision_precondition,
    assert_collection_precondition,
)

_AI_DECISION_MAX_RECORD_BYTES = 1024 * 1024

__all__ = [
    "SUBJECT_BINARY",
    "SUBJECT_TEXT",
    "SUBJECT_EMAIL",
    "SUBJECT_COLLECTION",
    "SUBJECT_AI_DECISION",
    "SUBJECT_CONTEXT_SNAPSHOT",
    "SUPPORTED_SUBJECT_PROFILES",
    "UnsupportedProfileError",
    "canonical_bytes_for_subject",
]

SUBJECT_BINARY = "subject.binary/1"
SUBJECT_TEXT = "subject.text/1"
SUBJECT_EMAIL = "subject.email/1"
SUBJECT_COLLECTION = "subject.collection/1"
SUBJECT_AI_DECISION = "subject.ai-decision/1"
SUBJECT_CONTEXT_SNAPSHOT = "subject.context-snapshot/1"

#: Profiles the SDK supports for `canonical_bytes` construction.
SUPPORTED_SUBJECT_PROFILES = [
    SUBJECT_BINARY,
    SUBJECT_TEXT,
    SUBJECT_EMAIL,
    SUBJECT_COLLECTION,
    SUBJECT_AI_DECISION,
    SUBJECT_CONTEXT_SNAPSHOT,
]

_CR = 0x0D
_LF = 0x0A
_SP = 0x20
_HTAB = 0x09
_CRLF = bytes((_CR, _LF))


class UnsupportedProfileError(Exception):
    """Raised when a subject declares a profile the SDK does not support."""

    def __init__(self, profile: str) -> None:
        super().__init__(f"unsupported subject profile: {profile}")
        self.profile = profile


def _is_wsp(b: int) -> bool:
    return b == _SP or b == _HTAB


def _normalize_line_endings(data: bytes) -> bytearray:
    """Normalize CR, LF and CRLF to CRLF in a single left-to-right pass.

    CRLF is matched before lone CR or lone LF (longest match first); a naive
    pass that mapped CR then LF would turn one CRLF into two.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        if data[i] == _CR and i + 1 < n and data[i + 1] == _LF:
            out += _CRLF
            i += 2
        elif data[i] == _CR or data[i] == _LF:
            out += _CRLF
            i += 1
        else:
            out.append(data[i])
            i += 1
    return out


def _collapse_trailing_crlf(data: bytes | bytearray) -> bytearray:
    """Collapse the maximal trailing CRLF run to exactly one CRLF."""
    end = len(data)
    while end >= 2 and data[end - 2] == _CR and data[end - 1] == _LF:
        end -= 2
    out = bytearray(data[:end])
    out += _CRLF
    return out


def _canonicalize_text(material: bytes) -> bytes:
    """`subject.text/1`: CRLF line endings, exactly one trailing CRLF."""
    return bytes(_collapse_trailing_crlf(_normalize_line_endings(material)))


def _canonicalize_email(material: bytes) -> bytes:
    """`subject.email/1`: CRLF normalization, header unfolding, body terminator.

    Operates on raw bytes; no MIME decoding.
    """
    m = _normalize_line_endings(material)

    # Split at the FIRST CRLF CRLF. The four-byte delimiter may end at the final
    # byte, so the last candidate index is len(m) - 4.
    split = -1
    for i in range(len(m) - 3):
        if m[i] == _CR and m[i + 1] == _LF and m[i + 2] == _CR and m[i + 3] == _LF:
            split = i
            break

    if split == -1:
        headers = m
        body = bytearray()
    else:
        headers = m[:split]
        body = m[split + 4 :]

    # Unfold headers only (RFC 5322 §2.2.3): each CRLF immediately followed by a
    # WSP byte is deleted. The WSP itself is preserved byte-for-byte, including
    # SP-vs-HTAB identity and run length — collapsing it would change the digest.
    unfolded = bytearray()
    i = 0
    n = len(headers)
    while i < n:
        if (
            headers[i] == _CR
            and i + 2 < n
            and headers[i + 1] == _LF
            and _is_wsp(headers[i + 2])
        ):
            i += 2  # drop the CRLF; the WSP is emitted on the next iteration
        else:
            unfolded.append(headers[i])
            i += 1

    # A non-empty body ends in exactly one CRLF; an empty body stays empty.
    body_out = _collapse_trailing_crlf(body) if len(body) > 0 else bytearray()

    # Assembly: headers_unfolded || CRLF CRLF || body (delimiter always present).
    return bytes(unfolded + _CRLF + _CRLF + body_out)


def _canonicalize_json_subject(profile: str, material: bytes) -> bytes:
    """JSON-object subjects: parse, enforce the precondition, JCS the VALUE.

    The value is canonicalized, not the source bytes, so member order and
    whitespace in the input do not reach the digest. The string-only discipline
    enforced by the precondition keeps JCS free of number serialization.

    Decoding is strict UTF-8: invalid bytes raise rather than becoming U+FFFD,
    which would produce a digest for material nobody can reproduce.
    """
    if profile == SUBJECT_AI_DECISION and len(material) > _AI_DECISION_MAX_RECORD_BYTES:
        raise SubjectPreconditionError(profile, "record source exceeds 1 MiB")
    if profile == SUBJECT_AI_DECISION and material.startswith(b"\xef\xbb\xbf"):
        raise SubjectPreconditionError(
            profile, "record source must not begin with a UTF-8 BOM"
        )
    text = material.decode("utf-8")  # strict by default; raises UnicodeDecodeError
    # Strict parse: a member name repeated at any depth makes the material
    # non-conformant, so it fails closed instead of being canonicalized from
    # whichever duplicate a parser keeps.
    value: Any = strict_json_loads(text)
    if profile == SUBJECT_COLLECTION:
        assert_collection_precondition(value)
    elif profile == SUBJECT_AI_DECISION:
        assert_ai_decision_precondition(value)
    else:
        # context-snapshot fixes no member set: the snapshot shape is governed by
        # CCVP/1, not by this profile. What it does fix — and all it fixes here —
        # is the absence of JSON numbers, which keeps JCS free of number
        # serialization, the one practical cross-language divergence vector.
        assert_context_snapshot_precondition(value)
    canonical = jcs_canonicalize_bytes(value)
    if profile == SUBJECT_AI_DECISION and len(canonical) > _AI_DECISION_MAX_RECORD_BYTES:
        raise SubjectPreconditionError(profile, "canonical record exceeds 1 MiB")
    return canonical


def canonical_bytes_for_subject(profile: str, material: bytes) -> bytes:
    """Compute `canonical_bytes(subject)` under the declared profile.

    - `subject.binary/1`: the exact input bytes, opaque, no transformation.
    - `subject.text/1`: line-ending normalization plus a single trailing CRLF,
      every other byte preserved.
    - `subject.email/1`: CRLF normalization, header/body split, RFC 5322 header
      unfolding (WSP preserved), body terminator normalization.
    - `subject.collection/1` / `subject.ai-decision/1`: UTF-8 bytes of the RFC
      8785 serialization of the parsed JSON value, after the profile
      precondition.

    Raises `UnsupportedProfileError` for any other declared profile.
    """
    if profile == SUBJECT_BINARY:
        # Opaque byte array: canonical_bytes == exact input bytes.
        return material
    if profile == SUBJECT_TEXT:
        return _canonicalize_text(material)
    if profile == SUBJECT_EMAIL:
        return _canonicalize_email(material)
    if profile in (SUBJECT_COLLECTION, SUBJECT_AI_DECISION, SUBJECT_CONTEXT_SNAPSHOT):
        return _canonicalize_json_subject(profile, material)
    raise UnsupportedProfileError(profile)
