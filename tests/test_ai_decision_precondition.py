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

"""Closed multimodal precondition for `subject.ai-decision/1`."""

import pytest

from certcrypt.crypto.subject_json_preconditions import (
    SubjectPreconditionError,
    assert_ai_decision_precondition,
)

HEX = "a" * 64
NONCE_A = "1" * 64
NONCE_B = "2" * 64


def record(**overrides):
    base = {
        "profile": "subject.ai-decision/1",
        "decision_id": "decision-1",
        "decided_at": "2026-08-16T12:00:00.000Z",
        "model": {"id": "m-1", "provider": "acme"},
        "observation_scope": "client",
        "input": [part("prompt", "user")],
        "output": [part("answer", "assistant")],
        "decision": "approved",
    }
    base.update(overrides)
    return base


def part(
    identifier,
    role,
    profile="subject.text/1",
    media_type="text/plain",
    commitment=HEX,
    nonce=None,
):
    return {
        "id": identifier,
        "role": role,
        "media_type": media_type,
        "profile": profile,
        "material_nonce_hex": nonce or (NONCE_A if identifier in ("prompt", "payload", "image") else NONCE_B),
        "commitment_digest_hex": commitment,
    }


def test_minimal_record_is_accepted():
    assert_ai_decision_precondition(record())
    assert_ai_decision_precondition(record(parameters={}))
    assert_ai_decision_precondition(record(parameters={"temperature": "0.0"}))
    assert_ai_decision_precondition(
        record(
            observation_scope="runtime",
            started_at="2026-08-16T11:59:59.000Z",
            context={"purpose_ref": "purpose-1"},
        )
    )


@pytest.mark.parametrize("value", [["a"], {"x": "1"}])
def test_parameters_members_must_be_flat_strings(value):
    with pytest.raises(SubjectPreconditionError, match="parameters.k"):
        assert_ai_decision_precondition(record(parameters={"k": value}))


@pytest.mark.parametrize("bad", ["aa", "A" * 64, "g" * 64, HEX + "\n"])
def test_commitment_digest_hex_must_be_64_lowercase_hex(bad):
    with pytest.raises(SubjectPreconditionError, match="commitment_digest_hex"):
        assert_ai_decision_precondition(record(output=[part("answer", "assistant", commitment=bad)]))


@pytest.mark.parametrize("bad", ["aa", "A" * 64, "g" * 64, NONCE_A + "\n"])
def test_material_nonce_hex_must_be_64_lowercase_hex(bad):
    with pytest.raises(SubjectPreconditionError, match="material_nonce_hex"):
        assert_ai_decision_precondition(record(output=[part("answer", "assistant", nonce=bad)]))


@pytest.mark.parametrize(
    "profile", ["subject.collection/1", "subject.context-snapshot/1", "subject.unknown/1"]
)
def test_io_profile_outside_the_admitted_set_is_refused(profile):
    with pytest.raises(SubjectPreconditionError, match="admitted material profile"):
        assert_ai_decision_precondition(record(input=[part("payload", "user", profile=profile)]))


@pytest.mark.parametrize(
    "profile", ["subject.text/1", "subject.binary/1", "subject.email/1", "subject.ai-decision/1"]
)
def test_io_profile_in_the_admitted_set_is_accepted(profile):
    assert_ai_decision_precondition(record(input=[part("payload", "user", profile=profile)]))


@pytest.mark.parametrize(
    "ok", ["2026-08-16T12:00:00.000Z", "2024-02-29T23:59:59.999Z"]
)
def test_decided_at_valid_spellings(ok):
    assert_ai_decision_precondition(record(decided_at=ok))


@pytest.mark.parametrize(
    "bad",
    [
        "2026-08-16 12:00:00.000Z",
        "2026-08-16t12:00:00.000z",
        "2026-13-16T12:00:00.000Z",
        "2026-08-16T12:00:00",
        "2026-08-16T12:00:00Z",
        "2026-08-16T12:00:00.000Z\n",
        "２０２６-08-16T12:00:00.000Z",
        "2026-02-30T12:00:00.000Z",
        "2026-08-16T12:00:00.5Z",
        "2026-08-16T12:00:00.0000Z",
        "2026-08-16T12:00:00.000+02:00",
    ],
)
def test_decided_at_invalid_spellings(bad):
    with pytest.raises(SubjectPreconditionError, match="decided_at"):
        assert_ai_decision_precondition(record(decided_at=bad))


def test_started_at_must_not_follow_decided_at():
    with pytest.raises(SubjectPreconditionError, match="must not be after"):
        assert_ai_decision_precondition(record(started_at="2026-08-16T12:00:00.001Z"))


def test_material_ids_are_global_and_canonical():
    with pytest.raises(SubjectPreconditionError, match="decision_id"):
        assert_ai_decision_precondition(record(decision_id="Bad ID"))
    with pytest.raises(SubjectPreconditionError, match="duplicated"):
        assert_ai_decision_precondition(record(output=[part("prompt", "assistant")]))


def test_material_nonces_are_global_across_input_and_output():
    with pytest.raises(SubjectPreconditionError, match="material nonce.*duplicated"):
        assert_ai_decision_precondition(
            record(output=[part("answer", "assistant", nonce=NONCE_A)])
        )


def test_legacy_digest_member_is_refused_by_the_closed_shape():
    legacy = part("answer", "assistant")
    legacy["digest_hex"] = legacy.pop("commitment_digest_hex")
    with pytest.raises(SubjectPreconditionError, match="commitment_digest_hex"):
        assert_ai_decision_precondition(record(output=[legacy]))


def test_media_type_is_lowercase_essence_and_binary_media_is_allowed():
    with pytest.raises(SubjectPreconditionError, match="lowercase MIME essence"):
        assert_ai_decision_precondition(
            record(input=[part("image", "user", "subject.binary/1", "Image/PNG")])
        )
    assert_ai_decision_precondition(
        record(input=[part("image", "user", "subject.binary/1", "image/png")])
    )


def test_context_must_be_a_bounded_flat_string_map():
    with pytest.raises(SubjectPreconditionError, match="context.nested"):
        assert_ai_decision_precondition(record(context={"nested": {"x": "1"}}))
    with pytest.raises(SubjectPreconditionError, match="at most 128"):
        assert_ai_decision_precondition(record(context={f"k{i}": "v" for i in range(129)}))


def test_input_and_output_are_nonempty_arrays():
    with pytest.raises(SubjectPreconditionError, match="non-empty array"):
        assert_ai_decision_precondition(record(input=[]))
    with pytest.raises(SubjectPreconditionError, match="non-empty array"):
        assert_ai_decision_precondition(record(output=[]))


@pytest.mark.parametrize(
    "model",
    [
        {"id": "", "provider": "p"},
        {"id": "m", "provider": ""},
        {"id": "m", "provider": "p", "version": ""},
    ],
)
def test_model_identifiers_are_nonempty(model):
    with pytest.raises(SubjectPreconditionError, match=r"model\..*must not be empty"):
        assert_ai_decision_precondition(record(model=model))


def test_decision_is_nonempty():
    with pytest.raises(SubjectPreconditionError, match="decision.*must not be empty"):
        assert_ai_decision_precondition(record(decision=""))


def test_observation_scope_is_closed():
    with pytest.raises(SubjectPreconditionError, match="client.*runtime"):
        assert_ai_decision_precondition(record(observation_scope="provider"))
