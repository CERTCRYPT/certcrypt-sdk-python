# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");

import json

import pytest

from certcrypt import (
    AiDecisionMaterialInput,
    SubjectInput,
    build_ai_decision_part,
    build_ai_decision_subject,
    compute_subject_commitment,
    subject_local_digest_hex,
)

NONCE_A = "1" * 64
NONCE_B = "2" * 64


def material(identifier, role, value, nonce=None, profile="subject.text/1", media_type="text/plain"):
    return AiDecisionMaterialInput(
        id=identifier,
        role=role,
        media_type=media_type,
        profile=profile,
        material=value,
        material_nonce_hex=nonce,
    )


def test_build_part_applies_the_cccp_subject_commitment_formula():
    source = material("prompt", "user", b"approve\n", NONCE_A)
    built = build_ai_decision_part(source)
    expected = compute_subject_commitment(
        NONCE_A, subject_local_digest_hex(SubjectInput(source.profile, source.material))
    )
    assert built.descriptor == {
        "id": "prompt",
        "role": "user",
        "media_type": "text/plain",
        "profile": "subject.text/1",
        "material_nonce_hex": NONCE_A,
        "commitment_digest_hex": expected,
    }


def test_build_subject_returns_issuance_subject_and_private_opening_material():
    built = build_ai_decision_subject(
        decision_id="decision-1",
        decided_at="2026-08-16T12:00:00.000Z",
        model={"id": "model-1", "provider": "provider-1", "version": "2026-08"},
        observation_scope="client",
        input=[material("prompt", "user", b"Should this request be approved?", NONCE_A)],
        output=[material(
            "answer", "assistant", b'{"decision":"approved"}', NONCE_B,
            profile="subject.binary/1", media_type="application/json",
        )],
        decision="approved",
        parameters={"temperature": "0"},
    )
    assert built.subject.profile == "subject.ai-decision/1"
    assert json.loads(built.subject.material) == built.record
    assert list(built.materials) == ["prompt", "answer"]
    assert built.materials["prompt"]["material_nonce_hex"] == NONCE_A
    assert built.materials["answer"]["material_nonce_hex"] == NONCE_B
    assert (
        built.record["input"][0]["commitment_digest_hex"]
        != built.record["output"][0]["commitment_digest_hex"]
    )


def test_build_subject_generates_independent_nonces_and_refuses_reuse():
    kwargs = dict(
        decision_id="decision-1",
        decided_at="2026-08-16T12:00:00.000Z",
        model={"id": "model-1", "provider": "provider-1"},
        observation_scope="runtime",
        decision="complete",
    )
    built = build_ai_decision_subject(
        **kwargs,
        input=[material("prompt", "user", b"same")],
        output=[material("answer", "assistant", b"same")],
    )
    input_nonce = built.record["input"][0]["material_nonce_hex"]
    output_nonce = built.record["output"][0]["material_nonce_hex"]
    assert len(input_nonce) == len(output_nonce) == 64
    assert input_nonce != output_nonce

    with pytest.raises(ValueError, match="globally unique"):
        build_ai_decision_subject(
            **kwargs,
            input=[material("prompt", "user", b"same", NONCE_A)],
            output=[material("answer", "assistant", b"same", NONCE_A)],
        )
