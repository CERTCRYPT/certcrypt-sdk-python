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

"""Productive builders for salted ``subject.ai-decision/1`` subjects."""

import json
import re
import secrets
from dataclasses import dataclass

from ..artifacts.base_certificate import (
    SubjectInput,
    compute_subject_commitment,
    subject_local_digest_hex,
)
from .canonical_subject import SUBJECT_AI_DECISION, canonical_bytes_for_subject

_HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AiDecisionMaterialInput:
    id: str
    role: str
    media_type: str
    profile: str
    material: bytes
    #: Testing only: omit this in production so the SDK generates a fresh nonce.
    material_nonce_hex: str | None = None


@dataclass(frozen=True)
class BuiltAiDecisionPart:
    descriptor: dict[str, str]
    material: bytes


@dataclass(frozen=True)
class BuiltAiDecisionSubject:
    subject: SubjectInput
    record: dict
    #: Original material and opening data, keyed by part id. Keep this private.
    materials: dict[str, dict]


def _generate_material_nonce_hex() -> str:
    return secrets.token_bytes(32).hex()


def _assert_material_nonce_hex(value: str) -> None:
    if not _HEX64.fullmatch(value):
        raise ValueError("material_nonce_hex must be 64 lowercase hex characters")


def build_ai_decision_part(part: AiDecisionMaterialInput) -> BuiltAiDecisionPart:
    """Build one salted, profile-aware part without interpreting its material."""
    material = bytes(part.material)
    material_nonce_hex = (
        part.material_nonce_hex
        if part.material_nonce_hex is not None
        else _generate_material_nonce_hex()
    )
    _assert_material_nonce_hex(material_nonce_hex)
    local_digest = subject_local_digest_hex(SubjectInput(part.profile, material))
    return BuiltAiDecisionPart(
        descriptor={
            "id": part.id,
            "role": part.role,
            "media_type": part.media_type,
            "profile": part.profile,
            "material_nonce_hex": material_nonce_hex,
            "commitment_digest_hex": compute_subject_commitment(
                material_nonce_hex, local_digest
            ),
        },
        material=material,
    )


def build_ai_decision_subject(
    *,
    decision_id: str,
    decided_at: str,
    model: dict[str, str],
    observation_scope: str,
    input: list[AiDecisionMaterialInput],
    output: list[AiDecisionMaterialInput],
    decision: str,
    parameters: dict[str, str] | None = None,
    context: dict[str, str] | None = None,
    started_at: str | None = None,
    actor_id: str | None = None,
    policy_ref: str | None = None,
) -> BuiltAiDecisionSubject:
    """Build and validate a complete ``subject.ai-decision/1`` subject."""
    used_nonces: set[str] = set()
    materials: dict[str, dict] = {}

    def build_side(parts: list[AiDecisionMaterialInput]) -> list[dict[str, str]]:
        descriptors: list[dict[str, str]] = []
        for part in parts:
            material_nonce_hex = part.material_nonce_hex
            if material_nonce_hex is not None:
                _assert_material_nonce_hex(material_nonce_hex)
                if material_nonce_hex in used_nonces:
                    raise ValueError(
                        "material_nonce_hex values must be globally unique across input and output"
                    )
            else:
                while True:
                    material_nonce_hex = _generate_material_nonce_hex()
                    if material_nonce_hex not in used_nonces:
                        break
            used_nonces.add(material_nonce_hex)
            built = build_ai_decision_part(
                AiDecisionMaterialInput(
                    id=part.id,
                    role=part.role,
                    media_type=part.media_type,
                    profile=part.profile,
                    material=part.material,
                    material_nonce_hex=material_nonce_hex,
                )
            )
            descriptors.append(built.descriptor)
            materials[part.id] = {
                "profile": part.profile,
                "material": built.material,
                "material_nonce_hex": material_nonce_hex,
                "commitment_digest_hex": built.descriptor["commitment_digest_hex"],
            }
        return descriptors

    record = {
        "profile": SUBJECT_AI_DECISION,
        "decision_id": decision_id,
        "decided_at": decided_at,
        "model": dict(model),
        "observation_scope": observation_scope,
        "input": build_side(input),
        "output": build_side(output),
        "decision": decision,
    }
    for key, value in (
        ("parameters", parameters),
        ("context", context),
        ("started_at", started_at),
        ("actor_id", actor_id),
        ("policy_ref", policy_ref),
    ):
        if value is not None:
            record[key] = dict(value) if isinstance(value, dict) else value

    material = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    canonical_bytes_for_subject(SUBJECT_AI_DECISION, material)
    return BuiltAiDecisionSubject(
        subject=SubjectInput(SUBJECT_AI_DECISION, material),
        record=record,
        materials=materials,
    )
