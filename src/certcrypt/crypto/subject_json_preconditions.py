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

"""Field-set and value-discipline preconditions for the JSON-object subject
profiles, enforced BEFORE canonicalization.

The issuer-side `canonical_bytes(subject)` for JSON-object profiles matches the
verifier's.

Each profile spec states that structural conformance is a *precondition of
canonicalization*, not a separable later check: `canonical_bytes(subject)` is
defined ONLY for an object satisfying the profile in full, and for any other
object the profile does not apply and the implementation MUST fail closed.
"""

import re
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "SubjectPreconditionError",
    "assert_collection_precondition",
    "assert_ai_decision_precondition",
    "assert_context_snapshot_precondition",
]

# Used with `fullmatch` only: `re.match` with `$` would also accept a trailing "\n".
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CANONICAL_UINT = re.compile(r"[1-9][0-9]*")

#: `subject.ai-decision/1` §7.4: the profiles an input or output may be declared under.
AI_DECISION_IO_PROFILES = (
    "subject.text/1",
    "subject.binary/1",
    "subject.email/1",
    "subject.ai-decision/1",
)

# `subject.ai-decision/1` §7.3 canonical UTC millisecond timestamp syntax.
_DECISION_TIME = re.compile(
    r"([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\.([0-9]{3})Z",
    re.ASCII,
)
_AI_PART_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}", re.ASCII)
_MEDIA_TYPE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}",
    re.ASCII,
)
_AI_MAX_PARTS = 256
_AI_MAX_MAP_MEMBERS = 128
_CARDINALITY_MAX = 18446744073709551615  # 2^64 − 1


class SubjectPreconditionError(Exception):
    """Raised when a JSON-object subject violates its profile precondition."""

    def __init__(self, profile: str, detail: str) -> None:
        super().__init__(f"subject precondition failed for {profile}: {detail}")
        self.profile = profile


def _is_plain_object(value: Any) -> bool:
    # `dict` only: a list is not an object, and Python has no separate null type
    # to exclude beyond None.
    return isinstance(value, dict)


def _assert_string_only(profile: str, value: Any, path: str) -> None:
    """Assert the string-only value discipline of `subject.collection/1` and
    `subject.ai-decision/1` (`subject.context-snapshot/1` only excludes numbers).

    Every value at any depth MUST be a JSON string, object, or array. A number,
    boolean, or null anywhere is non-conformant. This is what keeps RFC 8785 free
    of number serialization.

    `bool` is checked before `str`/`int` on purpose: in Python `True` is an
    instance of `int`, and letting it through would admit a JSON boolean the
    profile forbids.
    """
    if isinstance(value, bool):
        raise SubjectPreconditionError(
            profile,
            f"value at {path or '(root)'} is a JSON boolean; every value must be "
            "a string, object, or array (no numbers/booleans/nulls)",
        )
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for i, el in enumerate(value):
            _assert_string_only(profile, el, f"{path}[{i}]")
        return
    if _is_plain_object(value):
        for k in value:
            _assert_string_only(profile, value[k], f"{path}.{k}" if path else k)
        return

    kind = "null" if value is None else type(value).__name__
    raise SubjectPreconditionError(
        profile,
        f"value at {path or '(root)'} is a JSON {kind}; every value must be a "
        "string, object, or array (no numbers/booleans/nulls)",
    )


def assert_collection_precondition(value: Any) -> None:
    """`subject.collection/1`: exactly four members, plus leaf and cardinality shape."""
    P = "subject.collection/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "subject is not a JSON object")

    required = ["commitment_scheme", "root", "declared_cardinality", "leaves"]
    string_members = ["commitment_scheme", "root", "declared_cardinality"]

    for k in required:
        if k not in value:
            raise SubjectPreconditionError(P, f'missing member "{k}"')
    for k in value:
        if k not in required:
            raise SubjectPreconditionError(
                P, f'unexpected member "{k}" (exactly four members allowed)'
            )
        if k in string_members and not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'member "{k}" must be a string')

    # `leaves` is the one non-string member: an ordered array where each entry
    # declares its own profile and commitment. Its position IS the leaf index,
    # so the array is load-bearing.
    leaves = value["leaves"]
    if not isinstance(leaves, list) or len(leaves) == 0:
        raise SubjectPreconditionError(P, '"leaves" must be a non-empty array')

    for i, leaf in enumerate(leaves):
        if not _is_plain_object(leaf):
            raise SubjectPreconditionError(P, f'"leaves[{i}]" must be an object')
        keys = list(leaf)
        if len(keys) != 2 or "profile" not in leaf or "commitment_digest_hex" not in leaf:
            raise SubjectPreconditionError(
                P,
                f'"leaves[{i}]" must contain exactly "profile" and '
                '"commitment_digest_hex"',
            )
        for k in keys:
            if not isinstance(leaf[k], str):
                raise SubjectPreconditionError(P, f'"leaves[{i}].{k}" must be a string')
        if not _HEX64.fullmatch(leaf["commitment_digest_hex"]):
            raise SubjectPreconditionError(
                P,
                f'"leaves[{i}].commitment_digest_hex" must be 64 lowercase hex '
                "characters",
            )

    # declared_cardinality: canonical unsigned base-10, no sign, no leading
    # zeros, > 0, ≤ 2^64 − 1.
    dc = value["declared_cardinality"]
    if not _CANONICAL_UINT.fullmatch(dc):
        raise SubjectPreconditionError(
            P,
            '"declared_cardinality" must be a canonical unsigned base-10 integer '
            "with no sign and no leading zeros",
        )
    if int(dc) > _CARDINALITY_MAX:
        raise SubjectPreconditionError(P, '"declared_cardinality" exceeds 2^64 − 1')
    # The economic layer bills on declared_cardinality, so it MUST agree with the
    # array rather than be derived from it.
    if str(len(leaves)) != dc:
        raise SubjectPreconditionError(
            P,
            f'"declared_cardinality" ({dc}) does not equal the number of leaves '
            f"({len(leaves)})",
        )

    if value["commitment_scheme"] == "collection.merkle-sha3-256/1":
        if not _HEX64.fullmatch(value["root"]):
            raise SubjectPreconditionError(
                P,
                '"root" must be a 64-character lowercase hex string under '
                "collection.merkle-sha3-256/1",
            )

    _assert_string_only(P, value, "")


def assert_ai_decision_precondition(value: Any) -> None:
    """Validate the closed, multimodal `subject.ai-decision/1` record shape."""
    P = "subject.ai-decision/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "record is not a JSON object")

    # String-only first: it is the discipline that keeps JCS number-free and it
    # subsumes "no boolean/null" for every member below.
    _assert_string_only(P, value, "")

    required = [
        "profile",
        "decision_id",
        "decided_at",
        "model",
        "observation_scope",
        "input",
        "output",
        "decision",
    ]
    optional = ["parameters", "context", "started_at", "actor_id", "policy_ref"]
    allowed = set(required) | set(optional)

    for k in required:
        if k not in value:
            raise SubjectPreconditionError(P, f'missing required member "{k}"')
    for k in value:
        if k not in allowed:
            raise SubjectPreconditionError(P, f'unexpected member "{k}"')

    if value["profile"] != P:
        raise SubjectPreconditionError(P, f'"profile" must equal "{P}"')

    for k in ("profile", "decision_id", "decision", "observation_scope"):
        if not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'member "{k}" must be a string')
    if not _AI_PART_ID.fullmatch(value["decision_id"]):
        raise SubjectPreconditionError(P, '"decision_id" is not a canonical identifier')
    if not value["decision"]:
        raise SubjectPreconditionError(P, '"decision" must not be empty')

    if value["observation_scope"] not in ("client", "runtime"):
        raise SubjectPreconditionError(
            P, '"observation_scope" must be "client" or "runtime"'
        )
    decided_at = _decision_time(P, value["decided_at"], "decided_at")
    if "started_at" in value:
        started_at = _decision_time(P, value["started_at"], "started_at")
        if started_at > decided_at:
            raise SubjectPreconditionError(P, '"started_at" must not be after "decided_at"')

    _assert_nested_string_object(P, value["model"], "model", ["id", "provider"], ["version"])
    for member in ("id", "provider", *(('version',) if "version" in value["model"] else ())):
        if not value["model"][member]:
            raise SubjectPreconditionError(P, f'"model.{member}" must not be empty')
    seen_ids: set[str] = set()
    seen_nonces: set[str] = set()
    part_count = 0
    for side in ("input", "output"):
        parts = value[side]
        if not isinstance(parts, list) or not parts:
            raise SubjectPreconditionError(P, f'"{side}" must be a non-empty array')
        part_count += len(parts)
        for index, part in enumerate(parts):
            name = f"{side}[{index}]"
            _assert_nested_string_object(
                P,
                part,
                name,
                [
                    "id",
                    "role",
                    "media_type",
                    "profile",
                    "material_nonce_hex",
                    "commitment_digest_hex",
                ],
                [],
            )
            if not _AI_PART_ID.fullmatch(part["id"]):
                raise SubjectPreconditionError(P, f'"{name}.id" is not a canonical part identifier')
            if part["id"] in seen_ids:
                raise SubjectPreconditionError(P, f'material id {part["id"]!r} is duplicated')
            seen_ids.add(part["id"])
            if not part["role"]:
                raise SubjectPreconditionError(P, f'"{name}.role" must not be empty')
            if not _MEDIA_TYPE.fullmatch(part["media_type"]):
                raise SubjectPreconditionError(
                    P, f'"{name}.media_type" must be a lowercase MIME essence without parameters'
                )
            if part["profile"] not in AI_DECISION_IO_PROFILES:
                raise SubjectPreconditionError(P, f'"{name}.profile" is not an admitted material profile')
            if not _HEX64.fullmatch(part["material_nonce_hex"]):
                raise SubjectPreconditionError(
                    P,
                    f'"{name}.material_nonce_hex" must be 64 lowercase hex characters',
                )
            if part["material_nonce_hex"] in seen_nonces:
                raise SubjectPreconditionError(
                    P, f'material nonce {part["material_nonce_hex"]!r} is duplicated'
                )
            seen_nonces.add(part["material_nonce_hex"])
            if not _HEX64.fullmatch(part["commitment_digest_hex"]):
                raise SubjectPreconditionError(
                    P,
                    f'"{name}.commitment_digest_hex" must be 64 lowercase hex characters',
                )
    if part_count > _AI_MAX_PARTS:
        raise SubjectPreconditionError(
            P, f"input and output together may contain at most {_AI_MAX_PARTS} parts"
        )

    for map_name in ("parameters", "context"):
        if map_name in value:
            _assert_flat_string_map(P, value[map_name], map_name)

    for k in ("actor_id", "policy_ref"):
        if k in value and not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'optional member "{k}" must be a string')


def _decision_time(profile: str, value: Any, member: str) -> datetime:
    if not isinstance(value, str) or not _DECISION_TIME.fullmatch(value):
        raise SubjectPreconditionError(
            profile, f'"{member}" must be UTC with milliseconds (YYYY-MM-DDTHH:MM:SS.sssZ)'
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SubjectPreconditionError(profile, f'"{member}" is not a real Gregorian date') from exc


def _assert_flat_string_map(profile: str, value: Any, name: str) -> None:
    if not _is_plain_object(value):
        raise SubjectPreconditionError(profile, f'"{name}" must be an object when present')
    if len(value) > _AI_MAX_MAP_MEMBERS:
        raise SubjectPreconditionError(
            profile, f'"{name}" may contain at most {_AI_MAX_MAP_MEMBERS} members'
        )
    for key, item in value.items():
        if not isinstance(item, str):
            raise SubjectPreconditionError(profile, f'"{name}.{key}" must be a string')


def _assert_nested_string_object(
    profile: str, obj: Any, name: str, required: list[str], optional: list[str]
) -> None:
    if not _is_plain_object(obj):
        raise SubjectPreconditionError(profile, f'member "{name}" must be an object')
    allowed = set(required) | set(optional)
    for k in required:
        if k not in obj:
            raise SubjectPreconditionError(profile, f'"{name}" missing member "{k}"')
    for k in obj:
        if k not in allowed:
            raise SubjectPreconditionError(profile, f'"{name}" has unexpected member "{k}"')
        if not isinstance(obj[k], str):
            raise SubjectPreconditionError(profile, f'"{name}.{k}" must be a string')


def assert_context_snapshot_precondition(value: Any) -> None:
    """`subject.context-snapshot/1` §7.1: no JSON NUMBER at any depth.

    Booleans and nulls are permitted, and that is narrower than the string-only
    discipline of `subject.collection/1` and `subject.ai-decision/1` on purpose.
    Those profiles fix closed, entirely string-valued member sets. This one fixes
    no member set — the snapshot shape belongs to CCVP/1 — and §7 requires
    preserving "the exact string, boolean, array, object, and null semantics of
    the input", while §8 forbids coercing "booleans or nulls into strings".

    CCVP/1 §7.1 relies on it: its normative entry example carries
    ``valid_to: null`` for an open-ended eligibility window and ``revoked_at:
    null`` for one never revoked. Rejecting nulls would make the governing
    protocol's own example non-conformant and force an open window to be spelled
    as a string — exactly the coercion §8 prohibits.

    Only numbers are excluded, because number serialization is the one RFC 8785
    divergence vector across languages.
    """
    P = "subject.context-snapshot/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "snapshot is not a JSON object")
    _assert_no_json_number(P, value, "")


def _assert_no_json_number(profile: str, value: Any, path: str) -> None:
    # bool before int/float: in Python bool IS an int, and booleans are permitted.
    if not isinstance(value, bool) and isinstance(value, (int, float)):
        raise SubjectPreconditionError(
            profile,
            f"value at {path or '(root)'} is a JSON number; every numeric-looking "
            "value must be carried as a JSON string so RFC 8785 canonicalization "
            "converges across languages",
        )
    if isinstance(value, list):
        for i, el in enumerate(value):
            _assert_no_json_number(profile, el, f"{path}[{i}]")
        return
    if _is_plain_object(value):
        for k, v in value.items():
            _assert_no_json_number(profile, v, f"{path}.{k}" if path else k)
