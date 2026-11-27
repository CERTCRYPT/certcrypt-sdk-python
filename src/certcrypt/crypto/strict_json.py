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

"""Strict JSON parsing.

Pinned by the conformance family `strict-json`. The text MUST be RFC 8259 JSON,
and no object may carry the same member name twice, at any depth. A parser that
keeps the first or the last of two duplicates reads a different value than one
that keeps the other, so a duplicate makes the input non-conformant and this
parser refuses it.

Member names are compared after their escapes are decoded (the decoder hands
each object's members over already decoded), so ``"anchor"`` and
``"\\u0061nchor"`` are the same name. Only object members are compared:
repeated array elements are ordinary data. ``NaN``, ``Infinity`` and a leading
byte-order mark are not JSON and are refused.
"""

import json
from typing import Any


class StrictJsonError(ValueError):
    """The text is not RFC 8259 JSON, or an object repeats a member name."""


def _reject_constant(token: str) -> Any:
    raise StrictJsonError(f"non-finite number {token} is not JSON")


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise StrictJsonError(f"duplicate member name {name!r}")
        out[name] = value
    return out


def strict_json_loads(text: str) -> Any:
    """Parse ``text`` as strict JSON. Raises :class:`StrictJsonError`."""
    if text.startswith("\ufeff"):
        raise StrictJsonError("byte-order mark before the JSON text")
    try:
        return json.loads(
            text, object_pairs_hook=_unique_members, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as e:
        raise StrictJsonError(str(e)) from e
