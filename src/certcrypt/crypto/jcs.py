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

"""RFC 8785 JSON Canonicalization Scheme (JCS).

Per CCCP/1, the canonical form for payload signing uses RFC 8785: lexicographic
key ordering, no extra whitespace, and deterministic number serialization.

This is the byte form every signature in the protocol is computed over, so it must
agree with the other language bindings exactly. Python's `json.dumps` is close
but not equivalent, and the three places it diverges are handled explicitly
below — each one silently produces different signed bytes, which surfaces as a
signature another implementation rejects rather than as an error here.

  1. **Key ordering.** RFC 8785 sorts by UTF-16 code unit (RFC 8785 §3.2.3).
     Python's `sorted()`
     compares by Unicode code point. The two agree for everything in the Basic
     Multilingual Plane and disagree above it: a supplementary character (U+10000
     and up) sorts after U+FFFF by code point, but its surrogate pair starts with
     0xD800-0xDBFF and sorts *before* it in UTF-16. `_utf16_sort_key` encodes to
     UTF-16 code units so the comparison matches.

  2. **Number serialization.** RFC 8785 mandates ECMAScript `Number::toString`.
     Python renders floats differently (`1.0` where ECMAScript gives `1`; a
     two-digit padded exponent such as `1e-07` where ECMAScript gives `1e-7`).
     Integers are exact in both, so `int` passes straight
     through; `float` is normalized in `_number_to_string`.

  3. **String escaping.** RFC 8785 escapes only what JSON requires — quote,
     backslash, and the C0 controls — and emits everything else as literal UTF-8.
     `json.dumps` defaults to `ensure_ascii=True`, which would \\u-escape every
     non-ASCII character and change the bytes. `ensure_ascii=False` matches.
"""

import json
import math
from typing import Any

__all__ = ["jcs_canonicalize_bytes", "jcs_canonicalize_string"]


def jcs_canonicalize_bytes(obj: Any) -> bytes:
    """Canonical RFC 8785 bytes for `obj` (UTF-8 encoded)."""
    return _jcs_stringify(obj).encode("utf-8")


def jcs_canonicalize_string(obj: Any) -> str:
    """Canonical RFC 8785 form of `obj`, as a string."""
    return _jcs_stringify(obj)


def _utf16_sort_key(key: str) -> tuple[int, ...]:
    """Sort key matching RFC 8785's UTF-16 code-unit ordering.

    See note 1 in the module docstring: this differs from Python's default
    string ordering only for characters outside the Basic Multilingual Plane,
    but where it differs, the canonical bytes differ too.
    """
    encoded = key.encode("utf-16-be")
    return tuple(
        int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2)
    )


def _number_to_string(value: float | int) -> str:
    """Serialize a number the way ECMAScript `Number::toString` does.

    RFC 8785 defers to ECMAScript here, so a float that holds an integral value
    renders without a decimal point (`1`, not `1.0`) and exponent form drops the
    `+` (`1e21`, not `1e+21`).
    """
    if isinstance(value, bool):
        # bool is a subclass of int in Python; callers should never reach this,
        # but returning "1" for True would silently corrupt the signed bytes.
        raise TypeError("JCS: bool must be serialized as true/false, not a number")

    if isinstance(value, int):
        return str(value)

    if math.isnan(value) or math.isinf(value):
        raise ValueError("JCS does not support Infinity or NaN")

    if value == int(value) and abs(value) < 1e21:
        return str(int(value))

    # repr() gives Python's shortest round-tripping form, which agrees with
    # ECMAScript's for ordinary magnitudes; the exponent spelling does not.
    #
    # ECMAScript keeps the sign on a positive exponent (`1e+21`) and drops
    # leading zeros (`1e-7`, not `1e-07`). Python's repr agrees on the sign but
    # pads to two digits, so only the padding is stripped here. Checked against
    # the ECMAScript rule rather than assumed — the first draft emitted `1e21` and
    # would have produced signatures no other implementation accepts.
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        sign = "-" if exponent.startswith("-") else "+"
        digits = exponent.lstrip("+-").lstrip("0") or "0"
        if mantissa.endswith(".0"):
            mantissa = mantissa[:-2]
        text = f"{mantissa}e{sign}{digits}"
    return text


def _jcs_stringify(value: Any) -> str:
    if value is None:
        return "null"

    if isinstance(value, bool):
        # Checked before int: bool is a subclass of int in Python.
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return _number_to_string(value)

    if isinstance(value, str):
        # ensure_ascii=False keeps non-ASCII literal — see note 3 above.
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_stringify(v) for v in value) + "]"

    if isinstance(value, dict):
        # Python has no `undefined`, and `None` maps to JSON `null`, which
        # RFC 8785 serializes rather than drops — so every key is emitted.
        keys = sorted(value.keys(), key=_utf16_sort_key)
        members = [
            json.dumps(k, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _jcs_stringify(value[k])
            for k in keys
        ]
        return "{" + ",".join(members) + "}"

    raise TypeError(f"JCS: unsupported type {type(value).__name__}")
