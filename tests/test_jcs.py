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

"""JCS parity against the verifier toolkit.

The canonical bytes are what every signature in the protocol is computed over, so
a divergence here does not surface as a failure in this repository — it surfaces
as a certificate this SDK mints and another implementation rejects, or worse, as
two bindings that disagree about what a given payload even is.

`tests/vectors/jcs-verifier-parity.json` holds inputs paired with the exact
output of the verifier toolkit's `jcsCanonicalizeString`, captured by running it.
They are committed rather than regenerated so this suite pins the RFC 8785 bytes
a verifier computes even where no verifier is installed.

These vectors caught a real defect while this module was being written: the first
draft serialized `1e21` where ECMAScript emits `1e+21`, which would have produced
signatures no other binding accepts.
"""

import json
from pathlib import Path

import pytest

from certcrypt.crypto.jcs import jcs_canonicalize_bytes, jcs_canonicalize_string

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "jcs-verifier-parity.json").read_text("utf-8")
)


@pytest.mark.parametrize("pair", VECTORS["pairs"], ids=range(len(VECTORS["pairs"])))
def test_matches_the_verifier_toolkit(pair):
    assert jcs_canonicalize_string(pair["input"]) == pair["jcs"]


def test_bytes_are_utf8_of_the_string():
    for pair in VECTORS["pairs"]:
        assert jcs_canonicalize_bytes(pair["input"]) == pair["jcs"].encode("utf-8")


def test_keys_sort_by_utf16_code_unit():
    """RFC 8785 orders by UTF-16 code unit, not by Unicode code point.

    The two disagree only above the BMP: U+1F600 sorts after U+FFFF by code
    point, but its surrogate pair begins with 0xD83D and sorts before it in
    UTF-16. Sorting by code point here would place the keys in the other order
    and change the signed bytes.
    """
    out = jcs_canonicalize_string({"\U0001f600": 1, "￿": 2})
    assert out.index("\U0001f600") < out.index("￿")


def test_integral_floats_lose_the_decimal_point():
    # ECMAScript Number::toString gives "1", not Python's "1.0".
    assert jcs_canonicalize_string({"n": 1.0}) == '{"n":1}'


def test_exponent_keeps_the_positive_sign():
    # The defect these vectors caught: ECMAScript emits 1e+21, not 1e21.
    assert jcs_canonicalize_string({"n": 1e21}) == '{"n":1e+21}'
    assert jcs_canonicalize_string({"n": 1e-7}) == '{"n":1e-7}'


def test_non_ascii_stays_literal():
    # ensure_ascii=True would \\u-escape these and change the bytes.
    assert jcs_canonicalize_string({"k": "héllo ☃"}) == '{"k":"héllo ☃"}'


def test_null_members_are_emitted_not_dropped():
    assert jcs_canonicalize_string({"b": None, "a": 1}) == '{"a":1,"b":null}'


def test_rejects_non_finite_numbers():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            jcs_canonicalize_string({"n": bad})


def test_rejects_unsupported_types():
    with pytest.raises(TypeError):
        jcs_canonicalize_string({"k": {1, 2}})
