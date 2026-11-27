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

"""SHA3-256 against the published conformance vectors.

`subject.binary/1` is the profile whose canonical bytes ARE the input bytes, so
these vectors pin the digest itself with no canonicalization in the way: empty
subject, embedded NUL, leading BOM. An implementation that quietly normalized any
of them would produce a commitment nobody else can reproduce.

The vectors live in `certcrypt-conformance`, which is data rather than code, so
every language binding is held to the identical result. They are not vendored
here: the contract is versioned separately and a copy would drift. When the
sibling checkout is absent these tests skip with a message naming what to check
out, rather than failing.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from certcrypt.crypto.digest import digest_bytes, digest_hex_bytes, digest_hex_text

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "subject-binary"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not _FIXTURE.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_FIXTURE})"
    ))


def _vectors():
    data = json.loads(_FIXTURE.read_text("utf-8"))
    return data["vectors"]


def _input_bytes(vector) -> bytes:
    if "input_b64" in vector:
        return base64.b64decode(vector["input_b64"])
    if "input_hex" in vector:
        return bytes.fromhex(vector["input_hex"])
    raise AssertionError(f"vector has no recognized input field: {sorted(vector)}")


def _expected_digest(vector) -> str | None:
    return vector.get("subject_local_digest_hex") or vector.get("digest_hex")


def test_matches_every_published_vector():
    checked = 0
    for vector in _vectors():
        expected = _expected_digest(vector)
        if expected is None:
            continue
        assert digest_hex_bytes(_input_bytes(vector)) == expected, vector.get("name")
        checked += 1
    assert checked > 0, "no vector carried an expected digest — fixture shape changed"


def test_hex_and_raw_agree():
    for vector in _vectors():
        raw = _input_bytes(vector)
        assert digest_bytes(raw).hex() == digest_hex_bytes(raw)


def test_text_digest_is_utf8_of_the_string():
    assert digest_hex_text("héllo ☃") == digest_hex_bytes("héllo ☃".encode("utf-8"))


def test_is_fips202_sha3_not_keccak():
    """SHA3-256 and Keccak-256 differ in padding and disagree on every input.

    Pinned against the FIPS 202 value for the empty string: a binding wired to
    Keccak would still produce 32 plausible-looking bytes.
    """
    assert (
        digest_hex_bytes(b"")
        == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert digest_hex_bytes(b"") == hashlib.sha3_256(b"").hexdigest()
