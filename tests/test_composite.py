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

"""Composite signing, and the round-trip through the reference verifier.

The signature is the point at which this SDK stops being checkable on its own:
bytes that verify here but not under another binding are worse than bytes that
fail outright, because they ship. `test_verifier_toolkit_accepts_our_composite`
is therefore the load-bearing test in this file — it hands what this SDK produces
to the real `verifyComposite` in `certcrypt-verifier-toolkit-js` and requires a
`valid: true` with BOTH components verified.

That round-trip needs Node and a built sibling toolkit, so it skips when either
is missing rather than failing. The rest of the file pins what can be checked
without them.
"""

import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from certcrypt.crypto.composite import (
    ALG_ECDSA_P256,
    ALG_MLDSA65,
    COMPOSITE_DOMAIN_PREFIX,
    PROFILE_P256_MLDSA65,
    CompositeSigningKey,
    composite_m_prime,
    composite_sign_p256)
from certcrypt.crypto.digest import digest_hex_text
from certcrypt.crypto.ecdsa_p256 import (
    P256_HALF_N,
    private_key_from_scalar,
    public_key_sec1_uncompressed_b64,
    scalar_from_seed_material,
    verify_ecdsa_p256_raw)
from certcrypt.crypto.ml_dsa import keygen_ml_dsa65, verify_ml_dsa65

_SEED = bytes(range(1, 33))
_TOOLKIT_DIST = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-verifier-toolkit-js"
    / "dist"
    / "core"
    / "crypto"
)


@pytest.fixture(scope="module")
def signing_key():
    p256 = private_key_from_scalar(scalar_from_seed_material(_SEED))
    mldsa_pub, mldsa_secret = keygen_ml_dsa65(_SEED)
    return {
        "key": CompositeSigningKey(p256_private=p256, mldsa_secret=mldsa_secret),
        "p256_pub_b64": public_key_sec1_uncompressed_b64(p256),
        "mldsa_pub_b64": base64.b64encode(mldsa_pub).decode("ascii"),
    }


def test_m_prime_layout():
    """M' is ASCII prefix || 0x00 || alg id || 0x00 || digest hex.

    The NUL separators keep the fields unambiguous: without them a profile id
    ending in hex characters could run into the digest.
    """
    m = composite_m_prime("alg-id", "deadbeef")
    assert m == COMPOSITE_DOMAIN_PREFIX.encode("ascii") + b"\x00alg-id\x00deadbeef"
    assert m.count(b"\x00") == 2


def test_wire_shape(signing_key):
    wire = composite_sign_p256(digest_hex_text("payload"), signing_key["key"])
    assert wire["alg"] == PROFILE_P256_MLDSA65
    assert wire["mode"] == "AND"
    # Classical FIRST — the order is load-bearing, a verifier reads positionally.
    assert [c["alg"] for c in wire["signatures"]] == [ALG_ECDSA_P256, ALG_MLDSA65]
    classical, pqc = wire["signatures"]
    assert classical["encoding"] == "raw-rs-64"
    assert classical["low_s"] is True
    # The PQC component carries neither field.
    assert "encoding" not in pqc and "low_s" not in pqc


def test_both_components_sign_the_same_m_prime(signing_key):
    """Each component must verify against M', not against the digest."""
    digest = digest_hex_text("payload")
    wire = composite_sign_p256(digest, signing_key["key"])
    m_prime = composite_m_prime(PROFILE_P256_MLDSA65, digest)

    classical, pqc = wire["signatures"]
    assert verify_ecdsa_p256_raw(
        signing_key["p256_pub_b64"], m_prime, base64.b64decode(classical["sig_b64"])
    )
    assert verify_ml_dsa65(
        base64.b64decode(signing_key["mldsa_pub_b64"]),
        m_prime,
        base64.b64decode(pqc["sig_b64"]))


def test_classical_component_is_low_s(signing_key):
    """low-s is normative: the verifier rejects high-s outright.

    ECDSA admits both s and n-s, so a signer that skipped normalization would
    emit signatures every conformant verifier refuses about half the time.
    """
    for i in range(12):
        wire = composite_sign_p256(digest_hex_text(f"payload-{i}"), signing_key["key"])
        sig = base64.b64decode(wire["signatures"][0]["sig_b64"])
        assert len(sig) == 64
        assert int.from_bytes(sig[32:], "big") <= P256_HALF_N


def test_binding_the_profile_into_m_prime_stops_replay():
    """A component lifted into another profile must not verify."""
    digest = digest_hex_text("payload")
    assert composite_m_prime(PROFILE_P256_MLDSA65, digest) != composite_m_prime(
        "certcrypt-composite-ed25519-mldsa65-v1", digest
    )


@pytest.mark.skipif(
    shutil.which("node") is None or not _TOOLKIT_DIST.exists(),
    reason=(
        "cross-binding check needs Node and a built certcrypt-verifier-toolkit-js "
        "sibling (run `npm run build` there)"
    ))
def test_verifier_toolkit_accepts_our_composite(signing_key):
    """The reference verifier must return valid with BOTH components verified.

    This is the assertion that makes the SDKs siblings rather than lookalikes.
    """
    digest = digest_hex_text("payload")
    wire = composite_sign_p256(digest, signing_key["key"])

    script = f"""
    import {{ verifyComposite, PROFILE_P256_MLDSA65 }} from "{_TOOLKIT_DIST}/composite.js";
    import {{ initMlDsa65 }} from "{_TOOLKIT_DIST}/ml-dsa.js";
    import {{ readFileSync }} from "node:fs";
    await initMlDsa65();
    const d = JSON.parse(readFileSync(process.argv[2], "utf8"));
    console.log(JSON.stringify(verifyComposite(
      PROFILE_P256_MLDSA65, d.digest, d.wire,
      {{ classicalPubB64: d.p256, mldsaPubB64: d.mldsa }}
    )));
    """
    payload = {
        "wire": wire,
        "digest": digest,
        "p256": signing_key["p256_pub_b64"],
        "mldsa": signing_key["mldsa_pub_b64"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        mjs = Path(tmp) / "check.mjs"
        data = Path(tmp) / "payload.json"
        mjs.write_text(script, "utf-8")
        data.write_text(json.dumps(payload), "utf-8")
        out = subprocess.run(
            ["node", str(mjs), str(data)],
            capture_output=True,
            text=True,
            timeout=180)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result["valid"] is True, result
    assert result["classical"]["passed"] is True, result
    # `performed` guards against a pass that only means "PQC was skipped".
    assert result["mldsa"]["performed"] is True, result
    assert result["mldsa"]["passed"] is True, result
