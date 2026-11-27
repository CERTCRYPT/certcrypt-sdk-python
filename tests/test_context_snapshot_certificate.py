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

"""Context snapshot certificates and the CCVP/1 declared context, checked
against the conformance vectors where they pin bytes and by construction where
they pin shape."""

import json
from pathlib import Path

import pytest

from certcrypt import (
    SubjectInput,
    assemble_base_certificate,
    assemble_context_snapshot_certificate,
    generate_issuer_key,
    issuer_key_fingerprint_hex,
)
from certcrypt.crypto.composite import composite_m_prime
from certcrypt.crypto.digest import digest_hex_bytes, digest_hex_text
from certcrypt.crypto.jcs import jcs_canonicalize_bytes

_VECTORS = (Path(__file__).resolve().parents[2] / "certcrypt-conformance" / "fixtures"
            / "primitives" / "ccvp-consistency" / "vectors.json")
NONCE = "ab" * 32
DOMAIN = {"system_id": "certcrypt", "rules_version": "rules/conformance"}
SNAPSHOT = {
    "context_set_id": "invoices",
    "snapshot_id": "01JAN0000000000000000000AA",
    "issued_at": "2026-01-01T00:00:00Z",
    "entries": [],
}


def _mint(snapshot, key=None):
    return assemble_context_snapshot_certificate(
        snapshot=snapshot, issuer_key=key or generate_issuer_key("context:test"),
        nonce_hex=NONCE, issued_at="2026-01-01T00:00:00Z", **DOMAIN,
    ).base_certificate


@pytest.mark.skipif(not _VECTORS.exists(), reason="conformance checkout not alongside")
def test_fingerprint_reproduces_the_vectors():
    v = json.loads(_VECTORS.read_text(encoding="utf-8"))
    for k in v["keys"].values():
        assert issuer_key_fingerprint_hex(k["pub_p256_b64"], k["pub_mldsa_b64"]) == \
            k["composite_key_fingerprint_digest_hex"]


def test_snapshot_certificate_carries_the_snapshot_and_one_committing_subject():
    cert = _mint(SNAPSHOT)
    p = cert["payload"]
    assert p["snapshot"] == SNAPSHOT
    assert [s["profile"] for s in p["anchor"]["subjects"]] == ["subject.context-snapshot/1"]
    local = digest_hex_bytes(jcs_canonicalize_bytes(SNAPSHOT))
    assert p["anchor"]["subjects"][0]["commitment_digest_hex"] == digest_hex_text(NONCE + local)
    assert cert["payload_canon_digest_hex"] == digest_hex_bytes(jcs_canonicalize_bytes(p))


def test_snapshot_certificate_signature_verifies_under_its_signer():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    import base64

    cert = _mint(SNAPSHOT)
    sig = cert["signatures"][0]
    m_prime = composite_m_prime(sig["alg"], cert["payload_canon_digest_hex"])
    raw = base64.b64decode(sig["signatures"][0]["sig_b64"])
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), base64.b64decode(sig["signer"]["pub_p256_b64"]))
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
               m_prime, ec.ECDSA(hashes.SHA3_256()))


@pytest.mark.parametrize("bad, match", [
    ({**SNAPSHOT, "snapshot_id": ""}, "snapshot_id"),
    ({**SNAPSHOT, "issued_at": "2026-01-01T00:00:00+00:00"}, "issued_at"),
    ({**SNAPSHOT, "entries": [{"issuer_id": "a"}]}, "pub_fingerprint_digest_hex"),
])
def test_snapshot_outside_the_ccvp_shape_is_refused(bad, match):
    with pytest.raises(ValueError, match=match):
        _mint(bad)


def test_snapshot_with_a_json_number_is_refused():
    # subject.context-snapshot/1 §7.1: no JSON number at any depth.
    with pytest.raises(Exception):
        _mint({**SNAPSHOT, "revision": 2})


def test_declared_context_is_signed_into_the_payload():
    key = generate_issuer_key("issuer:test")
    ctx_key = generate_issuer_key("context:test")
    context = {
        "snapshot_issuer_id": ctx_key.id,
        "snapshot_issuer_fingerprint_digest_hex":
            issuer_key_fingerprint_hex(ctx_key.pub_p256_b64, ctx_key.pub_mldsa_b64),
        "context_set_id": "invoices",
    }
    base = dict(issuer_key=key, subjects=[SubjectInput(profile="subject.binary/1", material=b"\x01")],
                nonce_hex=NONCE, issued_at="2026-04-12T10:00:00Z", **DOMAIN)
    assert assemble_base_certificate(**base, context=context).base_certificate["payload"]["context"] == context
    assert "context" not in assemble_base_certificate(**base).base_certificate["payload"]
    with pytest.raises(ValueError, match="fingerprint"):
        assemble_base_certificate(**base, context={**context, "snapshot_issuer_fingerprint_digest_hex": "x"})
