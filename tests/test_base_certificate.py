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

"""Minting a base certificate, and the commitment rules that must not drift.

The load-bearing test here is `test_toolkit_verifies_our_certificate`: it hands a
certificate minted by this SDK to the reference verifier's composite check over
the real `payload_canon_digest_hex`. If the JCS, the anchor assembly, or the
ASCII-concatenation rule drifted by one byte, the digest changes and the
signature no longer matches — so that single assertion covers the whole chain.
"""

import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from certcrypt.artifacts.base_certificate import (
    CERTIFICATE_SCHEMA,
    SubjectInput,
    assemble_base_certificate,
    assemble_unsigned_payload,
    compute_anchor_commitment,
    compute_expires_at,
    compute_subject_commitment,
    derive_issuer_key,
    generate_nonce_hex,
    payload_canon_digest_hex,
    resolve_collection_subjects)
from certcrypt.crypto.collection_merkle import CollectionLeafInput
from certcrypt.crypto.digest import digest_hex_bytes, digest_hex_text
from certcrypt.crypto.jcs import jcs_canonicalize_string

_SEED = bytes(range(32))
_NONCE = "ab" * 32
_ISSUED_AT = "2026-05-09T12:00:00Z"
_TOOLKIT_DIST = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-verifier-toolkit-js"
    / "dist"
    / "core"
    / "crypto"
)


@pytest.fixture(scope="module")
def issuer_key():
    return derive_issuer_key(_SEED, "issuer-test")


def _mint(issuer_key, subjects=None, **kw):
    return assemble_base_certificate(
        issuer_key=issuer_key,
        subjects=subjects or [SubjectInput("subject.binary/1", b"invoice bytes")],
        nonce_hex=kw.pop("nonce_hex", _NONCE),
        issued_at=kw.pop("issued_at", _ISSUED_AT),
        system_id=kw.pop("system_id", "certcrypt"),
        rules_version=kw.pop("rules_version", "rules/conformance"),
        **kw)


def test_subject_commitment_concatenates_hex_as_ascii():
    """The rule most often got wrong: the hex strings are NOT decoded first.

    Decoding them is the intuitive reading of "concatenate the digests" and
    produces a commitment no other implementation reproduces.
    """
    nonce, local = "ab" * 32, "cd" * 32
    assert compute_subject_commitment(nonce, local) == digest_hex_text(nonce + local)
    # Explicitly NOT the decoded form.
    assert compute_subject_commitment(nonce, local) != digest_hex_bytes(
        bytes.fromhex(nonce) + bytes.fromhex(local)
    )


def test_anchor_commitment_rule():
    payload = assemble_unsigned_payload(
        subjects=[SubjectInput("subject.binary/1", b"x")],
        nonce_hex=_NONCE,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    anchor = payload["anchor"]
    expected = digest_hex_text(
        _NONCE + digest_hex_bytes(jcs_canonicalize_string(anchor).encode("utf-8"))
    )
    assert payload["anchor_commitment_digest_hex"] == expected
    assert compute_anchor_commitment(anchor) == expected


def test_subject_order_is_preserved_and_significant():
    subjects = [
        SubjectInput("subject.binary/1", b"first"),
        SubjectInput("subject.text/1", b"second\r\n"),
        SubjectInput("subject.binary/1", b"third"),
    ]
    payload = assemble_unsigned_payload(
        subjects=subjects,
        nonce_hex=_NONCE,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    assert [s["profile"] for s in payload["anchor"]["subjects"]] == [
        "subject.binary/1",
        "subject.text/1",
        "subject.binary/1",
    ]
    reordered = assemble_unsigned_payload(
        subjects=list(reversed(subjects)),
        nonce_hex=_NONCE,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    assert payload_canon_digest_hex(payload) != payload_canon_digest_hex(reordered)


def test_nonce_salts_every_commitment():
    """A different nonce must change the commitment for identical material."""
    a = assemble_unsigned_payload(
        subjects=[SubjectInput("subject.binary/1", b"same")],
        nonce_hex="ab" * 32,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    b = assemble_unsigned_payload(
        subjects=[SubjectInput("subject.binary/1", b"same")],
        nonce_hex="cd" * 32,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    assert (
        a["anchor"]["subjects"][0]["commitment_digest_hex"]
        != b["anchor"]["subjects"][0]["commitment_digest_hex"]
    )


def test_malformed_inputs_fail_fast():
    base = dict(
        subjects=[SubjectInput("subject.binary/1", b"x")],
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    for bad_nonce in ("AB" * 32, "ab" * 31, "zz" * 32, ""):
        with pytest.raises(ValueError):
            assemble_unsigned_payload(**{**base, "nonce_hex": bad_nonce})
    with pytest.raises(ValueError):
        assemble_unsigned_payload(**{**base, "nonce_hex": _NONCE, "root_id": "nope"})
    with pytest.raises(ValueError):
        assemble_unsigned_payload(
            **{**base, "nonce_hex": _NONCE, "subjects": []}
        )


def test_root_id_omitted_when_absent():
    """An absent root_id must not appear as null: it changes the canonical bytes."""
    payload = assemble_unsigned_payload(
        subjects=[SubjectInput("subject.binary/1", b"x")],
        nonce_hex=_NONCE,
        issued_at=_ISSUED_AT,
        system_id="certcrypt",
        rules_version="rules/conformance")
    assert "root_id" not in payload["anchor"]


def test_collection_subject_is_resolved_and_rides_signed(issuer_key):
    subjects = [
        SubjectInput(
            "subject.collection/1",
            leaves=[
                CollectionLeafInput("subject.binary/1", b"a"),
                CollectionLeafInput("subject.text/1", b"b\r\n"),
            ])
    ]
    resolved, collections = resolve_collection_subjects(subjects, _NONCE)
    assert len(collections) == 1
    assert collections[0].subject_index == 0
    assert len(collections[0].leaf_hashes) == 2

    minted = _mint(issuer_key, resolved)
    subject = minted.base_certificate["payload"]["anchor"]["subjects"][0]
    # The descriptor rides inside the signed subject: each leaf's profile enters
    # the signature, since the profile decides how that leaf canonicalizes.
    assert subject["collection"]["declared_cardinality"] == "2"
    assert [leaf["profile"] for leaf in subject["collection"]["leaves"]] == [
        "subject.binary/1",
        "subject.text/1",
    ]


def test_collection_rejects_material_and_leaves_together():
    with pytest.raises(ValueError):
        resolve_collection_subjects(
            [
                SubjectInput(
                    "subject.collection/1",
                    material=b"{}",
                    leaves=[CollectionLeafInput("subject.binary/1", b"a")])
            ],
            _NONCE)


def test_certificate_shape(issuer_key):
    minted = _mint(issuer_key)
    cert = minted.base_certificate
    assert cert["schema"] == CERTIFICATE_SCHEMA
    assert cert["payload_canon_digest_hex"] == payload_canon_digest_hex(cert["payload"])
    sig = cert["signatures"][0]
    assert sig["role"] == "issuer"
    assert sig["sig_target"] == "payload_canon_digest_hex"
    assert sig["mode"] == "AND"
    assert sig["signer"]["id"] == "issuer-test"
    assert minted.certificate_commitment_digest == digest_hex_text(
        jcs_canonicalize_string(cert)
    )


def test_derive_issuer_key_depends_on_the_seed_alone():
    a = derive_issuer_key(_SEED, "issuer-test")
    b = derive_issuer_key(_SEED.hex(), "issuer-test")
    assert a.pub_p256_b64 == b.pub_p256_b64
    assert a.pub_mldsa_b64 == b.pub_mldsa_b64
    # The id is a label: the same seed is the same identity under any id.
    other = derive_issuer_key(_SEED, "other")
    assert other.id == "other"
    assert other.pub_p256_b64 == a.pub_p256_b64
    assert other.pub_mldsa_b64 == a.pub_mldsa_b64


def test_issuer_seed_must_be_32_bytes():
    with pytest.raises(
        ValueError, match=r"issuer key master seed must be 32 bytes \(64 hex chars\)"
    ):
        derive_issuer_key(b"\x01" * 31, "issuer-test")


def test_generate_nonce_is_64_lowercase_hex_and_unique():
    nonces = {generate_nonce_hex() for _ in range(64)}
    assert len(nonces) == 64
    for n in nonces:
        assert len(n) == 64 and n == n.lower()
        bytes.fromhex(n)


def test_compute_expires_at():
    assert compute_expires_at("2026-05-09T12:00:00Z", 86400) == "2026-05-10T12:00:00Z"
    for bad in (0, -1, 1.5, True):
        with pytest.raises(ValueError):
            compute_expires_at("2026-05-09T12:00:00Z", bad)


def test_issued_at_rejects_sub_second_precision():
    """Truncating would silently change the instant the issuer meant to record."""
    with pytest.raises(ValueError):
        assemble_unsigned_payload(
            subjects=[SubjectInput("subject.binary/1", b"x")],
            nonce_hex=_NONCE,
            issued_at=datetime(2026, 5, 9, 12, 0, 0, 500_000, tzinfo=timezone.utc),
            system_id="certcrypt",
            rules_version="rules/conformance")


@pytest.mark.skipif(
    shutil.which("node") is None or not _TOOLKIT_DIST.exists(),
    reason=(
        "cross-binding check needs Node and a built certcrypt-verifier-toolkit-js "
        "sibling (run `npm run build` there)"
    ))
def test_toolkit_verifies_our_certificate(issuer_key):
    """The reference verifier must accept a certificate this SDK minted.

    This covers the whole chain at once: if the JCS, the anchor assembly, or the
    ASCII-concatenation rule drifted, `payload_canon_digest_hex` changes and the
    signature stops matching.
    """
    minted = _mint(
        issuer_key,
        [
            SubjectInput("subject.binary/1", b"invoice bytes"),
            SubjectInput("subject.text/1", b"line one\nline two\n"),
        ])
    cert = minted.base_certificate
    sig = cert["signatures"][0]

    script = f"""
    import {{ verifyComposite, PROFILE_P256_MLDSA65 }} from "{_TOOLKIT_DIST}/composite.js";
    import {{ initMlDsa65 }} from "{_TOOLKIT_DIST}/ml-dsa.js";
    import {{ jcsCanonicalizeString }} from "{_TOOLKIT_DIST}/jcs.js";
    import {{ digestHexText }} from "{_TOOLKIT_DIST}/digest.js";
    import {{ readFileSync }} from "node:fs";
    await initMlDsa65();
    const cert = JSON.parse(readFileSync(process.argv[2], "utf8"));
    // Recompute the digest from the payload with the toolkit's own JCS: this is
    // what proves the canonical bytes agree, not just the signature.
    const recomputed = digestHexText(jcsCanonicalizeString(cert.payload));
    const sig = cert.signatures[0];
    // The composite is the entry's {{alg, mode, signatures}}; role, sig_target and
    // signer belong to the certificate's signature entry around it.
    const composite = {{ alg: sig.alg, mode: sig.mode, signatures: sig.signatures }};
    const result = verifyComposite(PROFILE_P256_MLDSA65, recomputed, composite, {{
      classicalPubB64: sig.signer.pub_p256_b64,
      mldsaPubB64: sig.signer.pub_mldsa_b64,
    }});
    console.log(JSON.stringify({{
      digest_matches: recomputed === cert.payload_canon_digest_hex,
      composite: result,
    }}));
    """
    with tempfile.TemporaryDirectory() as tmp:
        mjs, data = Path(tmp) / "check.mjs", Path(tmp) / "cert.json"
        mjs.write_text(script, "utf-8")
        data.write_text(json.dumps(cert), "utf-8")
        out = subprocess.run(
            ["node", str(mjs), str(data)], capture_output=True, text=True, timeout=180
        )
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout)
    # The toolkit's JCS must reproduce our digest byte-for-byte...
    assert report["digest_matches"] is True, report
    # ...and the composite must verify with BOTH components actually run.
    assert report["composite"]["valid"] is True, report
    assert report["composite"]["classical"]["passed"] is True, report
    assert report["composite"]["mldsa"]["performed"] is True, report
    assert report["composite"]["mldsa"]["passed"] is True, report


@pytest.mark.skipif(
    shutil.which("node") is None or not _TOOLKIT_DIST.exists(),
    reason=(
        "cross-binding check needs Node and a built certcrypt-verifier-toolkit-js "
        "sibling (run `npm run build` there)"
    ))
def test_toolkit_issued_path_accepts_our_certificate(issuer_key):
    """The whole Issued path of the reference verifier accepts the certificate:
    the CCSP/1 envelope (closed objects, formats, the one issuer signature, the
    recomputed digests) and then the composite signature. The certificate is read
    from a file, so it also goes through the verifier's strict JSON parser."""
    minted = _mint(
        issuer_key,
        [
            SubjectInput("subject.binary/1", b"invoice bytes"),
            SubjectInput("subject.text/1", b"line one\nline two\n"),
        ])
    core = _TOOLKIT_DIST.parent
    script = f"""
    import "{core}/crypto/provider/register-node.js";
    import {{ initMlDsa65 }} from "{core}/crypto/ml-dsa.js";
    import {{ verify }} from "{core}/verify.js";
    import {{ getConformanceConfig }} from "{core.parent}/harness/profiles.js";
    await initMlDsa65();
    const r = verify({{
      verification_target_requested: "issued",
      input_mode: "artifact_set",
      base_certificate_path: process.argv[2],
    }}, getConformanceConfig());
    console.log(JSON.stringify({{
      result_code: r.result_code,
      issued_valid: r.issued_valid,
      failed_check_ids: r.failed_check_ids,
      failure_reason: r.failure_reason,
    }}));
    """
    with tempfile.TemporaryDirectory() as tmp:
        mjs, data = Path(tmp) / "check.mjs", Path(tmp) / "cert.json"
        mjs.write_text(script, "utf-8")
        data.write_text(json.dumps(minted.base_certificate), "utf-8")
        out = subprocess.run(
            ["node", str(mjs), str(data)], capture_output=True, text=True, timeout=180
        )
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout)
    assert report["issued_valid"] is True, report
    assert report["result_code"] == "ISSUED_VALID", report
