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

"""Issuer-side minter of the `base_certificate` with a verifiable subject anchor.

NO CUSTODY: the issuer builds and SIGNS the certificate with its own key,
client-side. CERTCRYPT never holds that key and never signs on the issuer's
behalf.

Byte parity is load-bearing and pinned by the conformance vectors. One rule
causes most cross-language failures and is worth stating plainly:

    commitment_digest_hex = SHA3-256(ASCII(nonce_hex) || ASCII(subject_local_digest_hex))

The two hex strings are concatenated **as ASCII text and never decoded to bytes
first**. Decoding them — the intuitive reading of "concatenate the digests" —
produces a different commitment that no other implementation reproduces, and
nothing about the result looks wrong. `digest_hex_text` hashes the ASCII bytes of
the string, which is exactly the rule.
"""

import base64
import copy
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..crypto.canonical_subject import canonical_bytes_for_subject
from ..crypto.collection_merkle import CollectionLeafInput, build_collection
from ..crypto.composite import CompositeSigningKey, composite_sign_p256
from ..crypto.digest import digest_hex_bytes, digest_hex_text
from ..crypto.jcs import jcs_canonicalize_bytes, jcs_canonicalize_string
from ..crypto.ml_dsa import keygen_ml_dsa65
from ..crypto.ecdsa_p256 import (
    private_key_from_scalar,
    public_key_sec1_uncompressed_b64,
    scalar_from_seed_material,
)
from .rfc3339 import add_seconds, to_rfc3339_seconds

__all__ = [
    "CERTIFICATE_SCHEMA",
    "SubjectInput",
    "IssuerKey",
    "MintedCertificate",
    "ResolvedCollection",
    "compute_subject_commitment",
    "subject_local_digest_hex",
    "resolve_collection_subjects",
    "compute_anchor_commitment",
    "generate_nonce_hex",
    "compute_expires_at",
    "assemble_unsigned_payload",
    "payload_canon_digest_hex",
    "derive_issuer_key",
    "generate_issuer_key",
    "assemble_base_certificate",
]

CERTIFICATE_SCHEMA = "certcrypt-certificate"
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


@dataclass
class SubjectInput:
    """One subject to certify: its declared profile and its original bytes.

    For JSON-object profiles the material is the JSON source bytes; the VALUE is
    re-canonicalized. For a collection declared via `leaves`, omit `material` —
    the SDK builds the descriptor itself, because the salt is this certificate's
    own nonce and does not exist until issuance.
    """

    profile: str
    material: bytes | None = None
    leaves: list[CollectionLeafInput] | None = None
    #: Filled in by `resolve_collection_subjects` for collection subjects.
    collection: dict | None = None


@dataclass
class IssuerKey:
    """The issuer's composite signing identity."""

    id: str
    p256_private: Any  # ecdsa.SigningKey
    mldsa_secret: bytes
    pub_p256_b64: str
    pub_mldsa_b64: str


@dataclass
class ResolvedCollection:
    """What `resolve_collection_subjects` produced for one collection subject."""

    subject_index: int
    descriptor: dict
    #: Leaf hashes in leaf order. They travel signed inside the descriptor, but
    #: the issuer still needs them locally to build inclusion proofs later.
    leaf_hashes: list[str] = field(default_factory=list)


@dataclass
class MintedCertificate:
    base_certificate: dict
    certificate_commitment_digest: str


def compute_subject_commitment(nonce_hex: str, subject_local_digest: str) -> str:
    """The per-subject commitment.

    See the module docstring: the hex strings are ASCII-concatenated, NOT decoded.
    """
    return digest_hex_text(nonce_hex + subject_local_digest)


def subject_local_digest_hex(subject: SubjectInput) -> str:
    """`subject_local_digest_hex = SHA3-256(canonical_bytes(subject))`."""
    if subject.material is None:
        raise ValueError(
            f"subject of profile {subject.profile} has no material: a collection "
            "declared via `leaves` must be resolved with "
            "resolve_collection_subjects() first"
        )
    return digest_hex_bytes(
        canonical_bytes_for_subject(subject.profile, subject.material)
    )


def resolve_collection_subjects(
    subjects: list[SubjectInput], nonce_hex: str
) -> tuple[list[SubjectInput], list[ResolvedCollection]]:
    """Turn every `leaves`-declared collection into a concrete descriptor.

    Returns the resolved subjects plus, per collection, the descriptor and leaf
    hashes the caller must keep: the leaf hashes are not recoverable from the
    certificate, and without them element-level inclusion cannot be proven later.
    """
    salt = nonce_hex.encode("ascii")
    collections: list[ResolvedCollection] = []
    resolved: list[SubjectInput] = []

    for i, s in enumerate(subjects):
        if s.leaves is None:
            resolved.append(s)
            continue
        if s.material is not None:
            raise ValueError(f"subject {i}: pass either `material` or `leaves`, not both")

        built = build_collection(salt, s.leaves)
        collections.append(
            ResolvedCollection(
                subject_index=i,
                descriptor=built.descriptor,
                leaf_hashes=built.leaf_hashes,
            )
        )
        # The descriptor is both what the commitment digests and what the verifier
        # reads: the same bytes serve twice, so no separate file has to travel.
        resolved.append(
            SubjectInput(
                profile=s.profile,
                material=jcs_canonicalize_bytes(built.descriptor),
                collection=built.descriptor,
            )
        )

    return resolved, collections


def compute_anchor_commitment(anchor: dict) -> str:
    """`SHA3-256(ASCII(nonce_hex) || ASCII(SHA3-256(RFC8785(anchor))))`."""
    anchor_canon_hex = digest_hex_bytes(jcs_canonicalize_bytes(anchor))
    return digest_hex_text(anchor["nonce_hex"] + anchor_canon_hex)


def generate_nonce_hex() -> str:
    """A 256-bit CSPRNG nonce as 64 lowercase hex chars.

    Non-reuse is the caller's invariant: the nonce salts every commitment in the
    certificate, so repeating one across certificates would make their subject
    commitments comparable.
    """
    return secrets.token_bytes(32).hex()


def compute_expires_at(issued_at: str, ttl_seconds: int) -> str:
    """`issued_at + ttl`, at RFC 3339 second precision.

    The TTL is NOT chosen here: it comes from the active rules-domain registry,
    and the value it yields is the signed settlement-bound deadline a verifier
    evaluates. Hardcoding one would fail verification closed on any domain that
    disagrees.
    """
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError(
            f"ttl_seconds must be a positive whole number of seconds (got {ttl_seconds})"
        )
    return add_seconds(to_rfc3339_seconds(issued_at), ttl_seconds)


def assemble_unsigned_payload(
    *,
    subjects: list[SubjectInput],
    nonce_hex: str,
    issued_at: str,
    system_id: str,
    rules_version: str,
    root_id: str | None = None,
    context: dict | None = None,
) -> dict:
    """Build the unsigned payload with a verifiable subject anchor.

    ``context``, when given, is the CCVP/1 declared context the certificate
    names (CCVP/1 §5.2), signed with the payload: ``snapshot_issuer_id``,
    ``snapshot_issuer_fingerprint_digest_hex`` and ``context_set_id``. Opting in
    only lets a verifier evaluate consistency; it never changes Issued or
    Independent.

    Subject order is preserved and significant. Fails fast on a malformed nonce
    or an empty subject set — the verifier would reject those downstream, and a
    local failure is cheaper than one discovered by a third party.
    """
    if not _HEX64_RE.fullmatch(nonce_hex):
        raise ValueError(f"nonce_hex must be 64 lowercase hex chars (got {nonce_hex!r})")
    if len(subjects) == 0:
        raise ValueError("at least one subject is required")
    if root_id is not None and not _HEX64_RE.fullmatch(root_id):
        raise ValueError(
            f"root_id must be 64 lowercase hex chars when present (got {root_id!r})"
        )

    if context is not None:
        _assert_consistency_context(context)

    subject_commitments: list[dict] = []
    for s in subjects:
        entry = {
            "profile": s.profile,
            "commitment_digest_hex": compute_subject_commitment(
                nonce_hex, subject_local_digest_hex(s)
            ),
        }
        if s.collection is not None:
            # The descriptor rides INSIDE the subject so each leaf's profile enters
            # the signature: the profile decides how a leaf canonicalizes, so an
            # unsigned one would be forgeable.
            entry["collection"] = s.collection
        subject_commitments.append(entry)

    anchor: dict = {
        "issued_at": to_rfc3339_seconds(issued_at),
        "nonce_hex": nonce_hex,
    }
    if root_id is not None:
        anchor["root_id"] = root_id
    anchor["subjects"] = subject_commitments

    payload = {
        "anchor": anchor,
        "anchor_commitment_digest_hex": compute_anchor_commitment(anchor),
        "system_id": system_id,
        "rules_version": rules_version,
    }
    if context is not None:
        payload["context"] = dict(context)
    return payload


def _assert_consistency_context(ctx: dict) -> None:
    if not isinstance(ctx, dict):
        raise ValueError("context must be an object (CCVP/1 §5.2)")
    if not isinstance(ctx.get("snapshot_issuer_id"), str):
        raise ValueError("context.snapshot_issuer_id must be a string (CCVP/1 §5.2)")
    fp = ctx.get("snapshot_issuer_fingerprint_digest_hex")
    if not isinstance(fp, str) or not _HEX64_RE.fullmatch(fp):
        raise ValueError(
            "context.snapshot_issuer_fingerprint_digest_hex must be 64 lowercase hex chars "
            "(CCVP/1 §5.2)"
        )
    if not isinstance(ctx.get("context_set_id"), str) or not ctx["context_set_id"]:
        raise ValueError("context.context_set_id must be a non-empty string (CCVP/1 §5.2)")


def payload_canon_digest_hex(payload: dict) -> str:
    """`payload_canon_digest_hex = SHA3-256(RFC8785(payload))`."""
    return digest_hex_text(jcs_canonicalize_string(payload))


def _issuer_key_from_parts(id: str, p256_private, mldsa_public: bytes, mldsa_secret: bytes) -> IssuerKey:
    return IssuerKey(
        id=id,
        p256_private=p256_private,
        mldsa_secret=mldsa_secret,
        pub_p256_b64=public_key_sec1_uncompressed_b64(p256_private),
        pub_mldsa_b64=base64.b64encode(mldsa_public).decode("ascii"),
    )


def generate_issuer_key(id: str) -> IssuerKey:
    """Generate a fresh issuer composite key (dev/test; production keys via KMS)."""
    from ..crypto.ecdsa_p256 import generate_ecdsa_p256_key

    p256 = generate_ecdsa_p256_key()
    mldsa_pub, mldsa_secret = keygen_ml_dsa65()
    return _issuer_key_from_parts(id, p256, mldsa_pub, mldsa_secret)


def derive_issuer_key(master_seed: bytes | str, id: str) -> IssuerKey:
    """Derive the issuer's composite cert-signing key from a 32-byte master seed.

    The same seed the operation-key tree comes from, under two domain labels of
    its own:

      - P-256: ``material = SHA3-256(seed || "issuer-cert-key/p256")``, folded
        into a scalar in ``[1, n)`` by :func:`scalar_from_seed_material`;
      - ML-DSA-65: ``KeyGen_internal(SHA3-256(seed || "issuer-cert-key/mldsa"))``.

    The labels differ from each other and from ``op-key/<i>``, so the cert key is
    cryptographically independent of every operation key — a design invariant,
    not a convenience. The key depends on the seed ALONE: ``id`` is the label
    stamped into the certificate's signer block and never enters the
    derivation, so the same seed is the same signing identity under any id.
    Pinned by the conformance family ``issuer-key-derivation``.

    The issuer never handles this key; it is reconstructed from the seed each
    run, so it is stable across restarts with no stored key material.
    Production may still inject a KMS-backed :class:`IssuerKey` instead of
    deriving one — a deliberate hardening, not a requirement for issuance.
    """
    seed = bytes.fromhex(master_seed) if isinstance(master_seed, str) else bytes(master_seed)
    if len(seed) != 32:
        raise ValueError("issuer key master seed must be 32 bytes (64 hex chars)")

    p256_material = bytes.fromhex(digest_hex_bytes(seed + b"issuer-cert-key/p256"))
    p256 = private_key_from_scalar(scalar_from_seed_material(p256_material))
    mldsa_seed = bytes.fromhex(digest_hex_bytes(seed + b"issuer-cert-key/mldsa"))
    mldsa_pub, mldsa_secret = keygen_ml_dsa65(mldsa_seed)
    return _issuer_key_from_parts(id, p256, mldsa_pub, mldsa_secret)


def assemble_base_certificate(
    *,
    issuer_key: IssuerKey,
    subjects: list[SubjectInput],
    nonce_hex: str,
    issued_at: str,
    system_id: str,
    rules_version: str,
    root_id: str | None = None,
    context: dict | None = None,
) -> MintedCertificate:
    """Mint a signed base certificate; the issuer signs client-side.

    Returns the certificate plus `certificate_commitment_digest =
    SHA3-256(JCS(certificate))`. ``context`` is the optional CCVP/1 declared
    context (see :func:`assemble_unsigned_payload`).
    """
    payload = assemble_unsigned_payload(
        subjects=subjects,
        nonce_hex=nonce_hex,
        issued_at=issued_at,
        system_id=system_id,
        rules_version=rules_version,
        root_id=root_id,
        context=context,
    )
    return _sign_payload(payload, issuer_key)


def _sign_payload(payload: dict, issuer_key: IssuerKey) -> MintedCertificate:
    canon_digest = payload_canon_digest_hex(payload)

    composite = composite_sign_p256(
        canon_digest,
        CompositeSigningKey(
            p256_private=issuer_key.p256_private, mldsa_secret=issuer_key.mldsa_secret
        ),
    )

    base_certificate = {
        "schema": CERTIFICATE_SCHEMA,
        "payload": payload,
        "payload_canon_digest_hex": canon_digest,
        "signatures": [
            {
                "role": "issuer",
                "sig_target": "payload_canon_digest_hex",
                "alg": composite["alg"],
                "mode": composite["mode"],
                "signatures": composite["signatures"],
                "signer": {
                    "id": issuer_key.id,
                    "pub_p256_b64": issuer_key.pub_p256_b64,
                    "pub_mldsa_b64": issuer_key.pub_mldsa_b64,
                },
            }
        ],
    }

    return MintedCertificate(
        base_certificate=base_certificate,
        certificate_commitment_digest=digest_hex_text(
            jcs_canonicalize_string(base_certificate)
        ),
    )


def issuer_key_fingerprint_hex(pub_p256_b64: str, pub_mldsa_b64: str) -> str:
    """The composite key fingerprint of an issuer key (CCVP/1 §8.1).

    ``SHA3-256(pub_p256_bytes || pub_mldsa_bytes)`` over the decoded keys,
    classical first — the construction of composite-signature/1 §10. It is the
    value a context snapshot entry names in ``pub_fingerprint_digest_hex``, and
    the value a certificate names in
    ``context.snapshot_issuer_fingerprint_digest_hex`` for the key that signs
    its snapshots. Pass an :class:`IssuerKey`'s ``pub_p256_b64`` and
    ``pub_mldsa_b64``.
    """
    return digest_hex_bytes(base64.b64decode(pub_p256_b64) + base64.b64decode(pub_mldsa_b64))


#: CCSP/1 §7.3.1 form, which CCVP/1 §6.3 adopts for every timestamp.
_CCVP_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z")


def _assert_snapshot_shape(snapshot: Any) -> None:
    def fail(what: str):
        raise ValueError(f"context snapshot: {what} (CCVP/1 §6, §7.1)")

    def ts(v: Any) -> bool:
        return isinstance(v, str) and _CCVP_TIMESTAMP_RE.fullmatch(v) is not None

    if not isinstance(snapshot, dict):
        fail("the snapshot must be a JSON object")
    for k in ("context_set_id", "snapshot_id"):
        if not isinstance(snapshot.get(k), str) or not snapshot[k]:
            fail(f"{k} must be a non-empty string")
    if not ts(snapshot.get("issued_at")):
        fail("issued_at must be an RFC 3339 UTC timestamp ending in Z")
    if not isinstance(snapshot.get("entries"), list):
        fail("entries must be an array")
    for i, e in enumerate(snapshot["entries"]):
        if not isinstance(e, dict):
            fail(f"entries[{i}] must be an object")
        if not isinstance(e.get("issuer_id"), str) or not e["issuer_id"]:
            fail(f"entries[{i}].issuer_id must be a non-empty string")
        fp = e.get("pub_fingerprint_digest_hex")
        if not isinstance(fp, str) or not _HEX64_RE.fullmatch(fp):
            fail(f"entries[{i}].pub_fingerprint_digest_hex must be 64 lowercase hex chars")
        if not isinstance(e.get("status"), str):
            fail(f"entries[{i}].status must be a string")
        if not ts(e.get("valid_from")):
            fail(f"entries[{i}].valid_from must be an RFC 3339 UTC timestamp")
        for k in ("valid_to", "revoked_at"):
            if k in e and e[k] is not None and not ts(e[k]):
                fail(f"entries[{i}].{k} must be null or an RFC 3339 UTC timestamp")


def assemble_context_snapshot_certificate(
    *,
    snapshot: dict,
    issuer_key: IssuerKey,
    nonce_hex: str,
    issued_at: str,
    system_id: str,
    rules_version: str,
) -> MintedCertificate:
    """Mint a CCVP/1 context snapshot certificate.

    A base certificate carrying ``snapshot`` as ``payload.snapshot`` and exactly
    one ``subject.context-snapshot/1`` subject committing to it (CCVP/1 §5.1).
    The snapshot issuer is the key that signs it; verifiers derive it from the
    signature, never from the snapshot. The snapshot is carried exactly as
    given, so fix array order and timestamp spelling before calling.

    The snapshot is checked against the CCVP/1 shape and the profile's own
    preconditions (no JSON number at any depth) before anything is signed.
    """
    _assert_snapshot_shape(snapshot)
    payload = assemble_unsigned_payload(
        subjects=[SubjectInput(
            profile="subject.context-snapshot/1",
            material=json.dumps(snapshot, ensure_ascii=False).encode("utf-8"),
        )],
        nonce_hex=nonce_hex,
        issued_at=issued_at,
        system_id=system_id,
        rules_version=rules_version,
    )
    payload["snapshot"] = copy.deepcopy(snapshot)
    return _sign_payload(payload, issuer_key)
