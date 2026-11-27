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

"""The one issuance surface: `Certcrypt`.

The issuer supplies only the MATERIAL and its subject profile; this class does
everything else — derives the signing key from the seed, canonicalizes each
subject byte-identically to the verifier, mints a SIGNED base certificate whose
commitment is derived FROM the material, and anchors it toward `Independent`::

    result = certcrypt.issue(subjects=[...])

There is no opaque-digest mode: `issue()` always commits to real material, so a
third party can bind the proof to THIS exact content. To certify a non-document
fact, model it as a subject rather than passing a bare digest.

**Server-side only.** The seed is the issuer's identity; anyone holding it can
issue as you.
"""

import base64
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Protocol

from .artifacts.base_certificate import (
    IssuerKey,
    SubjectInput,
    assemble_base_certificate,
    compute_expires_at,
    derive_issuer_key,
    generate_nonce_hex,
    resolve_collection_subjects,
)
from .artifacts.capacity_evidence import (
    StableIdentifiers,
    assemble_evidence,
    assert_submission_set_within_bound,
    evidence_digest_hex,
)
from .artifacts.holder_keyset import HolderKeySet
from .artifacts.rfc3339 import to_rfc3339_seconds
from .client import (
    CertcryptNodeClient,
    CertcryptNodeError,
    is_settlement_overdue,
    issuer_auth_message,
)
from .types import SettlementPreferences
from .crypto.canonical_subject import SUBJECT_COLLECTION
from .crypto.strict_json import strict_json_loads
from .types import (
    TERMINAL_STATES,
    IssueResponse,
    LooseCommitment,
    SettlementWindowEstimate,
    UnresolvedEmission,
    UnresolvedEmissions,
)

__all__ = [
    "IssuerMode",
    "LeafStore",
    "InMemoryLeafStore",
    "BindingStore",
    "BindingStoreEntry",
    "SettlementPreferences",
    "EmissionHandle",
    "IssueResult",
    "EmissionResolution",
    "Certcrypt",
    "COMMITMENT_TTL_SECONDS",
]

IssuerMode = Literal["stable", "unlinkable"]

#: Capacity-commitment TTL per rules-domain, in seconds.
#:
#: A PUBLIC RULE of the domain, not an issuer setting. The verifier requires
#: `expires_at == issued_at + ttl`, so it cannot be guessed: an unknown
#: rules_version raises rather than falling back to a far-future expiry, which
#: would mint certificates the verifier silently rejects.
COMMITMENT_TTL_SECONDS: dict[str, int] = {
    "rules/2026-01": 86_400,
    "rules/conformance": 2_592_000,
}

#: The rules domains this SDK implements.
#:
#: Not configuration. ``rules_version`` is carried in every artifact this SDK
#: emits and covered by its signatures, and what it asserts is that the artifact
#: was produced under that exact normative body — its subject-profile
#: canonicalizations, its commitment constructions with their exact preimages, its
#: signature algorithms, its settlement contract. None of that is read from
#: anywhere: it is written into this package. So the SDK implements one normative
#: body, and the honest thing is to say which.
#:
#: Emitting under a rules domain this SDK does not implement is the failure mode
#: nothing downstream catches: the artifact verifies perfectly — signatures valid,
#: digests matching, settlement real — while attesting to behavior that never
#: happened. A verifier cannot detect it, because there is nothing malformed to
#: detect. Hence the refusal is here, at emission, where it is still possible
#: (``rules-domain/1`` §14.2).
#:
#: Adding an entry means having implemented that rules domain, not having decided
#: to support it.
SUPPORTED_RULES_VERSIONS: frozenset[str] = frozenset(
    {
        "rules/2026-01",
        "rules/conformance",
    }
)

#: Rules domains registered at runtime, on top of the published ones.
#:
#: A deployment may run under a rules domain it registers at runtime instead of
#: one from the published list. The domain then comes from whoever runs the SDK,
#: never from this package: the shape is public, a deployment's values are its
#: own.
#:
#: This does NOT relax the gate. Registering a domain asserts the same thing
#: ``SUPPORTED_RULES_VERSIONS`` asserts — that this SDK implements that normative
#: body — and the assertion is then made by whoever registers it. An unregistered
#: domain is still refused, which is what ``rules-domain/1`` §14.2 requires.
_RUNTIME_RULES_VERSIONS: set[str] = set()


def register_rules_domain(rules_version: str) -> None:
    """Register a rules domain this SDK implements but does not publish.

    For a deployment that runs under its own rules domain. Call it before constructing
    :class:`Certcrypt`: the gate runs at construction.

    Only accepts a domain whose canonicalization and settlement semantics this
    SDK already implements — i.e. one that differs from a published domain in
    WHERE it settles, not in HOW artifacts are formed. Registering anything else
    produces artifacts that verify correctly and attest to behavior that never
    happened, which is precisely what the gate exists to prevent.
    """
    if not isinstance(rules_version, str) or not rules_version:
        raise ValueError("register_rules_domain requires a non-empty rules_version")
    if not rules_version.startswith("rules/"):
        raise ValueError(
            f'rules_version must start with "rules/", got "{rules_version}"'
        )
    _RUNTIME_RULES_VERSIONS.add(rules_version)


def _implemented_rules_versions() -> set[str]:
    """Every rules domain this SDK will emit under: published + registered."""
    return set(SUPPORTED_RULES_VERSIONS) | _RUNTIME_RULES_VERSIONS

#: The subject profiles this SDK can canonicalize.
#:
#: Mirrors ``crypto/canonical_subject.py``, which is the only place that turns a
#: subject into committed bytes: a profile absent there cannot be emitted,
#: whatever else in this package mentions it. A rules domain may admit profiles
#: an SDK does not implement, and passing one is refused rather than approximated
#: — canonicalizing a subject under the wrong profile yields a commitment that is
#: well-formed and wrong, which is exactly the class of error rules-domain/1
#: §14.2 exists to prevent.
IMPLEMENTED_SUBJECT_PROFILES: frozenset[str] = frozenset(
    {
        "subject.binary/1",
        "subject.text/1",
        "subject.email/1",
        "subject.collection/1",
        "subject.ai-decision/1",
        "subject.context-snapshot/1",
    }
)


def _assert_rules_domain_implemented(rules_version: str) -> None:
    """Fail closed unless this SDK implements the rules domain asked for.

    Called from ``__init__`` so the refusal lands before a signing key is derived,
    capacity is touched, or an artifact exists to be mistaken for a valid one.
    """
    if rules_version in _implemented_rules_versions():
        return
    supported = ", ".join(sorted(_implemented_rules_versions()))
    raise ValueError(
        f'this SDK does not implement rules_version "{rules_version}". '
        f"It implements: {supported}. rules_version is not a parameter: it "
        "asserts, in every artifact emitted and under its signatures, that the "
        "artifact was produced under that exact normative body. Emitting under "
        "rules this SDK does not implement would produce artifacts that verify "
        "correctly and attest to behavior that never happened, which no verifier "
        "can detect (rules-domain/1 §14.2). Use a rules_version this SDK "
        "implements, or an SDK that implements that one."
    )

#: PRIVATE signing-domain separator for the issuer↔node↔issuance-service channel. Keeps a read
#: signature from ever being valid as anything else the same key signs.
#:
#: NOT a public protocol identifier: nothing in the normative specs defines it, no
#: verifier evaluates it, and a conforming third-party implementation never has to
#: reproduce it. The colon form is deliberate — the normative artifacts are all
#: shaped `name.thing/<version>`, so a separator in that shape would read as a spec
#: identifier to anyone scanning the code.
#:
#: The CERTCRYPT service verifies these exact strings (the activation one is
#: the possession message of the activation request), so they MUST NOT change:
#: changing one turns every read into a 401 and every activation into a rejected
#: possession proof.
PRIVATE_SIGNING_DOMAIN_READ = "certcrypt:read:2"
PRIVATE_SIGNING_DOMAIN_ACTIVATE = "certcrypt:activate:1"


def read_message(challenge: str, resource: str) -> str:
    """The bytes both halves of a read chain sign: domain, the issuer's per-read
    challenge, and the resource."""
    return f"{PRIVATE_SIGNING_DOMAIN_READ}|{challenge}|{resource}"

#: Default end of the minted authorization's validity window (RFC3339 seconds).
FAR_FUTURE = "2100-01-01T00:00:00Z"

#: The leaf that proves possession of the key set at activation. Activation is
#: not a commitment, so it does not draw from the leaf store.
_ACTIVATION_LEAF_INDEX = 0

class LeafStore(Protocol):
    """Persistent, monotone leaf allocator for the unlinkable mode.

    Each call MUST return a fresh index never handed out before, and it MUST
    survive restarts. Handing the same leaf to two commitments makes them
    linkable by key, which is the one thing the unlinkable mode exists to
    prevent — and no verifier can detect it, because none has global state.
    """

    def next_leaf(self) -> int: ...


class InMemoryLeafStore:
    """A trivial in-memory leaf store — NOT persistent.

    For tests and single-run scripts only. A real unlinkable deployment must
    supply a durable store: this one restarts at zero, which silently reuses
    every leaf it already handed out.
    """

    def __init__(self) -> None:
        self._cursor = 0

    def next_leaf(self) -> int:
        value = self._cursor
        self._cursor += 1
        return value


@dataclass(frozen=True)
class BindingStoreEntry:
    """What a binding store round-trips.

    All fields are public — no secret — so this is safe to persist anywhere.
    `holder_id` and `pool_id` are LEARNED from activation and authoritative for
    emission, so a store that saved only the binding would leave `holder_id`
    unresolved and `issue()` would fail.
    """

    binding: dict
    holder_id: str
    pool_id: str


class BindingStore(Protocol):
    """Optional persistence for the Level-1 binding.

    A CACHE that saves the activation round-trip on start, never a requirement
    for correctness: with `integration_key` plus `keyset_seed` the SDK
    re-activates by itself, since re-presenting the key against the same root is
    an idempotent replay. An empty or failing store degrades to one extra
    request.

    No default implementation is provided on purpose: where the binding lives is
    a deployment decision the SDK should not make.
    """

    def load(self) -> BindingStoreEntry | None: ...
    def save(self, entry: BindingStoreEntry) -> None: ...



@dataclass(frozen=True)
class EmissionHandle:
    """A serializable handle of ONE emission.

    Persist it and hand it back to `resolve_emission` later to check settlement
    and build the `verification_package` — WITHOUT re-emitting.

    Why this exists: every issuer whose settlement is asynchronous faces the same
    need — emit once, then resume. Without a handle an issuer either blocks a
    request waiting for settlement, or re-emits on every retry, producing a
    duplicate node operation per attempt for the SAME certificate. The handle
    carries the two pieces the node never returns, so a later process — even
    after a restart — can finish from the blob alone.

    Contains no secret (the capacity evidence is public), so it is safe to store
    next to the certificate. Treat it as opaque; its shape may gain fields.
    """

    operation_id: str
    independence_ref: str
    commitment_index: int
    capacity_evidence: dict
    base_certificate: dict
    upstream_operation_id: str | None = None
    collections: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize for persistence."""
        out = {
            "operation_id": self.operation_id,
            "independence_ref": self.independence_ref,
            "commitment_index": self.commitment_index,
            "capacity_evidence": self.capacity_evidence,
            "base_certificate": self.base_certificate,
        }
        if self.upstream_operation_id:
            out["upstream_operation_id"] = self.upstream_operation_id
        if self.collections:
            out["collections"] = [
                {
                    "subject_index": c.subject_index,
                    "descriptor": c.descriptor,
                    "leaf_hashes": c.leaf_hashes,
                }
                for c in self.collections
            ]
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "EmissionHandle":
        return cls(
            operation_id=data["operation_id"],
            independence_ref=data["independence_ref"],
            # Required, never defaulted: the index is a position in the Merkle
            # leaf order, and a placeholder 0 yields an inclusion proof that
            # verifies against nothing.
            commitment_index=int(data["commitment_index"]),
            capacity_evidence=data["capacity_evidence"],
            base_certificate=data["base_certificate"],
            upstream_operation_id=data.get("upstream_operation_id"),
            collections=data.get("collections", []),
        )

    @classmethod
    def from_recovery(
        cls,
        fragment: dict,
        *,
        base_certificate: dict,
        collections: list | None = None,
        upstream_operation_id: str | None = None,
    ) -> "EmissionHandle":
        """Rebuild a handle from a RECOVERED fragment plus the issuer-held half.

        `from_dict` round-trips a handle this SDK wrote. This one joins the two
        halves of a handle that was LOST: the four fields CERTCRYPT can return,
        plus the three it cannot.

        Why no endpoint returns two of them — and the cases are NOT alike:

          * `base_certificate` — the issuer minted and signed it; only its digest
            crossed the boundary. There is nothing server-side to return.
          * `collections` — descriptors and leaf hashes are computed locally under
            the certificate's own nonce, and travel only inside the base
            certificate, which CERTCRYPT never receives. They can be read back
            from that certificate, and from nothing CERTCRYPT holds.
        So recovery is a JOIN, not a download. An issuer that lost BOTH the handle
        and the certificate cannot reconstruct the emission from any endpoint, by
        design.

        WHY THIS EXISTS RATHER THAN A DICT LITERAL. The one dangerous mistake in
        recovery is supplying a `commitment_index` when the fragment has none —
        defaulting it to 0 because the field wants an int. That yields a handle
        that looks complete and an inclusion proof that verifies against NOTHING:
        the index is a position in the Merkle leaf order, and the wrong position
        is not a near miss. A partial fragment is refused here, loudly, instead of
        becoming an artifact that fails far away.

        Call it only for a fragment whose emission has SETTLED. For the rest,
        keep polling — `list_unresolved_emissions` says when.
        """
        index = fragment.get("commitment_index")
        if index is None:
            raise ValueError(
                "cannot rebuild an EmissionHandle from a partial fragment: "
                "commitment_index is None, which means the emission has not "
                "settled and its Merkle position does not exist yet. Poll until "
                "it settles, then recover again — never substitute a placeholder "
                "index: the inclusion proof it produces verifies against nothing"
            )
        return cls(
            operation_id=fragment["operation_id"],
            independence_ref=fragment["independence_ref"],
            commitment_index=int(index),
            capacity_evidence=fragment["capacity_evidence"],
            base_certificate=base_certificate,
            upstream_operation_id=upstream_operation_id,
            collections=collections or [],
        )


@dataclass(frozen=True)
class PreparedCommitment:
    """One certificate SIGNED but not yet sent — what `prepare()` returns and
    `submit()` consumes.

    N unrelated certificates sent as N requests carry the per-submission overhead
    N times, while the same N prepared and submitted together carry it ONCE — the
    reason this surface exists.

    TREAT IT AS SPENT THE MOMENT YOU HOLD IT. `prepare()` signs, and signing is
    what consumes the leaf and the operation salt; sending does not. In
    "unlinkable" mode a prepared commitment that is never submitted leaves its
    leaf spent for good: the leaf allocator is monotone by design (`LeafStore` has
    no `release()`), because recycling a leaf would reintroduce the reuse a
    verifier cannot detect. Losing a leaf costs one slot in a large key set;
    reusing one silently destroys the unlinkability the mode exists to provide.
    In "stable" mode leaf 0 is reused on purpose, so nothing is lost.

    Serializable: persist it if the submit happens in another process. What you
    must NOT do is re-`prepare()` the same certificate to retry a failed send —
    that signs a second commitment for the same material. Re-`submit()` the one
    you already hold.
    """

    #: The signed loose commitment, exactly as it will travel on the wire.
    commitment: LooseCommitment
    #: The signed base_certificate. Needed to build the handle after the submit
    #: and to verify the emission offline against the original material.
    base_certificate: dict
    #: Stable authorization id this commitment was signed under. All members of
    #: one submission set MUST share it (and the issuer), or the node refuses the
    #: mix.
    authorization_id: str
    #: Which leaf signed this commitment. Recorded so the no-reuse invariant is
    #: auditable; leaf 0 is valid and is the stable mode's only leaf.
    leaf_index: int
    #: Resolved collection subjects (descriptor + leaf hashes, in leaf order).
    #: The same values travel signed inside `base_certificate`; keep this or the
    #: certificate, because without either they cannot be recomputed short of the
    #: complete ordered leaf set and the certificate nonce.
    collections: list = field(default_factory=list)


@dataclass(frozen=True)
class SubmitResult:
    """What `submit()` returns: the node's response plus one handle per prepared
    commitment, in the SAME order they were passed in."""

    response: IssueResponse
    #: One serializable handle per submitted commitment, index-aligned with the
    #: input list. Persist each and pass it to `resolve_emission()` later.
    handles: list[EmissionHandle] = field(default_factory=list)


@dataclass(frozen=True)
class IssueResult:
    response: IssueResponse
    commitment: LooseCommitment
    authorization_id: str
    handle: EmissionHandle
    #: One entry per `leaves`-declared collection subject.
    #:
    #: The same descriptor and leaf hashes travel signed inside the base
    #: certificate, which CERTCRYPT never receives: keep this or the certificate.
    #: Lose both and they cannot be recomputed without the complete ordered leaf
    #: set and the certificate nonce. They are what makes element-level
    #: inclusion verifiable years later.
    collections: list = field(default_factory=list)


@dataclass(frozen=True)
class EmissionResolution:
    """The outcome of resolving a previously-emitted certificate."""

    #: ``expired`` (submission-set/1 §11.1): the accepted operation can no longer
    #: reach Independent and consumed nothing; the certificate stays Issued and a
    #: new emission under a fresh authorization is the way to Independent.
    state: Literal["independent", "pending", "rejected", "expired"]
    node_state: str
    verification_package: dict | None = None
    independence_ref: str | None = None
    #: On `pending`: the window the node expects to settle this operation in, when
    #: it reported one. A reconciler should schedule its next call around
    #: `settlement_window.expected_settled_by` (or `target_close_by` when the
    #: node reports no expected settlement instant) instead of polling blindly.
    #:
    #: Operational only — never verifier-evaluated, and it carries no cost figure.
    settlement_window: SettlementWindowEstimate | None = None
    #: On `pending`: True when `expected_settled_by` (or, without it,
    #: `target_close_by`) has already passed and the operation is still not
    #: settled — it is running LATE. Lets an issuer surface "your operation is
    #: delayed" instead of an indefinite spinner.
    overdue: bool = False
    #: On `expired`: why — ``authorization_expired_before_finality`` or
    #: ``commitment_window_expired``.
    reason_code: str | None = None


def _sum_effective_units(subjects: list[SubjectInput]) -> str:
    """Σ over the subjects of each one's effective units.

    A normal subject counts 1; a collection counts its declared cardinality. A
    multi-subject certificate therefore declares its TRUE subject count. The node
    re-derives this from the certificate and rejects a mismatch, so the
    declaration cannot understate what the certificate carries.
    """
    total = 0
    for s in subjects:
        if s.profile != SUBJECT_COLLECTION:
            total += 1
            continue
        if s.leaves:
            # Declared by leaves: the cardinality IS the leaf count, and no
            # descriptor exists yet (its root needs the anchor nonce).
            total += len(s.leaves) or 1
            continue
        try:
            obj = strict_json_loads(bytes(s.material or b"").decode("utf-8"))
            dc = int(str(obj.get("declared_cardinality", "0")))
            total += dc if dc > 0 else 1
        except Exception:
            # Malformed collection: count as 1. The node re-derives and rejects.
            total += 1
    return str(total)


def _derive_authorization_id(binding: dict) -> str:
    root = binding.get("level1_binding", {}).get("holder_key_set_root", "")
    return f"auth:{root[:32]}"


class Certcrypt:
    """The issuer-side entry point."""

    def __init__(
        self,
        *,
        node_base_url: str,
        keyset_seed: bytes | str,
        rules_version: str,
        system_id: str,
        system_root_fingerprint: str,
        pool_id: str | None = None,
        holder_id: str | None = None,
        integration_key: str | None = None,
        signed_level1: dict | None = None,
        mode: IssuerMode = "stable",
        tree_size: int | None = None,
        leaf_store: LeafStore | None = None,
        binding_store: BindingStore | None = None,
        issuer_key: IssuerKey | None = None,
        issuer_key_id: str | None = None,
        commitment_ttl_seconds: int | None = None,
        valid_until: str | None = None,
        retry_max_elapsed_ms: int | None = None,
        retry_max_attempts: int | None = None,
        retry_base_ms: int | None = None,
        retry_cap_ms: int | None = None,
        client: CertcryptNodeClient | None = None,
    ) -> None:
        # Before anything else: this SDK implements one normative body, and
        # refusing here means the refusal lands before a key is derived,
        # capacity is touched or an artifact exists to be mistaken for a valid one.
        _assert_rules_domain_implemented(rules_version)
        size = tree_size if tree_size is not None else (1 if mode == "stable" else 4096)
        if mode == "unlinkable" and size < 2:
            raise ValueError(
                "unlinkable mode needs a treeSize >= 2 (a distinct leaf per cert)"
            )
        if commitment_ttl_seconds is not None and not (
            isinstance(commitment_ttl_seconds, int)
            and not isinstance(commitment_ttl_seconds, bool)
            and commitment_ttl_seconds > 0
        ):
            raise ValueError(
                "commitment_ttl_seconds must be a positive whole number of seconds: "
                "the verifier requires expires_at == issued_at + ttl, and a TTL of "
                "zero or less yields a commitment that is already expired"
            )
        # No default store. The leaf bookkeeping has to survive restarts, and an
        # in-memory default would restart at zero and reuse every leaf it handed
        # out — the one failure no verifier can detect.
        if mode == "unlinkable" and leaf_store is None:
            raise ValueError(
                'mode="unlinkable" requires a leaf_store: each commitment must be '
                "signed with a leaf never used before, and that bookkeeping has to "
                "survive restarts"
            )

        self._seed = (
            bytes.fromhex(keyset_seed) if isinstance(keyset_seed, str) else bytes(keyset_seed)
        )
        if len(self._seed) != 32:
            raise ValueError("keyset_seed must be 32 bytes (64 hex chars)")

        self.mode = mode
        self.rules_version = rules_version
        self.system_id = system_id
        self.system_root_fingerprint = system_root_fingerprint
        self._commitment_ttl_seconds = commitment_ttl_seconds
        self._leaf_store = leaf_store
        self._binding_store = binding_store
        self._pool_id = pool_id
        self._holder_id = holder_id
        self._integration_key = integration_key
        self._signed_level1 = signed_level1
        # End of the authorization activation mints. Only used when activating;
        # defaults to FAR_FUTURE. Its start is not the issuer's to choose: the
        # issuance service fixes it (the activation instant, never before the
        # Level-1 key) and the SDK reads it from the answer.
        self._valid_until = valid_until
        self.key_set = HolderKeySet.from_master_seed(self._seed, size)

        # The key depends on the seed alone; the id is only the label stamped
        # into the signer block (conformance family `issuer-key-derivation`).
        self._issuer_key = issuer_key or derive_issuer_key(
            self._seed, issuer_key_id or f"issuer:{self.key_set.root[:32]}"
        )
        # node-local operation id -> the server's id for it, learned at submit.
        # Only ever holds emissions THIS process made; a handle restored from
        # storage carries its `upstream_operation_id` and is registered on use.
        self._upstream_ids: dict[str, str] = {}
        # How long a submit or a read keeps retrying while the node is
        # unreachable or asks for a pause. Default 120 s, no attempt limit,
        # backoff base 200 ms and cap 30 s. Ignored when a client is passed in:
        # that client carries its own policy.
        retry_kwargs: dict[str, Any] = {}
        if retry_max_elapsed_ms is not None:
            retry_kwargs["retry_max_elapsed_ms"] = retry_max_elapsed_ms
        if retry_max_attempts is not None:
            retry_kwargs["retry_max_attempts"] = retry_max_attempts
        if retry_base_ms is not None:
            retry_kwargs["retry_base_ms"] = retry_base_ms
        if retry_cap_ms is not None:
            retry_kwargs["retry_cap_ms"] = retry_cap_ms
        self.client = client or CertcryptNodeClient(
            node_base_url, pool_id=pool_id, **retry_kwargs
        )
        # Self-verifying issuer-auth on every request (the node checks it
        # offline: no token lookup, no call to the issuance service), and the issuer's half of every
        # read. The client polls by node-local id; the read proof must cover the
        # id the server routes on, which the issuer knows because the node
        # reported it at submit — nobody declares the mapping over the wire.
        self.client.bind_issuer(
            issuer_auth_proof=self._build_issuer_auth_proof,
            issuer_read_proof=lambda resource: self._build_issuer_read_proof(
                self._upstream_ids.get(resource, resource)
            ),
            on_upstream_operation_id=self._learn_upstream_id,
        )

    def keyset_root(self) -> str:
        return self.key_set.root

    def binding(self) -> dict | None:
        """The cached Level-1 binding, or None before activation.

        Public (no secret). Persisting it is an optimization, not a requirement —
        a restart re-activates from `integration_key`.
        """
        return self._signed_level1

    def _learn_upstream_id(self, operation_id: str, upstream: str) -> None:
        """A read revealed the upstream id of a member the node delivered late
        (it answered `accepted_for_retry` at submit): sign later reads over it."""
        self._upstream_ids.setdefault(operation_id, upstream)

    def _build_issuer_auth_proof(self, method: str, url: str, body: bytes) -> str | None:
        """The `x-certcrypt-issuer-auth` header value for one request.

        base64(JSON) of `{signed_level1, disclosure, challenge, possession_b64}`.
        The challenge is fresh per call (milliseconds + random) and the
        possession signature covers it together with the request
        (`issuer_auth_message`): the node accepts it once, and a copy is good
        for nothing but repeating that very request, which the downstream
        `request_id` idempotency makes harmless. None before activation: there
        is no binding to present yet.
        """
        if not self._signed_level1:
            return None
        leaf_index = 0
        challenge = (
            f"{int(time.time() * 1000)}."
            f"{base64.b64encode(secrets.token_bytes(16)).decode('ascii')}"
        )
        possession = self.key_set.sign(
            leaf_index, issuer_auth_message(challenge, method, url, body).encode("utf-8")
        )
        proof = {
            "signed_level1": self._signed_level1,
            "disclosure": self.key_set.disclosure(leaf_index).to_wire(),
            "challenge": challenge,
            "possession_b64": base64.b64encode(possession).decode("ascii"),
        }
        return base64.b64encode(
            json.dumps(proof, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    def _build_issuer_read_proof(self, resource: str) -> str | None:
        """The issuer's half of a read chain over `resource`.

        A submit proves who its issuer is from the inside — every certificate
        carries `capacity_evidence` this key set signed. A read carries no such
        artifact, so the scope has to come from a signature: the issuer signs the
        exact resource it is asking for, and the server derives the scope from WHO
        SIGNED rather than from the credential of the node that relays it.

        The signature covers `certcrypt:read:2|<challenge>|<resource>`, with a
        challenge minted per call that the issuance service accepts once: the node
        that relays this half cannot keep it and read again on its own.

        Returns None before activation: without the Level-1 binding there is
        nothing to present, and the server refuses — the correct fail-closed
        answer.
        """
        if not self._signed_level1:
            return None
        leaf_index = 0
        challenge = (
            f"{int(time.time() * 1000)}."
            f"{base64.b64encode(secrets.token_bytes(16)).decode('ascii')}"
        )
        possession = self.key_set.sign(
            leaf_index, read_message(challenge, resource).encode("utf-8")
        )
        proof = {
            "signed_level1": self._signed_level1,
            "disclosure": self.key_set.disclosure(leaf_index).to_wire(),
            "challenge": challenge,
            "possession_b64": base64.b64encode(possession).decode("ascii"),
        }
        return base64.b64encode(
            json.dumps(proof, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    def list_unresolved_emissions(
        self, since: str, limit: int | None = None
    ) -> UnresolvedEmissions:
        """List the emissions this integration has in flight.

        `resolve_emission` requires a handle and the node's operation read
        requires an id. An issuer that lost both can still enumerate its
        in-flight emissions here: the request is authenticated by the caller's
        own key, the read chain proves the key-set root, and the server answers
        for that root's integration.

        Persisting the handle at emission remains the supported path; this method
        makes a lost handle recoverable instead of a reason to re-emit, which
        would mint a second node operation for the same certificate.

        `since` is required (RFC3339) and bounded server-side. Check `truncated`
        before treating the list as complete: a truncated page read as complete
        looks like there is nothing left to finish.
        """
        self.ensure_activated()
        # The signed resource is the QUERY, not an id — a caller that lost its
        # handles has none. `since` is signed and sent as the SAME string: the
        # node relays it verbatim and the issuance service verifies both halves over identical
        # bytes, so reformatting it anywhere breaks the chain silently.
        # The client mints the read half per attempt from `issuer_read_proof`.
        return self.client.list_unresolved_emissions(since, limit=limit)

    def activate(self) -> dict:
        """Activate the integration WITHOUT issuing anything.

        Activation is normally invisible: the first `issue()` does it on the way
        past. Call this to redeem the integration key and confirm the credentials
        at deploy time, before any certificate exists.

        A first emission reaching `Independent` is a separate, later event;
        `activate()` does not cause it.

        Idempotent, consumes no capacity, creates no certificate. Safe to call on
        every start: once the key is bound to this seed's root, presenting it
        again is a replay (`already_consumed_same_root`) answered with the same
        binding. A refusal raises `CertcryptNodeError`; check its `code` for
        `integration_key_replaced` (configure the latest key) and
        `key_set_root_already_bound` (this seed belongs to another integration).
        """
        return self.ensure_activated()

    def ensure_activated(self) -> dict:
        """Ensure we hold a Level-1 binding.

        Resolution order, each step a fallback of the previous: already in
        memory, then the binding store, then activation from `integration_key`.

        The last step is what makes a COLD RESTART work with nothing persisted:
        the keyset root is re-derived from the seed, so re-presenting the same
        integration key is an idempotent replay the server answers with the same
        binding. The store only saves the round-trip, so a load failure is
        swallowed rather than fatal.
        """
        if self._signed_level1:
            return self._signed_level1

        # Cache hit: adopt the binding AND the identifiers activation bound to it.
        # A store that returned a binding without them would leave issue() failing.
        if self._binding_store is not None:
            try:
                cached = self._binding_store.load()
            except Exception:
                cached = None  # a cache is never fatal: re-activate from the key
            if cached and cached.binding:
                self._signed_level1 = cached.binding
                self._holder_id = cached.holder_id
                if not self._pool_id:
                    self._pool_id = cached.pool_id
                return self._signed_level1

        if not self._integration_key:
            raise CertcryptNodeError(
                "not activated: provide integration_key. Keep it in config alongside "
                "keyset_seed and supply it on every start; it is not consumed by "
                "use. A pre-obtained signed_level1 also works, but then holder_id "
                "must be set."
            )

        res = self.client.activate(**self._activation_request())

        self._signed_level1 = res.signed_level1
        if not self._pool_id:
            self._pool_id = res.pool_id
        # Activation is authoritative for the holder_id emission is attributed to:
        # always adopt it, overriding any configured value, so emission is
        # attributed to the identity the activation bound.
        self._holder_id = res.holder_id

        if self._binding_store is not None:
            try:
                self._binding_store.save(
                    BindingStoreEntry(
                        binding=res.signed_level1,
                        holder_id=res.holder_id,
                        pool_id=res.pool_id,
                    )
                )
            except Exception:
                pass  # persistence is an optimization, never correctness

        return self._signed_level1

    def _activation_request(self) -> dict:
        """The keyword arguments of `CertcryptNodeClient.activate` for this issuer.

        Activation travels THROUGH A NODE, so an unsigned root would be just a
        body field in transit. Signing `certcrypt:activate:1|<code>|<root>` with a
        leaf of that very key set is something only the holder of the seed can
        do: it ties the activation code to THIS issuer's key set and no other.
        The message binds both halves on purpose, so a captured signature cannot
        be replayed against another root or another code.
        """
        code = self._integration_key or ""
        root = self.key_set.root
        message = f"{PRIVATE_SIGNING_DOMAIN_ACTIVATE}|{code}|{root}".encode("utf-8")
        possession = self.key_set.sign(_ACTIVATION_LEAF_INDEX, message)
        return {
            "code": code,
            "holder_key_set_root": root,
            "key_set_disclosure": self.key_set.disclosure(_ACTIVATION_LEAF_INDEX).to_wire(),
            "key_set_possession_b64": base64.b64encode(possession).decode("ascii"),
            "rules_version": self.rules_version,
            "system_root_fingerprint": self.system_root_fingerprint,
            # No valid_from: the issuance service fixes it, and a same-root
            # replay answers with the authorization bound at first activation.
            "valid_until": self._valid_until or FAR_FUTURE,
        }

    def issue(
        self,
        *,
        subjects: list[SubjectInput],
        declared_effective_units: str | None = None,
        consumed_quantity: str = "0",
        issued_at: str | None = None,
        expires_at: str | None = None,
        settlement_preferences: SettlementPreferences | None = None,
    ) -> IssueResult:
        """Mint a signed certificate over `subjects` and submit it.

        `consumed_quantity` defaults to "0" and should be left alone: an issuer
        cannot know what an issuance will consume. The value is resolved
        server-side and reported back in the `settlement_material` that the
        `independence_proof` binds — that is the authoritative figure.

        This is `prepare()` + `submit()` for N=1, and stays the surface almost
        every integration should use: one certificate, one request, nothing to
        persist between the two halves and no leaf left in limbo if the send
        fails.
        """
        prepared = self.prepare(
            subjects=subjects,
            declared_effective_units=declared_effective_units,
            consumed_quantity=consumed_quantity,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        result = self.submit(
            [prepared], settlement_preferences=settlement_preferences
        )
        return IssueResult(
            response=result.response,
            commitment=prepared.commitment,
            authorization_id=prepared.authorization_id,
            handle=result.handles[0],
            collections=prepared.collections,
        )

    def prepare(
        self,
        *,
        subjects: list[SubjectInput],
        declared_effective_units: str | None = None,
        consumed_quantity: str = "0",
        issued_at: str | None = None,
        expires_at: str | None = None,
    ) -> PreparedCommitment:
        """Sign ONE certificate and return its commitment WITHOUT sending it, so
        several can be submitted together with `submit()`.

        WHY IT EXISTS. N unrelated certificates sent one at a time carry the
        per-submission overhead N times; the same N prepared and submitted in a
        single request carry it once. For a batch that is the whole saving: the
        node accepts N members in one request, and this is the step before that
        send.

        WHAT IT COSTS. This is where everything irreversible happens: the
        base_certificate is signed and the leaf and operation salt are spent.
        Sending is not what consumes them. In "unlinkable" mode a prepared
        commitment that is never submitted leaves its leaf spent for good — the
        allocator is monotone on purpose (`LeafStore` has no `release()`),
        because recycling would reintroduce a reuse no verifier can detect.
        Losing a leaf costs one slot in a large key set; reusing one silently
        destroys the unlinkability the mode exists for. In "stable" mode leaf 0
        is reused by design and nothing is lost.

        So: to retry a failed send, call `submit()` again with the commitment you
        already hold. Never re-`prepare()` the same material — that signs a
        second commitment for one certificate.

        Validation is identical to `issue()` (same non-empty subjects,
        implemented profiles, system_id, root_id, pool/holder, TTL) because both
        run this method.

        All members of one submission set must share issuer and authorization;
        every commitment from the same instance does, so prepared commitments can
        be mixed freely — `submit()` rejects a mismatch before spending a request.
        """
        signed_level1 = self.ensure_activated()

        pool_id = self._pool_id
        if not pool_id:
            raise ValueError("no pool_id (set pool_id or obtain it from activation)")
        holder_id = self._holder_id
        if not holder_id:
            raise ValueError(
                "no holder_id: it is learned from activation; provide an "
                "integration_key, or set holder_id when supplying signed_level1"
            )
        if not self.system_root_fingerprint:
            raise ValueError("issue() requires system_root_fingerprint (the root_id)")
        if not self.system_id:
            raise ValueError(
                'issue() requires system_id (e.g. "certcrypt"). Without it the '
                "certificate carries an empty payload.system_id and every "
                "conformant verifier REJECTS it"
            )
        if not subjects:
            raise ValueError("issue() requires a non-empty subjects list")
        # A rules domain may admit subject profiles this SDK does not implement.
        # Canonicalizing under the wrong profile produces a commitment that is
        # well-formed and wrong, so an unimplemented profile is refused rather
        # than approximated (rules-domain/1 §14.2).
        for index, subject in enumerate(subjects):
            profile = getattr(subject, "profile", None)
            if profile is not None and profile not in IMPLEMENTED_SUBJECT_PROFILES:
                implemented = ", ".join(sorted(IMPLEMENTED_SUBJECT_PROFILES))
                raise ValueError(
                    f'issue(): subject[{index}] declares profile "{profile}", '
                    f"which this SDK does not implement. It implements: "
                    f"{implemented}. The profile fixes how the subject is "
                    "canonicalized and committed to, so emitting under one this "
                    "SDK cannot canonicalize would bind the certificate to a "
                    "commitment no conforming verifier reproduces."
                )

        # `is not None`, not truthiness: only an absent value falls back. A zero
        # TTL is refused at construction, so nothing here has to tell 0 apart
        # from "unset".
        ttl = (
            self._commitment_ttl_seconds
            if self._commitment_ttl_seconds is not None
            else COMMITMENT_TTL_SECONDS.get(self.rules_version)
        )
        if expires_at is None and ttl is None:
            raise ValueError(
                f'issue(): no commitment TTL for rules_version "{self.rules_version}". '
                "The TTL is a public rule of the rules-domain and the verifier "
                "requires expires_at == issued_at + ttl, so it cannot be guessed. "
                "Pass commitment_ttl_seconds explicitly, or use a known rules_version"
            )
        # Explicit values win whenever they are given — an empty string included,
        # which then fails as the malformed timestamp it is rather than being
        # silently replaced.
        issued = (
            issued_at
            if issued_at is not None
            else to_rfc3339_seconds(datetime.now(timezone.utc).replace(microsecond=0))
        )
        expires = expires_at if expires_at is not None else compute_expires_at(issued, ttl)

        # Spent HERE, at signing: in unlinkable mode this leaf never comes back.
        leaf_index = 0 if self.mode == "stable" else self._leaf_store.next_leaf()
        operation_salt = secrets.token_bytes(32)
        authorization_id = _derive_authorization_id(signed_level1)

        # Generated up front: it is the collection salt, so it must exist before
        # the subjects are resolved.
        nonce_hex = generate_nonce_hex()
        resolved, collections = resolve_collection_subjects(subjects, nonce_hex)

        minted = assemble_base_certificate(
            issuer_key=self._issuer_key,
            subjects=resolved,
            nonce_hex=nonce_hex,
            issued_at=issued,
            system_id=self.system_id,
            rules_version=self.rules_version,
            root_id=self.system_root_fingerprint,
        )

        evidence = assemble_evidence(
            signed_level1=signed_level1,
            certificate_commitment_digest=minted.certificate_commitment_digest,
            consumed_quantity=consumed_quantity,
            declared_effective_units=(
                declared_effective_units
                if declared_effective_units is not None
                else _sum_effective_units(subjects)
            ),
            issued_at=issued,
            expires_at=expires,
            stable=StableIdentifiers(
                holder_id=holder_id,
                pool_id=pool_id,
                authorization_id=authorization_id,
            ),
            key_set=self.key_set,
            leaf_index=leaf_index,
            operation_salt=operation_salt,
        )

        # The canonical member: exactly what the protocol needs and can verify
        # (submission-set/1 §7.1).
        commitment = LooseCommitment(
            capacity_evidence=evidence,
            operative={"holder_id": holder_id, "pool_id": pool_id},
        )
        return PreparedCommitment(
            commitment=commitment,
            base_certificate=minted.base_certificate,
            authorization_id=authorization_id,
            leaf_index=leaf_index,
            collections=collections,
        )

    def submit(
        self,
        prepared: list[PreparedCommitment],
        *,
        settlement_preferences: SettlementPreferences | None = None,
        request_id: str | None = None,
    ) -> SubmitResult:
        """Submit prepared commitments as ONE submission set and return a handle
        for each.

        This is the request `prepare()` exists to fill: N members travel together
        and amortize the per-submission overhead across all of them. It is
        N-in-one-request, synchronous — nothing is buffered and nothing is deferred.

        Handles come back in the SAME order as the input, each already correlated
        with its member of the response, so a batch of N is as persistable as a
        single emission: keep each handle and call `resolve_emission()` on it
        later.

        A retry re-sends these same commitments — the SDK never re-signs, because
        a leaf must not be reused. If the send fails after signing, the leaves are
        already spent (see `prepare()`); calling `submit()` again with the same
        list is the correct move.

        At most `MAX_SUBMISSION_SET_MEMBERS` (64) commitments make one set; more
        raise `SubmissionSetTooLargeError` before anything is sent
        (submission-set/1 §8.1). Split a larger batch into several `submit()`
        calls.
        """
        if not prepared:
            raise ValueError("submit() requires a non-empty prepared list")
        # The producer refuses to build an over-bound set (submission-set/1 §8.1).
        assert_submission_set_within_bound(len(prepared))
        # Every member of one set must answer to the same issuer and
        # authorization, or the node refuses the whole request. Caught here so a
        # mixed batch costs an error rather than a round-trip — the commitments
        # are already signed either way, but the request is not spent.
        authorization_id = prepared[0].authorization_id
        for index, item in enumerate(prepared):
            if item.authorization_id != authorization_id:
                raise ValueError(
                    f"submit(): prepared[{index}] carries authorization_id "
                    f'"{item.authorization_id}" but prepared[0] carries '
                    f'"{authorization_id}". One submission set is one issuer '
                    "under one authorization; the node refuses a mixed set. "
                    "Submit them as separate requests."
                )

        response = self.client.issue(
            [item.commitment for item in prepared],
            request_id=request_id,
            settlement_preferences=settlement_preferences,
        )

        handles: list[EmissionHandle] = []
        for position, item in enumerate(prepared):
            # Correlate by commitment_index when the node reports one (a set of N
            # comes back indexed), falling back to positional order.
            member = next(
                (r for r in response.results if r.commitment_index == position),
                None,
            )
            if member is None:
                member = (
                    response.results[position]
                    if position < len(response.results)
                    else None
                )
            operation_id = member.operation_id if member else ""
            if not operation_id:
                # A whole-request failure — a transport error reaching the issuance service, or
                # a rejection before per-member evaluation — comes back with
                # `results` EMPTY and the reason in the top-level `state`.
                # Reporting "no operation_id" hides that reason behind a symptom,
                # which is how a transient upstream failure ends up looking like a
                # protocol bug — typically under concurrency, where one request of
                # several fails this way.
                whole = getattr(response, "state", None)
                if whole:
                    name = whole.get("state") if isinstance(whole, dict) else whole
                    detail = whole.get("error") if isinstance(whole, dict) else None
                    raise CertcryptNodeError(
                        f"submit failed: {name}" + (f" — {detail}" if detail else "")
                    )
                raise CertcryptNodeError(
                    f"submit: node returned no operation_id for prepared[{position}] "
                    f"(results had {len(response.results)} entries and no top-level state)"
                )
            upstream = None
            if member and member.state_name == "accepted":
                upstream = member.state.get("upstream_operation_id")
            if upstream:
                self._upstream_ids[operation_id] = upstream
            handles.append(
                EmissionHandle(
                    operation_id=operation_id,
                    upstream_operation_id=upstream,
                    independence_ref=evidence_digest_hex(item.commitment.capacity_evidence),
                    commitment_index=(
                        member.commitment_index if member else position
                    ),
                    capacity_evidence=item.commitment.capacity_evidence,
                    base_certificate=item.base_certificate,
                    collections=item.collections,
                )
            )
        return SubmitResult(response=response, handles=handles)

    def _resolve_by_commitment(
        self, handle: EmissionHandle, verification_context: dict
    ) -> EmissionResolution:
        """Resolve an emission by the digest of the capacity evidence behind it.

        The fallback when the node no longer knows the operation. The digest is the
        one identifier the issuer can always produce, because it recomputes it from
        evidence it signed; the attempt id was never the issuer's and the node's
        operation id belongs to a journal it may no longer be talking to.

        Not a weaker path: the read still carries both halves of the chain, and the
        resource signed is the digest itself — stronger than signing an id the node
        handed over, because the issuer can check what it means. The package it
        assembles is identical, since nothing in it is node-supplied.
        """
        record = self.client.get_emission_by_commitment(handle.independence_ref)
        if record.status == "expired":
            return EmissionResolution(
                state="expired", node_state=record.status, reason_code=record.reason_code or "expired"
            )
        # Every other terminal status that is not independent_ready ends the
        # emission without a proof (insufficient_capacity, for one).
        if record.status != "independent_ready" and record.status in TERMINAL_STATES:
            return EmissionResolution(state="rejected", node_state=record.status)
        # BOTH artifacts or nothing: a package missing the settlement material does
        # not verify, and returning a half-built one would fail later and further
        # away, where the cause is no longer visible.
        if (
            record.status != "independent_ready"
            or not record.independence_proof
            or not record.settlement_material
        ):
            return EmissionResolution(state="pending", node_state=record.status)

        package = self.client.assemble_verification_package_from_proof(
            independence_proof_b64=record.independence_proof,
            settlement_material_b64=record.settlement_material,
            base_certificate=handle.base_certificate,
            capacity_evidence=handle.capacity_evidence,
            commitment_index=handle.commitment_index,
            rules_version=verification_context["rules_version"],
            system_id=verification_context["system_id"],
        )
        return EmissionResolution(
            state="independent",
            node_state=record.status,
            verification_package=package,
            independence_ref=handle.independence_ref,
        )

    def resolve_emission(
        self,
        handle: EmissionHandle,
        *,
        verification_context: dict | None = None,
        **wait_kwargs: Any,
    ) -> EmissionResolution:
        """Resolve a previously-emitted certificate from its handle.

        Polls the ONE operation and NEVER re-emits. Returns:

        - ``independent`` with the full `verification_package` once settled;
        - ``pending`` while it is still being settled, with the node's window and
          whether it is overdue;
        - ``expired`` with its `reason_code` when it can no longer settle;
        - ``rejected`` on any other terminal state (`rejected`,
          `insufficient_capacity`, `replay_detected`, `pre_evaluation_rejected`,
          `submission_failed`).

        By default this is a single status check — a reconciler wants a quick "is
        it ready yet?", not a long block. Pass `wait_for_operation` options to
        wait inline: `max_attempts` above 1, `max_wait_ms`, or
        `strategy="auto"`. A wait that ends without a terminal state reports
        ``pending``; it does not raise.

        `verification_context` (`{"rules_version", "system_id"}`) is what the
        package records; it defaults to this instance's `rules_version` and
        `system_id`.
        """
        context = verification_context or {
            "rules_version": self.rules_version,
            "system_id": self.system_id,
        }
        # A process that only RESOLVES (it did not emit) has no binding yet, so
        # every read would go unauthenticated. Activating first is idempotent.
        self.ensure_activated()
        # A handle restored from storage carries the upstream id but was never
        # registered in this process: register it before any read, so the proof
        # signs the id the server routes on.
        if handle.upstream_operation_id:
            self._upstream_ids[handle.operation_id] = handle.upstream_operation_id
        # The node's operation id lives in THAT node's journal. A node restarted
        # with an in-memory journal, or a different node entirely (the model treats
        # moving as changing a URL, not migrating), answers 404 for an emission the
        # issuance service still holds.
        #
        # The capacity-evidence digest does not have that problem: the issuer
        # recomputes it from evidence it signed itself. So a 404 here is not the end
        # of the road — it is the signal to ask by the identifier that outlives the
        # node.
        try:
            record = self.client.get_operation(handle.operation_id)
        except CertcryptNodeError as exc:
            if exc.status != 404 or not handle.independence_ref:
                raise
            return self._resolve_by_commitment(handle, context)

        node_state = record.state_name
        expired_reason = record.state.get("reason_code") if node_state == "expired" else None
        window = record.settlement_window

        # Optional bounded wait. Default: just the one check already made. When
        # the caller DOES ask to wait, its options pass through untouched, so the
        # window-aware scheduling (and `on_progress`) apply exactly as on the
        # client.
        max_attempts = wait_kwargs.get("max_attempts")
        wants_wait = bool(wait_kwargs) and (
            (max_attempts if max_attempts is not None else 1) > 1
            or wait_kwargs.get("max_wait_ms") is not None
            or wait_kwargs.get("strategy") == "auto"
        )
        if wants_wait and node_state not in TERMINAL_STATES:
            try:
                settled = self.client.wait_for_operation(handle.operation_id, **wait_kwargs)
                node_state = settled.state_name
                if node_state == "expired":
                    expired_reason = settled.state.get("reason_code")
                if settled.settlement_window:
                    window = settled.settlement_window
            except CertcryptNodeError as exc:
                # The wait ended without a terminal state. That is NOT an error
                # here: the operation is still being settled and the handle is
                # still good, so report `pending` (with the window, so the caller
                # knows when to come back). A 404 (wrong id) still propagates.
                if exc.status == 404:
                    raise

        if node_state == "expired":
            return EmissionResolution(
                state="expired",
                node_state=node_state,
                reason_code=expired_reason or "expired",
            )
        # Every other terminal state that is not independent_ready ends the
        # emission without a proof.
        if node_state != "independent_ready" and node_state in TERMINAL_STATES:
            return EmissionResolution(state="rejected", node_state=node_state)
        if node_state != "independent_ready":
            # Surface the window and whether it has already passed, so a
            # reconciler can schedule its next call instead of polling blindly —
            # and can tell a delayed operation from one that is simply not ready.
            overdue = is_settlement_overdue(window, time.time() * 1000)
            return EmissionResolution(
                state="pending",
                node_state=node_state,
                settlement_window=window,
                overdue=overdue,
            )

        package = self.client.build_verification_package(
            handle.operation_id,
            commitment_index=handle.commitment_index,
            rules_version=context["rules_version"],
            system_id=context["system_id"],
            base_certificate=handle.base_certificate,
            capacity_evidence=handle.capacity_evidence,
        )
        return EmissionResolution(
            state="independent",
            node_state=node_state,
            verification_package=package,
            independence_ref=handle.independence_ref,
        )
