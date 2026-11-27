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

"""Wire types for the node's HTTP surface — this SDK's only network peer.

The issuer projects and signs a `capacity.evidence/1` with a per-operation leaf
of its operation-key tree and submits it. See `artifacts.capacity_evidence` for
the byte contract.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "OperationStateName",
    "TERMINAL_STATES",
    "LooseCommitment",
    "SettlementWindowEstimate",
    "SettlementProgress",
    "MemberResult",
    "IssueResponse",
    "OperationRecord",
    "UnresolvedEmission",
    "UnresolvedEmissions",
]

#: Node-local operation state names.
OperationStateName = Literal[
    # Per-member outcomes
    "accepted",
    "rejected",
    "replay_detected",
    "insufficient_capacity",
    # Whole-request outcomes (no per-member evaluation reached)
    "pre_evaluation_rejected",
    # Transport failed, but the node has durable custody and will deliver.
    # NON-TERMINAL: poll rather than re-submit.
    "accepted_for_retry",
    "submission_failed",
    # Later async finalization, observed by polling
    "processing",
    "independent_ready",
    # Terminal after processing (submission-set/1 §11.1): the accepted member can
    # no longer reach Independent and nothing was consumed. Not a rejection — its
    # authorization ran out. Re-submit under a fresh authorization.
    "expired",
]

#: States from which an operation will not move on its own.
#:
#: `accepted_for_retry` is deliberately NOT here: the node has taken custody and
#: will deliver it, so re-submitting would emit twice. `accepted` is not terminal
#: either — it means the member was accepted for processing, not settled.
TERMINAL_STATES: frozenset[str] = frozenset(
    {
        "rejected",
        "replay_detected",
        "insufficient_capacity",
        "pre_evaluation_rejected",
        "submission_failed",
        "independent_ready",
        "expired",
    }
)


@dataclass(frozen=True)
class LooseCommitment:
    """One commitment as submitted.

    The SDK signs only the holder's `capacity_evidence` — the one step no one
    else can perform — and 1..N of these are assembled into a submission set by
    the NODE. The SDK never builds the set.

    `operative` carries the integration's fixed `(holder_id, pool_id)`, issued at
    onboarding and configured once: carried through, never freely declared per
    call. It is routing context and never reaches the verifier. It is safe in
    clear because it is not accepted on assertion: the server re-derives the
    holder/pool pseudonyms from it under the evidence's own `operation_salt` and
    rejects the member unless they equal the signed ones (submission-set/1 §7.2).

    These two fields are the whole member (submission-set/1 §7.1): the member
    carries what the protocol needs and can verify, and nothing chosen freely by
    the issuer. Results correlate by `commitment_index`.
    """

    capacity_evidence: dict
    operative: dict

    def to_wire(self) -> dict:
        return {
            "capacity_evidence": self.capacity_evidence,
            "operative": dict(self.operative),
        }


@dataclass(frozen=True)
class SettlementWindowEstimate:
    """When the node expects this operation's settlement window to close.

    OPERATIONAL ONLY. Never part of the submission set, the proof, or anything a
    verifier evaluates — it describes the NODE's schedule, not the issuer.

    ZERO-DATA BOUNDARY, deliberately absent and to stay absent: no amount and no
    capacity figure. An operation's cost is committed and never revealed,
    because in the clear it would make an issuer's operations correlatable over
    time — and once a value travels in a response it is copied into logs,
    whoever it was meant for.
    """

    #: Opaque versioned label. Log it, show it in support, but never branch on
    #: it: schedule on `target_close_by`.
    window_profile: str
    window_profile_version: str
    #: RFC 3339 instant the window is expected to CLOSE. Absent when the node has
    #: frozen a profile but cannot yet name a target. This is the window's close
    #: target, NOT the moment the package is ready — chain finality adds more
    #: after it. Treat it as "not before", never as a deadline.
    target_close_by: str | None = None
    #: RFC 3339 instant by which the operator expects this window's settlement
    #: to be anchored and final, so that a read can return a terminal state.
    #: Never earlier than `target_close_by`; present exactly when it is. The
    #: client schedules its next check on it and reports the operation overdue
    #: only once it has passed. An operational ESTIMATE from the operator: not a
    #: promise of when the operation becomes Independent, and not proof material.
    expected_settled_by: str | None = None

    @classmethod
    def from_wire(cls, data: dict | None) -> "SettlementWindowEstimate | None":
        if not data:
            return None
        return cls(
            window_profile=data.get("window_profile", ""),
            window_profile_version=data.get("window_profile_version", ""),
            target_close_by=data.get("target_close_by"),
            expected_settled_by=data.get("expected_settled_by"),
        )


@dataclass(frozen=True)
class SettlementProgress:
    """Advisory progress indicator for an in-flight settlement.

    NOT A VERDICT, and never a substitute for the artifacts. `state` remains the
    authority; this only says how far along the wait is. In particular
    `finality_pending` is NOT verifiable evidence: the settlement profile refuses
    every provisional, head-only or soft-confirmed action, so an operation only
    carries a temporal claim once its artifacts are served with
    `independent_ready`.

    Deliberately opaque about the substrate: a coarse phase and a normalized
    fraction, never blocks, ledgers or the chain's finality model. Render a bar
    from it; do not infer how the chain works, and do not gate anything on it.
    """

    #: `queued` — assigned to a window, nothing on chain yet.
    #: `finality_pending` — settled on chain, waiting for irreversibility.
    #: `final` — irreversible.
    #:
    #: An open string on purpose: a future substrate may add a phase, and code
    #: that switches exhaustively on it would break. Branch on the ones you know
    #: and fall through on the rest.
    phase: str
    #: Progress toward irreversibility as a fraction × 1e6 (743000 = 74.3%).
    #: Absent before broadcast, and where the substrate has immediate finality.
    progress_ppm: int | None = None
    #: When the operator last sampled the chain for that fraction (RFC 3339). An
    #: observation timestamp — NOT the settlement's temporal claim, which comes
    #: only from the irreversible block time inside the settlement material.
    observed_at: str | None = None

    @classmethod
    def from_wire(cls, data: Any) -> "SettlementProgress | None":
        """Copy ONLY the three known fields, never the whole object: the wire
        could grow a substrate-revealing field, and passing it through would
        hand it to a caller and its logs without anyone deciding to. A body
        without a string `phase` carries no progress."""
        if not isinstance(data, dict) or not isinstance(data.get("phase"), str):
            return None
        ppm = data.get("progress_ppm")
        observed = data.get("observed_at")
        return cls(
            phase=data["phase"],
            progress_ppm=ppm if isinstance(ppm, (int, float)) and not isinstance(ppm, bool) else None,
            observed_at=observed if isinstance(observed, str) else None,
        )


@dataclass(frozen=True)
class MemberResult:
    """One per-member result in an issue response.

    `commitment_index` is the member's position in the set as submitted, and what
    correlates this result back to the request. An issuer keeping its own label
    for a certificate associates it with that position locally.
    """

    operation_id: str
    commitment_index: int
    state: dict

    @property
    def state_name(self) -> str:
        return self.state.get("state", "")

    @classmethod
    def from_wire(cls, data: dict) -> "MemberResult":
        return cls(
            operation_id=data.get("operation_id", ""),
            commitment_index=int(data.get("commitment_index", 0)),
            state=data.get("state") or {},
        )


@dataclass(frozen=True)
class IssueResponse:
    """The node returns EITHER a per-member shape OR a whole-request shape.

    `results` populated with `state` absent is the normal path; `results` empty
    with `state` set is a pre-evaluation rejection or a transport failure. The
    two are mutually exclusive.
    """

    request_id: str
    results: list[MemberResult] = field(default_factory=list)
    submission_set_id: str | None = None
    #: Whole-request outcome, set ONLY when no per-member evaluation happened.
    #: A `submission_failed` here may carry `upstream_status` (the node answers
    #: HTTP 422): the CERTCRYPT service definitively refused the request with that
    #: HTTP status, nothing was queued, and resending the same bytes cannot change
    #: the answer — fix the cause first. Without it: the service answered in a way
    #: the node could not use, or the node could not record the outcome.
    state: dict | None = None

    @classmethod
    def from_wire(cls, data: dict) -> "IssueResponse":
        return cls(
            request_id=data.get("request_id", ""),
            results=[MemberResult.from_wire(r) for r in data.get("results") or []],
            submission_set_id=data.get("submission_set_id"),
            state=data.get("state"),
        )


@dataclass(frozen=True)
class EmissionHandleRecord:
    """Response of the issuance service's `by-commitment` lookup, relayed by the node.

    Deliberately smaller than :class:`OperationRecord`: this lookup recovers a
    handle, not the scheduling view. What it must carry is what the issuer does
    NOT already hold — the proof and the settlement material. Everything else the
    `verification_package` needs is in the handle the issuer kept.
    """

    operation_id: str
    status: str
    reason_code: str | None = None
    #: base64 of the canonical ``independence.proof/1``; only on ``independent_ready``.
    independence_proof: str | None = None
    #: base64 of the leaf's ``settlement-material/1``; only on ``independent_ready``.
    settlement_material: str | None = None
    window_status: str | None = None
    window_settled_at: str | None = None

    @classmethod
    def from_wire(cls, data: dict) -> "EmissionHandleRecord":
        return cls(
            operation_id=data["operation_id"],
            status=data["status"],
            reason_code=data.get("reason_code"),
            independence_proof=data.get("independence_proof"),
            settlement_material=data.get("settlement_material"),
            window_status=data.get("window_status"),
            window_settled_at=data.get("window_settled_at"),
        )


@dataclass(frozen=True)
class OperationRecord:
    """Normalized `GET /v1/operations/{id}` record.

    The node answers that route with one of two shapes: a local record carrying
    `state`, or the server's authoritative body forwarded verbatim, which uses
    `status` instead and drops `request_id`. `from_wire` normalizes both, so a
    caller never has to know which one arrived.

    The two proof artifacts are present only when `independent_ready`.
    """

    operation_id: str
    state: dict
    request_id: str | None = None
    #: base64 of the canonical independence proof bytes.
    independence_proof: str | None = None
    #: base64 of the canonical settlement material JSON.
    settlement_material: str | None = None
    settlement_window: SettlementWindowEstimate | None = None
    #: How far the settlement backing this operation has come, while it is in
    #: flight: "queued behind a window" versus "on chain, waiting for the
    #: substrate's irreversibility". Advisory; see `SettlementProgress`.
    settlement_progress: SettlementProgress | None = None

    @property
    def state_name(self) -> str:
        return self.state.get("state", "")

    @property
    def is_terminal(self) -> bool:
        return self.state_name in TERMINAL_STATES

    @classmethod
    def from_wire(cls, data: dict) -> "OperationRecord":
        state = data.get("state")
        if state is None and "status" in data:
            state = _state_from_server_status(data)
        return cls(
            operation_id=data.get("operation_id", ""),
            state=state or {},
            request_id=data.get("request_id"),
            independence_proof=data.get("independence_proof"),
            settlement_material=data.get("settlement_material"),
            settlement_window=SettlementWindowEstimate.from_wire(
                data.get("settlement_window")
            ),
            settlement_progress=SettlementProgress.from_wire(
                data.get("settlement_progress")
            ),
        )


def _state_from_server_status(data: dict) -> dict:
    """Map a server body forwarded verbatim (`status` is a bare string) to a state.

    Every client must read an operation the same way, so this table follows the
    statuses the issuance service defines, and only those. The service answers one
    of five statuses — processing, independent_ready, rejected,
    insufficient_capacity, expired. An operation can be rejected after it was accepted (e.g. a window whose
    settlement could not be proven), or expire: its authorization ran out before it
    could settle and nothing was consumed (submission-set/1 §11.1). Folding either
    into `processing` would leave `wait_for_operation` polling indefinitely, so every
    known terminal status is mapped explicitly. A rejection or an expiry carries
    `reason_code` and `message` like the node's own. Only an unrecognized status falls back to `processing`, so the
    poller keeps going rather than inventing a terminal state.
    """
    status = str(data.get("status") or "processing")
    operation_id = data.get("operation_id", "")
    if status == "independent_ready":
        return {"state": "independent_ready", "upstream_operation_id": operation_id}
    if status == "rejected":
        reason = data.get("reason_code")
        message = data.get("message")
        return {
            "state": "rejected",
            "reason_code": reason if isinstance(reason, str) else status,
            "message": message if isinstance(message, str) else "",
        }
    if status == "insufficient_capacity":
        return {"state": "insufficient_capacity"}
    if status == "expired":
        reason = data.get("reason_code")
        message = data.get("message")
        return {
            "state": "expired",
            "reason_code": reason if isinstance(reason, str) else status,
            "message": message if isinstance(message, str) else "",
        }
    return {"state": "processing", "upstream_operation_id": operation_id}


@dataclass(frozen=True)
class UnresolvedEmission:
    """One in-flight emission for this integration.

    Not handle material: enough to decide what to fetch and when to poll again,
    and cheap enough for a routine pending-work check. The recoverable half of a
    handle is fetched one emission at a time.

    `commitment_index` is absent here on purpose — it is not knowable while an
    emission is unresolved (it lives in the Proof of Independence, which does not
    exist until the settlement window closes).
    """

    #: The id the issuer knows this emission by — the same value its lost handle
    #: carried as `operation_id`.
    operation_id: str
    #: Public ontology only: the node reports public states, never internal ones.
    status: str
    reason_code: str | None = None
    updated_at: str | None = None
    #: RFC3339 close TARGET of the settlement window, when one was assigned.
    #: Schedule the next poll on it; treat it as "not before", never a deadline.
    target_close_by: str | None = None
    #: RFC3339 instant by which the operator expects the settlement to be
    #: anchored and final, when a window was assigned (never earlier than
    #: `target_close_by`). An operational estimate: the best moment for the
    #: next poll.
    expected_settled_by: str | None = None
    #: RFC3339 effective settle time, when already settled.
    settled_at: str | None = None
    #: How many handles this emission yields for this integration.
    commitment_count: int = 0

    @classmethod
    def from_wire(cls, data: dict) -> "UnresolvedEmission":
        return cls(
            operation_id=str(data.get("operation_id", "")),
            status=str(data.get("status", "")),
            reason_code=data.get("reason_code"),
            updated_at=data.get("updated_at"),
            target_close_by=data.get("target_close_by"),
            expected_settled_by=data.get("expected_settled_by"),
            settled_at=data.get("settled_at"),
            commitment_count=int(data.get("commitment_count", 0)),
        )


@dataclass(frozen=True)
class UnresolvedEmissions:
    """The answer to "what do I still have open?".

    `truncated` is true when the page hit the server-side cap. It MUST NOT be
    ignored: a reconciler that reads a truncated page as complete concludes there
    is nothing left to finish, and the recovery it skips becomes a re-emission.
    """

    emissions: list[UnresolvedEmission]
    truncated: bool = False

    @classmethod
    def from_wire(cls, data: dict) -> "UnresolvedEmissions":
        raw = data.get("emissions")
        items = raw if isinstance(raw, list) else []
        return cls(
            emissions=[UnresolvedEmission.from_wire(e) for e in items],
            truncated=data.get("truncated") is True,
        )


@dataclass(frozen=True)
class SettlementPreferences:
    """Issuer-elected settlement window.

    Operational only: the profile is never part of the submission set, the proof,
    or anything a verifier evaluates. Choosing a faster window changes WHEN a
    certificate becomes independently verifiable, never whether it is valid.
    """

    #: Which settlement window to close the emission's aggregate under, e.g.
    #: "close_3min" (the default profile) or "close_6h". It is NEVER a trust
    #: tier or a proof level, and does not change what the certificate asserts.
    window_profile: str
    #: What to do when the elected profile cannot be honored. "slower_allowed"
    #: permits degrading to a slower profile; "reject" prefers to fail. A window
    #: is never degraded to a FASTER one: a fallback may only move slower.
    fallback_policy: Literal["reject", "slower_allowed"] = "reject"

    def to_wire(self) -> dict:
        # snake_case is the node's contract (its settlement preferences use these
        # field names verbatim). camelCase keys deserialize to None and
        # the emission silently falls back to the default window.
        return {
            "window_profile": self.window_profile,
            "fallback_policy": self.fallback_policy,
        }
