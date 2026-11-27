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

"""HTTP client for the CERTCRYPT node — this SDK's only network peer.

Uses only the standard library (`urllib`) so the SDK carries no HTTP dependency;
callers who prefer `requests` or `httpx` can inject a transport.

Three behaviors here are easy to get wrong and are worth stating up front:

  - **`accepted_for_retry` is not terminal and must not be re-submitted.** The
    node has taken durable custody and will deliver the set; submitting again
    emits twice. Poll instead.
  - **A retried submit is the SAME request.** `issue()` fixes the `request_id`
    once and resends the same signed set on every attempt, so the node and the
    server deduplicate whatever arrives twice. When to retry, how long to wait
    and when to stop is the `transport-retry` policy in `retry.py`.
  - **Waiting is scheduled, not spun.** Settlement waits for a real window
    to close, so the client sleeps until the window the node reported rather than
    polling every second for minutes.
"""

import base64
import json
import logging
import math
import random
import secrets
import time
import urllib.error
import urllib.request
import hashlib
from urllib.parse import quote, urlsplit
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .artifacts.capacity_evidence import assert_submission_set_within_bound
from .artifacts.commitment_inclusion import build_commitment_inclusion_proof

#: Signing domain of the issuer's per-request proof to a node.
ISSUER_AUTH_DOMAIN = "certcrypt:issuer-auth:1"

#: What an issuer proof provider is given: the request it is for.
IssuerAuthProof = Callable[[str, str, bytes], "str | None"]


def issuer_auth_message(challenge: str, method: str, url: str, body: bytes = b"") -> str:
    """The bytes the issuer's leaf signs for `challenge` on a request:
    `certcrypt:issuer-auth:1|<challenge>|<host>|<METHOD> <path?query>|<sha3-256
    hex of the body>`.

    The node rebuilds it from the request it receives, so a proof captured in
    transit is good only for repeating that very request — not another route,
    body or node. `host` carries the port only when it is not the scheme's
    default, as an HTTP client sends it.
    """
    u = urlsplit(url)
    host = u.hostname or ""
    default_port = {"http": 80, "https": 443}.get(u.scheme)
    if u.port is not None and u.port != default_port:
        host = f"{host}:{u.port}"
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    digest = hashlib.sha3_256(body).hexdigest()
    return f"{ISSUER_AUTH_DOMAIN}|{challenge}|{host}|{method.upper()} {path}|{digest}"
from .retry import (
    RETRY_AFTER_MAX_MS,
    RETRY_AFTER_MIN_MS,
    RETRY_DEFAULTS,
    RetryPolicy,
    TransportOutcome,
    decide_retry,
    draw_backoff_ms,
    parse_retry_after,
)
from .types import (
    EmissionHandleRecord,
    SettlementPreferences,
    SettlementProgress,
    IssueResponse,
    LooseCommitment,
    OperationRecord,
    SettlementWindowEstimate,
    UnresolvedEmissions,
)

__all__ = [
    "ActivationResult",
    "CertcryptNodeError",
    "DeadLetter",
    "WaitProgress",
    "CertcryptNodeClient",
    "next_poll_delay_ms",
]

#: Extra margin past a window's close target before checking, when the node
#: reports no `expected_settled_by`: the target is when the window CLOSES, and
#: chain finality adds more after it.
WINDOW_SETTLING_MARGIN_MS = 3_000
#: Extra margin past the operator's `expected_settled_by` before the last
#: scheduled check. That instant already accounts for anchoring and finality, so
#: the margin only absorbs clock skew between this host and the operator.
EXPECTED_SETTLED_MARGIN_MS = 1_000
#: Where the early check sits between the close and `expected_settled_by`, as a
#: fraction of that span. The operator sets `expected_settled_by` with headroom so
#: that "overdue" means something; most settlements land well before it, and one
#: check inside the span finds them without waiting out the headroom.
SETTLEMENT_CHECKPOINT_FRACTION = 0.6
#: Every operation in a window shares its close, so their checks would otherwise
#: reach the node, and through it the operator, at the same instant. Each
#: scheduled check is pushed back by a random 0..this many ms: only ever later,
#: never earlier, so no check lands before the instant it is aimed at.
CHECKPOINT_SPREAD_MS = 1_000
#: Upper bound on ONE sleep towards a scheduled check. The backoff cap is far too
#: short for this: a window that closes in three minutes would otherwise be polled
#: every 30 s while it is still open, for nothing. This bound only exists so that
#: a mis-set instant cannot park the poller indefinitely; the whole wait is still
#: bounded by `max_wait_ms`.
SCHEDULED_SLEEP_CAP_MS = 10 * 60_000
#: Wall-clock bound of a wait in the window-aware (`"auto"`) strategy.
DEFAULT_MAX_WAIT_MS = 15 * 60_000
#: When no `on_progress` was supplied, a sleep at least this long is announced
#: through `logging` at INFO. Below it the wait reads as "working"; above it,
#: silence reads as a hang.
QUIET_WAIT_WARN_MS = 10_000
#: How long every request waits for the node, in seconds: 30 s.
REQUEST_TIMEOUT_S = 30.0

_log = logging.getLogger("certcrypt")

#: `(method, url, headers, body, timeout) -> (status, text, response_headers)`.
Transport = Callable[[str, str, dict, "bytes | None", float], "tuple[int, str, dict]"]


class CertcryptNodeError(Exception):
    """A node request failed. Carries the HTTP status and body when there was one.

    `retry_after_ms` is the wait the node asked for, in ms, when it refused with
    503 or 429 and a usable `Retry-After` — a restart, an outbox it could not
    write. `None` otherwise. Read by the retry policy; surfaced so a caller that
    gives up can still tell "come back in 10 s" from "broken".

    `code` is the machine-readable reason the node gave, when its body carries
    one: the `error` code of a `{error, message, request_id}` answer (a request
    the node refused before submitting it), or the whole-request `state` of an
    issue response (e.g. `submission_failed`). `None` otherwise.

    `integration_key_replaced` (HTTP 409, on activation): the integration key in
    this configuration was replaced by a newer one — regenerating the key in the
    console invalidates every previous key at once. Not retryable: update the
    configuration with the latest integration key and start again.

    `upstream_status`, for a `submission_failed` the node answered with HTTP 422,
    is the HTTP status with which the CERTCRYPT service definitively refused the
    request. Nothing was queued; resending the same request gets the same answer,
    so fix the cause before submitting anew. `None` otherwise.
    """

    def __init__(
        self,
        message: str,
        status: int | None = None,
        body: str | None = None,
        retry_after_ms: int | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.body = body
        self.retry_after_ms = retry_after_ms
        detail = _node_error_detail(body) if body else None
        self.code: str | None = detail[0] if detail else None
        self.upstream_status: int | None = detail[2] if detail else None


@dataclass(frozen=True)
class ActivationResult:
    """What `POST /v1/activate` returns, parsed.

    `signed_level1` is `{level1_binding, level1_signature}` exactly as the
    system domain signed it. `status` is `redeemed` on the first activation and
    `already_consumed_same_root` on an idempotent replay with the same key-set
    root: both are success, and a replay re-mints the same binding. All fields
    are public values.
    """

    signed_level1: dict
    holder_id: str
    pool_id: str
    status: str


@dataclass(frozen=True)
class DeadLetter:
    """A submission the node gave up delivering."""

    request_id: str
    attempts: int
    created_at_ms: int
    last_error: str | None


def _retry_after_of(status: int, headers: dict | None) -> tuple[str | None, int | None]:
    """The node's `Retry-After` as `(raw, ms)`, honored only on 503 and 429
    for the two statuses that can explicitly request a delay."""
    raw = next(
        (v for k, v in (headers or {}).items() if k.lower() == "retry-after"), None
    )
    honored = status in (503, 429)
    return raw, (parse_retry_after(raw) if honored else None)


def _node_error_detail(text: str) -> tuple[str, str, int | None] | None:
    """`(code, message, upstream_status)` from a node error body, or None.

    Two JSON shapes: an issue response with a whole-request `state`
    (`{"state": {"state", "error"?, "upstream_status"?}}`), or the node's plain
    `{error, message, request_id}`.
    """
    try:
        b = json.loads(text)
    except ValueError:
        return None  # not JSON: the status says it all
    if not isinstance(b, dict):
        return None
    state = b.get("state")
    if isinstance(state, dict) and isinstance(state.get("state"), str):
        message = state.get("error")
        if not isinstance(message, str):
            message = state.get("message")
        up = state.get("upstream_status")
        upstream = up if isinstance(up, int) and not isinstance(up, bool) else None
        return state["state"], message if isinstance(message, str) else "", upstream
    if isinstance(b.get("error"), str):
        message = b.get("message")
        return b["error"], message if isinstance(message, str) else "", None
    return None


def _describe_state(text: str) -> str:
    """` — <code>[ (upstream HTTP <n>)]: <message>` from a node error body, when it
    carries one, so the caller sees WHY the node refused, not just the status."""
    detail = _node_error_detail(text)
    if detail is None:
        return ""
    code, message, upstream = detail
    up = f" (upstream HTTP {upstream})" if upstream is not None else ""
    return f" — {code}{up}" + (f": {message}" if message else "")


#: The two statuses a successful `POST /v1/activate` carries: `redeemed` on the
#: first activation, `already_consumed_same_root` on an idempotent replay with the
#: same key-set root. Any other value is not an activation.
_ACTIVATION_STATUSES = ("redeemed", "already_consumed_same_root")

#: The fields an activation answer cannot do without, in the order a refusal
#: names them.
_ACTIVATION_REQUIRED = (
    "level1_binding",
    "level1_signature",
    "holder_id",
    "pool_id",
)
#: The required fields that must be strings, in the order a refusal names them.
_ACTIVATION_STRINGS = ("holder_id", "pool_id")


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _is_composite_signature(value: Any) -> bool:
    """The composite signature wire shape `level1_signature` must have: the shape
    the binding's verifier later reads (`alg`, `mode`, and one or more component
    signatures, each with its `alg` and `sig_b64`). The SDK carries the signature
    verbatim into every proof it presents, so a value of any other shape would
    only fail later, far from its cause."""
    if not isinstance(value, dict):
        return False
    if not _is_nonempty_str(value.get("alg")) or not _is_nonempty_str(value.get("mode")):
        return False
    components = value.get("signatures")
    if not isinstance(components, list) or not components:
        return False
    for component in components:
        if not isinstance(component, dict):
            return False
        if not _is_nonempty_str(component.get("alg")):
            return False
        if not _is_nonempty_str(component.get("sig_b64")):
            return False
        if "encoding" in component and not isinstance(component["encoding"], str):
            return False
        if "low_s" in component and not isinstance(component["low_s"], bool):
            return False
    return True


def _parse_activation(body: Any) -> "ActivationResult":
    """Read a `POST /v1/activate` answer, failing closed.

    Four refusals, checked in this order, each raising `CertcryptNodeError` with
    no HTTP status (the request itself succeeded):

      1. the body is not a JSON object: `activate returned no JSON object`;
      2. a required field is absent or empty (`None`, `""`, `0`, `False`, `{}`,
         `[]`): `activate returned no <fields>`;
      3. a field has the wrong type (`level1_binding` not an object,
         `level1_signature` not a composite signature, `holder_id` or `pool_id`
         not a string):
         `activate returned a malformed <fields>`;
      4. `status` is neither `redeemed` nor `already_consumed_same_root`:
         `activate returned an unrecognized status`.

    The checks and their order are part of the activation contract of the
    issuance service. Nothing is cached or persisted on a refusal: the caller adopts
    nothing until this returns.
    """
    if not isinstance(body, dict):
        raise CertcryptNodeError("activate returned no JSON object")
    raw = json.dumps(body)

    missing = [k for k in _ACTIVATION_REQUIRED if not body.get(k)]
    if missing:
        raise CertcryptNodeError(f"activate returned no {', '.join(missing)}", None, raw)

    malformed = []
    if not isinstance(body["level1_binding"], dict):
        malformed.append("level1_binding")
    if not _is_composite_signature(body["level1_signature"]):
        malformed.append("level1_signature")
    for k in _ACTIVATION_STRINGS:
        if not isinstance(body[k], str):
            malformed.append(k)
    if malformed:
        raise CertcryptNodeError(
            f"activate returned a malformed {', '.join(malformed)}", None, raw
        )

    status = body.get("status")
    if not isinstance(status, str) or status not in _ACTIVATION_STATUSES:
        raise CertcryptNodeError("activate returned an unrecognized status", None, raw)

    return ActivationResult(
        signed_level1={
            "level1_binding": body["level1_binding"],
            "level1_signature": body["level1_signature"],
        },
        holder_id=body["holder_id"],
        pool_id=body["pool_id"],
        status=status,
    )


#: Verdicts the client must NOT re-POST. Everything else transient (timeout,
#: transport error, `submission_failed`) is retryable.
#:
#: `accepted_for_retry` is here on purpose: the node has taken durable custody of
#: the set and will deliver it. Re-POSTing would be wasted work, and worse, it
#: invites a duplicate; the outcome is observed by polling, not by re-issuing.
_NON_RETRYABLE_STATES = frozenset(
    {
        "independent_ready",
        "accepted",
        "accepted_for_retry",
        "rejected",
        "expired",
        "insufficient_capacity",
        "replay_detected",
        # The node sends a rejection before per-member evaluation with HTTP 200;
        # resending the same set gets the same answer.
        "pre_evaluation_rejected",
    }
)


def _is_response_final(response: IssueResponse) -> bool:
    if response.state is not None:
        if response.state.get("state") == "submission_failed":
            return False
        return response.state.get("state") in _NON_RETRYABLE_STATES
    if response.results:
        return all(m.state_name in _NON_RETRYABLE_STATES for m in response.results)
    # No state and no results: treat as retryable (incomplete).
    return False


_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _new_ulid() -> str:
    """A ULID (10 time + 16 random Crockford base32 chars), the idempotency key
    `issue()` fixes once and reuses on every retry."""
    ts = int(time.time() * 1000)
    chars = []
    for _ in range(10):
        chars.append(_ULID_ALPHABET[ts % 32])
        ts //= 32
    out = "".join(reversed(chars))
    return out + "".join(_ULID_ALPHABET[b % 32] for b in secrets.token_bytes(16))


def _js_round(x: float) -> int:
    """Round half up (Python's `round` rounds half to even), for the seconds a
    give-up message reports."""
    return math.floor(x + 0.5)


@dataclass(frozen=True)
class WaitProgress:
    """What a poll tick is currently waiting on — reported to `on_progress`."""

    #: 1-based poll number.
    attempt: int
    #: The node's last reported state (e.g. `processing`).
    node_state: str
    #: Ms this tick will sleep before the next check.
    next_check_in_ms: int
    #: Total ms elapsed since the wait began.
    elapsed_ms: int
    #: True once the operator's `expected_settled_by` has passed (or, when the
    #: node reports no such instant, once `target_close_by` has passed) and the
    #: operation is still not terminal — it is running LATE. The poller has
    #: fallen back to backoff.
    overdue: bool
    #: The window the node expects to settle in, when it reported one.
    window: SettlementWindowEstimate | None
    #: A ready-to-log line describing what the wait is doing and why. A long
    #: sleep (waiting for a window) is indistinguishable from a hang unless
    #: something says so — this is that something.
    message: str
    #: How far the settlement has come, when the operator reported it: "still
    #: queued behind a window" versus "on chain, waiting for irreversibility".
    #: Advisory: never treat `finality_pending` as evidence.
    settlement: SettlementProgress | None = None


def _describe_wait(
    *,
    node_state: str,
    elapsed_ms: float,
    next_check_in_ms: float,
    overdue: bool,
    window: SettlementWindowEstimate | None,
    settlement: SettlementProgress | None,
) -> str:
    """The human-readable line carried by `WaitProgress.message`."""

    def secs(ms: float) -> str:
        return f"{max(1, _js_round(ms / 1000))}s"

    head = f"still {node_state} after {secs(elapsed_ms)}"
    # Once settlement is on the substrate the window is no longer what the wait
    # is about: it is the substrate's irreversibility, which no window scheduling shortens.
    if settlement is not None and settlement.phase == "finality_pending":
        pct = (
            ""
            if settlement.progress_ppm is None
            else f" (~{math.floor(settlement.progress_ppm / 10_000)}%)"
        )
        return (
            f"{head} — settled on chain, waiting for irreversibility{pct}; "
            f"next check in {secs(next_check_in_ms)}"
        )
    if overdue and window is not None and window.expected_settled_by:
        return (
            f"{head} — OVERDUE: settlement is past the operator's expected instant "
            f"{window.expected_settled_by} (window {window.window_profile}); "
            f"retrying in {secs(next_check_in_ms)}"
        )
    if window is not None and window.expected_settled_by:
        close = f" to close (~{window.target_close_by})" if window.target_close_by else ""
        return (
            f"{head} — waiting for settlement window {window.window_profile}{close}, "
            f"settlement expected by ~{window.expected_settled_by}; "
            f"next check in {secs(next_check_in_ms)}"
        )
    if overdue and window is not None and window.target_close_by:
        return (
            f"{head} — OVERDUE: window {window.window_profile} was due to close by "
            f"{window.target_close_by}; retrying in {secs(next_check_in_ms)}"
        )
    if window is not None and window.target_close_by:
        return (
            f"{head} — waiting for settlement window {window.window_profile} to close "
            f"(~{window.target_close_by}); next check in {secs(next_check_in_ms)}"
        )
    if window is not None:
        return (
            f"{head} — window {window.window_profile} assigned, no close estimate yet; "
            f"next check in {secs(next_check_in_ms)}"
        )
    return f"{head} — no window estimate from the node; next check in {secs(next_check_in_ms)}"


def _parse_instant_ms(value: str) -> float | None:
    """An RFC 3339 instant in epoch milliseconds, or None when it is not one.

    Accepts second precision and fractional seconds alike (`...:00Z`,
    `...:00.000Z`) and any UTC offset, because the node may send either; an
    instant without an offset is not an instant and reads as None.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp() * 1000


def _window_checkpoints(
    window: SettlementWindowEstimate | None,
) -> tuple[list[float], float | None]:
    """The checks a wait schedules for a window, in order, and the instant after
    which a still-pending operation is overdue.

    With `expected_settled_by` (E) and `target_close_by` (T): one check at
    T + 60 % of (E - T), one at E + 1 s; overdue past E. With only T: one check at
    T + 3 s; overdue past T. With only E: one check at E + 1 s. Neither (or
    neither parses): no checks, `None`.
    """
    if window is None:
        return [], None
    target_ms = _parse_instant_ms(window.target_close_by) if window.target_close_by else None
    expected_ms = (
        _parse_instant_ms(window.expected_settled_by) if window.expected_settled_by else None
    )
    if expected_ms is not None:
        # The operator never reports settlement before the close; if it did, the
        # close is still the earlier bound on a terminal state.
        due = expected_ms if target_ms is None else max(expected_ms, target_ms)
        checkpoints: list[float] = []
        if target_ms is not None and due > target_ms:
            checkpoints.append(
                target_ms + round((due - target_ms) * SETTLEMENT_CHECKPOINT_FRACTION)
            )
        checkpoints.append(due + EXPECTED_SETTLED_MARGIN_MS)
        return checkpoints, due
    if target_ms is not None:
        return [target_ms + WINDOW_SETTLING_MARGIN_MS], target_ms
    return [], None


def is_settlement_overdue(
    window: SettlementWindowEstimate | None, now_ms: float
) -> bool:
    """Whether the instant a wait is scheduled on has already passed.

    The rule a `pending` resolution reports as `overdue`: past the operator's
    `expected_settled_by` when reported, else past `target_close_by`. No polling
    margin is added; the margin only decides when the next check runs.
    """
    _, due_ms = _window_checkpoints(window)
    return due_ms is not None and now_ms > due_ms


def next_poll_delay_ms(
    *,
    attempt: int,
    now_ms: float,
    window: SettlementWindowEstimate | None,
    backoff_base_ms: int,
    backoff_cap_ms: int,
    rand: Callable[[], float] = random.random,
) -> tuple[int, bool]:
    """Choose how long to sleep before the next poll; returns `(delay_ms, overdue)`.

    A pure function on purpose: the scheduling decision is the whole point of
    window-aware waiting, and it is far easier to pin here than through a live
    poll loop.
    """
    checkpoints, _ = _window_checkpoints(window)

    def backoff() -> int:
        return min(backoff_base_ms * 2 ** max(0, attempt - 1), backoff_cap_ms)

    if checkpoints:
        upcoming = next((p for p in checkpoints if p > now_ms), None)
        if upcoming is not None:
            # The next scheduled check is still ahead: sleep straight until it
            # (plus the spread) instead of polling a window that is still open.
            # Capped only so a mis-set instant cannot park the poller indefinitely.
            spread = math.floor(min(max(rand(), 0.0), 1.0) * CHECKPOINT_SPREAD_MS)
            cap = max(SCHEDULED_SLEEP_CAP_MS, backoff_cap_ms)
            return int(min(upcoming - now_ms + spread, cap)), False
        # Every scheduled check has run and we are still not terminal: running
        # late. Back off, and SAY it is overdue rather than looking identical to a
        # normal wait.
        return backoff(), True

    return backoff(), False


class CertcryptNodeClient:
    """Talks to one CERTCRYPT node.

    Retrying follows the `transport-retry` policy (see `retry.py`) and ends on
    TIME, not on a count of quick failures: a node that restarts in 20 s is
    waited out however many times the connection was refused meanwhile. A
    `Retry-After` the node sends is honored exactly and never counted as an
    attempt.

    - `retry_max_elapsed_ms`: total time budget from the first attempt. Default
      120 000.
    - `retry_max_attempts`: max COUNTED attempts (incl. the first). Default: no
      limit — the time budget bounds the retrying. 1 disables retry.
    - `retry_base_ms`: attempt n waits a draw under `base * 2^(n-1)`. Default 200.
    - `retry_cap_ms`: cap on a single backoff wait. Default 30 000.
    - `now_ms` / `sleep` (seconds): the clock the retries run on, injectable for
      tests and simulations.
    - `issuer_read_proof`: builds the issuer's half of a READ chain over a
      resource — the `x-certcrypt-issuer-read` header. The server derives a
      read's scope from who SIGNED it, since a read carries no signed artifact
      of its own. Set by the `Certcrypt` issuer. Called again for EVERY attempt:
      the half carries a challenge the issuance service accepts once.
    - `on_upstream_operation_id`: called when a read reveals the upstream id of a
      node-local operation the caller did not know it for — a member the node
      delivered after answering `accepted_for_retry`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        pool_id: str | None = None,
        retry_max_elapsed_ms: int = RETRY_DEFAULTS.max_elapsed_ms,
        retry_max_attempts: int | None = RETRY_DEFAULTS.max_attempts,
        retry_base_ms: int = RETRY_DEFAULTS.backoff_base_ms,
        retry_cap_ms: int = RETRY_DEFAULTS.backoff_cap_ms,
        issuer_auth_proof: IssuerAuthProof | None = None,
        issuer_read_proof: Callable[[str], str | None] | None = None,
        on_upstream_operation_id: Callable[[str, str], None] | None = None,
        transport: Transport | None = None,
        now_ms: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        rand: Callable[[], float] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.pool_id = pool_id
        self._retry_policy = RetryPolicy(
            max_elapsed_ms=retry_max_elapsed_ms,
            max_attempts=None if retry_max_attempts is None else max(1, retry_max_attempts),
            backoff_base_ms=retry_base_ms,
            backoff_cap_ms=retry_cap_ms,
        )
        self._now_ms = now_ms or (lambda: time.time() * 1000)
        self._sleep = sleep or time.sleep
        #: Spreads scheduled settlement checks; injectable for tests.
        self._rand = rand or random.random
        self._issuer_auth_proof = issuer_auth_proof
        self._issuer_read_proof = issuer_read_proof
        self._on_upstream_operation_id = on_upstream_operation_id
        self._transport = transport or _urllib_transport

    def bind_issuer(
        self,
        *,
        issuer_auth_proof: IssuerAuthProof,
        issuer_read_proof: Callable[[str], str | None],
        on_upstream_operation_id: Callable[[str, str], None],
    ) -> None:
        """Attach an issuer's proof providers to a client built without them.

        The `Certcrypt` issuer calls this on a client it was handed, so an
        injected client authenticates exactly like one the issuer built. A
        provider the client already has is kept.
        """
        self._issuer_auth_proof = self._issuer_auth_proof or issuer_auth_proof
        self._issuer_read_proof = self._issuer_read_proof or issuer_read_proof
        self._on_upstream_operation_id = (
            self._on_upstream_operation_id or on_upstream_operation_id
        )

    def _read_headers(self, resource: str) -> Callable[[], dict | None]:
        """The `x-certcrypt-issuer-read` header for `resource`, minted per attempt.

        A callable, not a dict: the issuer's half carries a challenge the issuance
        service spends on first use, so a retry that reused it would be a 401.
        """

        def build() -> dict | None:
            proof = self._issuer_read_proof(resource) if self._issuer_read_proof else None
            return {"x-certcrypt-issuer-read": proof} if proof else None

        return build

    def _auth_headers(
        self, method: str, url: str, body: bytes | None, extra: dict | None = None
    ) -> dict:
        """Headers for authenticated requests (issue, operations, emission
        lookups, dead letters). `/health` and `/v1/activate` need no issuer
        proof.

        Zero-trust auth: the node authenticates an issuer ONLY by the
        self-verifying proof in `x-certcrypt-issuer-auth` — the system-domain-signed
        binding over the holder_key_set_root + a leaf disclosure + a possession
        signature over a fresh challenge bound to THIS request (method, URL,
        body; see `issuer_auth_message`), built anew for every attempt. The node
        verifies it offline, with no token lookup. No `Authorization` header is
        sent: the node would ignore it, and a bearer credential handed to a node
        buys nothing but exposure. Your scope derives from the proof, never from
        the request body.
        """
        headers = dict(extra or {})
        if self._issuer_auth_proof:
            proof = self._issuer_auth_proof(method, url, body or b"")
            if proof:
                headers["x-certcrypt-issuer-auth"] = proof
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        headers: dict | Callable[[], dict | None] | None = None,
        timeout: float = REQUEST_TIMEOUT_S,
        idempotent: bool = False,
    ) -> Any:
        """Perform one request; an idempotent one is retried under the
        `transport-retry` policy.

        Only idempotent calls are retried here. `issue()` has its own loop, which
        is safe to retry because it fixes the `request_id` first; any other POST
        is sent once.
        """
        url = f"{self.base_url}{path}"
        payload = json.dumps(body).encode("utf-8") if body is not None else None

        started = self._now_ms()
        counted = 0
        while True:
            # A fresh proof per ATTEMPT: the node accepts a challenge once, so
            # reusing the first attempt's header would turn every retry of a
            # request that reached the node into a 401.
            # Same for the read half, which is why `headers` may be a builder.
            extra = headers() if callable(headers) else headers
            request_headers = self._auth_headers(method, url, payload, extra)
            if payload is not None:
                request_headers.setdefault("content-type", "application/json")
            try:
                status, text, response_headers = self._transport(
                    method, url, request_headers, payload, timeout
                )
            except Exception as exc:  # transport-level failure
                outcome = TransportOutcome.transport()
                last = CertcryptNodeError(f"{method} {path} failed: {exc}")
                cause: Exception | None = exc
            else:
                if status < 400:
                    return json.loads(text) if text else None
                raw, retry_after_ms = _retry_after_of(status, response_headers)
                outcome = TransportOutcome.http(status, raw)
                last = CertcryptNodeError(
                    f"{method} {path} failed with HTTP {status}", status, text, retry_after_ms
                )
                cause = None

            if not idempotent:
                raise last from cause
            if self._settle_failure(last, outcome, counted, started, cause):
                counted += 1

    def _settle_failure(
        self,
        last: CertcryptNodeError,
        outcome: TransportOutcome,
        counted: int,
        started: float,
        cause: Exception | None,
    ) -> bool:
        """Apply the policy to one failure: raise, or sleep before the next attempt.

        Returns whether the failure spent an attempt.
        """
        d = decide_retry(self._retry_policy, outcome, counted, self._now_ms() - started)
        if d.action == "return":
            raise last from cause  # about the request, not the transport
        if d.action == "give_up":
            raise CertcryptNodeError(
                f"{last} — gave up after {_js_round((self._now_ms() - started) / 1000)}s "
                f"and {counted + 1} attempt(s)",
                last.status,
                last.body,
                last.retry_after_ms,
            ) from cause
        if d.counts_attempt:
            self._sleep(draw_backoff_ms(d.wait_ms_max) / 1000)
            return True
        self._sleep(d.wait_ms / 1000)
        return False

    def health(self) -> bool:
        """Liveness check. True when the node answers /health with a 2xx.

        One request, never retried, bounded at 30 s, and it never raises: a
        transport failure (refused, reset, no answer in time) and an error status
        both report False. A liveness probe that waited out a restart would
        report the node alive minutes late instead of reporting it down.
        """
        try:
            status, _, _ = self._transport(
                "GET", f"{self.base_url}/health", {}, None, REQUEST_TIMEOUT_S
            )
        except Exception:
            return False
        return 200 <= status < 300

    def activate(
        self,
        *,
        code: str,
        holder_key_set_root: str,
        key_set_disclosure: dict,
        key_set_possession_b64: str,
        rules_version: str,
        system_root_fingerprint: str,
        valid_until: str,
    ) -> "ActivationResult":
        """Activate an integration by redeeming its activation code (TOFU).

        The node forwards this verbatim to the server's `POST /v1/activate`; the
        server redeems the code, mints the Level-1 authorization over
        `holder_key_set_root` and returns the signed binding inline. The caller
        (usually `Certcrypt`) caches it and presents it on every later request.

        `key_set_disclosure` is a leaf of `holder_key_set_root` plus its
        inclusion path, and `key_set_possession_b64` that leaf's ML-DSA-65
        signature over `certcrypt:activate:1|<code>|<holder_key_set_root>`.
        Together they prove the root belongs to the sender and not to a node
        that substituted its own in transit. `rules_version` and
        `system_root_fingerprint` come from the onboarding config; the server
        refuses a fingerprint other than its own.

        Sent once, never retried here: a failed activation is a refusal to act
        on (`integration_key_replaced`, `key_set_root_already_bound`, an expired
        key), not a transient to wait out. A refusal raises `CertcryptNodeError`
        carrying `status` and the server's `code`.
        """
        try:
            body = self._request(
                "POST",
                "/v1/activate",
                body={
                    "code": code,
                    "holder_key_set_root": holder_key_set_root,
                    "key_set_disclosure": key_set_disclosure,
                    "key_set_possession_b64": key_set_possession_b64,
                    "rules_version": rules_version,
                    "system_root_fingerprint": system_root_fingerprint,
                    "valid_until": valid_until,
                },
            )
        except CertcryptNodeError as exc:
            if exc.status is None:
                raise
            raise CertcryptNodeError(
                f"activate failed: HTTP {exc.status}{_describe_state(exc.body or '')}",
                exc.status,
                exc.body,
                exc.retry_after_ms,
            ) from exc
        except ValueError as exc:  # a 2xx whose body is not JSON at all
            raise CertcryptNodeError("activate returned no JSON object") from exc
        # The server binds the integration's canonical (holder_id, pool_id) at
        # activation and echoes both (the node relays them verbatim). The caller
        # MUST emit under this holder_id: emitting under a self-chosen one would
        # not be accounted for against this integration at all. A 200 that is
        # not an activation is refused before anything is adopted.
        return _parse_activation(body)

    def issue(
        self,
        commitments: list[LooseCommitment],
        *,
        request_id: str | None = None,
        settlement_preferences: SettlementPreferences | None = None,
    ) -> IssueResponse:
        """Submit 1..N commitments. The NODE assembles the submission set.

        `settlement_preferences` is the issuer's elected settlement window. It is
        operational only and never reaches the proof; omit it to accept the
        default profile.

        Transient failures (timeout, 5xx, connection refused, node
        `submission_failed`, a node restarting) are retried under the
        `transport-retry` policy. Every attempt carries the SAME `request_id`, so
        the server deduplicates idempotently — a retry never re-signs and never
        double-submits. Final verdicts (`rejected`, `insufficient_capacity`,
        `replay_detected`, `accepted_for_retry`) are returned at once, and a 4xx
        other than 408/425/429 raises at once.

        More than `MAX_SUBMISSION_SET_MEMBERS` (64) commitments raise
        `SubmissionSetTooLargeError` before anything is sent
        (submission-set/1 §8.1).
        """
        if not commitments:
            raise ValueError("issue requires at least one commitment")
        # The producer refuses to build an over-bound set
        # (submission-set/1 §8.1): fail fast, before the request leaves the
        # process. The node and the submit endpoint reject one independently.
        assert_submission_set_within_bound(len(commitments))
        body: dict[str, Any] = {"commitments": [c.to_wire() for c in commitments]}
        # Fixed ONCE here and reused on every retry: the server deduplicates on
        # it. Left to the node (its fallback), each retry would get a new id and
        # stop being idempotent. The signed evidence is likewise built once — a
        # retry is transport-only and never re-signs, because a leaf must not be
        # reused.
        body["request_id"] = request_id if request_id is not None else _new_ulid()
        if settlement_preferences is not None:
            body["settlement_preferences"] = settlement_preferences.to_wire()

        path = "/v1/issue"
        url = f"{self.base_url}{path}"
        payload = json.dumps(body).encode("utf-8")

        started = self._now_ms()
        counted = 0
        while True:
            # Fresh per attempt, for the same reason as in `_request`.
            request_headers = self._auth_headers(
                "POST", url, payload, {"content-type": "application/json"}
            )
            cause: Exception | None = None
            try:
                status, text, response_headers = self._transport(
                    "POST", url, request_headers, payload, REQUEST_TIMEOUT_S
                )
            except Exception as exc:
                # No HTTP answer at all: refused, reset, timed out — the node restarting.
                outcome = TransportOutcome.transport()
                last = CertcryptNodeError(f"issue failed: {exc}")
                cause = exc
            else:
                try:
                    data = json.loads(text)
                except ValueError:
                    data = None
                if 200 <= status < 300:
                    if not isinstance(data, dict):
                        outcome = TransportOutcome.transport()
                        last = CertcryptNodeError(
                            "issue failed: unparseable node response", status, text
                        )
                    else:
                        response = IssueResponse.from_wire(data)
                        # A response with any non-final member is retryable;
                        # otherwise return it — `accepted_for_retry` included:
                        # the node holds the set.
                        if _is_response_final(response):
                            return response
                        outcome = TransportOutcome.transport()
                        shown = data.get("state")
                        if shown is None:
                            shown = data.get("results")
                        last = CertcryptNodeError(
                            f"issue not final (retryable): {json.dumps(shown)}",
                            status,
                            text,
                        )
                else:
                    raw, retry_after_ms = _retry_after_of(status, response_headers)
                    outcome = TransportOutcome.http(status, raw)
                    last = CertcryptNodeError(
                        f"issue failed: HTTP {status}{_describe_state(text)}",
                        status,
                        text,
                        retry_after_ms,
                    )

            if self._settle_failure(last, outcome, counted, started, cause):
                counted += 1

    def list_dead_letters(self) -> list[DeadLetter]:
        """This integration's submissions the node gave up delivering (dead-lettered).

        A node keeps retrying an unreachable or unavailable server for as long as
        it takes; what lands here is a refusal about the request or the node's own
        credentials, which retrying unchanged cannot fix. Empty is the healthy
        answer. Delivery metadata only — never the stored set.
        """
        body = self._request("GET", "/v1/outbox/dead", idempotent=True) or {}
        return [
            DeadLetter(
                request_id=str(d.get("request_id") if d.get("request_id") is not None else ""),
                attempts=int(d.get("attempts") or 0),
                created_at_ms=int(d.get("created_at_ms") or 0),
                last_error=d.get("last_error") if isinstance(d.get("last_error"), str) else None,
            )
            for d in body.get("dead") or []
        ]

    def redrive_dead_letter(self, request_id: str) -> None:
        """Put one dead-lettered submission back in the node's delivery queue,
        once whatever refused it has been fixed.

        The node resends the SAME signed set under the same `request_id` —
        nothing is re-signed, and the server deduplicates. Raises 404 for an id
        this integration does not own.
        """
        # Percent-encode everything but the RFC 3986 unreserved marks, so the
        # path segment is the same whatever characters the id carries.
        segment = quote(request_id, safe="!~*'()")
        self._request("POST", f"/v1/outbox/dead/{segment}/redrive")

    def get_operation(self, operation_id: str) -> OperationRecord:
        """Fetch one operation, normalizing the node's two response shapes."""
        return self._read_operation(operation_id, idempotent=True)

    def _read_operation(self, operation_id: str, *, idempotent: bool) -> OperationRecord:
        # The issuer's half of the read chain, bound to THIS operation id. The
        # node adds its own half and forwards both; the server verifies the
        # pair. Binding the resource is what stops a signature captured for one
        # read from being replayed against another operation.
        record = OperationRecord.from_wire(
            self._request(
                "GET",
                f"/v1/operations/{operation_id}",
                idempotent=idempotent,
                headers=self._read_headers(operation_id),
            )
        )
        # A member the node delivered LATE (it answered `accepted_for_retry` at
        # submit) reaches `accepted` with an upstream id the issuer was never
        # told. The node's local record carries it; hand it over so the caller
        # can route later reads on it.
        if self._on_upstream_operation_id and record.state_name == "accepted":
            upstream = record.state.get("upstream_operation_id")
            if upstream:
                self._on_upstream_operation_id(operation_id, upstream)
        return record

    def get_emission_by_commitment(self, independence_ref: str) -> EmissionHandleRecord:
        """Read one emission by the digest of the capacity evidence that produced it.

        The lookup that outlives the node. A node's operation id lives in THAT
        node's journal, so a restart with an in-memory journal — or moving to
        another node, which the model treats as changing a URL — leaves the issuer
        unable to ask about an emission the issuance service still holds. The
        digest has no such problem: the issuer recomputes it from evidence it signed itself.

        The read chain is unchanged, and the signed resource is the digest. That is
        stronger than signing an id the node handed over: the issuer can check what
        the digest means, because it produced it.
        """
        # No id translation here, unlike an operation read: the digest IS the
        # resource the server routes and verifies on.
        headers = self._read_headers(independence_ref)
        return EmissionHandleRecord.from_wire(
            self._request(
                "GET",
                f"/v1/emissions/by-commitment/{independence_ref}",
                idempotent=True,
                headers=headers,
            )
        )

    def list_unresolved_emissions(
        self,
        since: str,
        *,
        limit: int | None = None,
    ) -> UnresolvedEmissions:
        """List the emissions this integration has in flight.

        Reading one operation requires an id, and an issuer that lost its handles
        lost the ids with them: they travel only in the emission response. This
        endpoint lets such an issuer enumerate its in-flight emissions instead of
        re-emitting, which would open a second node operation for the same
        certificate — the outcome the handle exists to prevent.

        Scope is this integration, resolved server-side from the key-set root the
        read proof establishes, not from any credential of the node that relays
        it.

        The issuer's half of the read chain, over `emissions:unresolved:<since>`,
        comes from `issuer_read_proof`. Without it the server refuses: the node's
        own credential says who is relaying, the signature says on whose behalf.

        The `since` sent here MUST be byte-identical to the one that was signed —
        the node relays it verbatim and the server verifies both halves over the
        same bytes, so reformatting it anywhere breaks the chain silently.
        """
        query = f"?since={quote(since, safe='')}"
        if limit is not None:
            query += f"&limit={int(limit)}"
        headers = self._read_headers(f"emissions:unresolved:{since}")
        # Idempotent: a GET that lists is safe to retry on a transient failure.
        # No empty-list fallback on error — a reconciler would read that as
        # "nothing pending" and act on it by re-emitting.
        return UnresolvedEmissions.from_wire(
            self._request(
                "GET", f"/v1/emissions/unresolved{query}", headers=headers, idempotent=True
            )
        )

    def wait_for_operation(
        self,
        operation_id: str,
        *,
        interval_ms: int | None = None,
        max_attempts: int | None = None,
        strategy: str | None = None,
        max_wait_ms: float | None = None,
        backoff_base_ms: int | None = None,
        backoff_cap_ms: int | None = None,
        on_progress: Callable[[WaitProgress], None] | None = None,
    ) -> OperationRecord:
        """Poll until the operation reaches a terminal state, or raise.

        Terminal states: `independent_ready`, `rejected`, `expired`,
        `replay_detected`, `insufficient_capacity`, `pre_evaluation_rejected`,
        `submission_failed`. When the wait ends without one, this raises
        `CertcryptNodeError` ("did not reach a terminal state"): the operation
        is still progressing and the caller's handle stays valid, so poll again
        later.

        Scheduling (`strategy`):

        - ``"auto"`` (the default when neither `interval_ms` nor `max_attempts`
          is given): when the node reports a settlement window, sleep until
          `expected_settled_by` plus a small clock-skew margin (or, when the
          node reports only the close, `target_close_by` plus a small settling
          margin) and check on arrival;
          otherwise exponential backoff from `backoff_base_ms` (default 1000)
          capped at `backoff_cap_ms` (default 30 000). Attempts are unlimited
          and `max_wait_ms` (default 15 minutes) bounds the wait.
        - ``"fixed"`` (the default when `interval_ms` or `max_attempts` is
          given): a poll every `interval_ms` (default 1000), at most
          `max_attempts` polls (default 60), and no wall-clock bound unless
          `max_wait_ms` is given.

        When both bounds are set, whichever trips first ends the wait.

        A transient poll failure does NOT abort the wait — a network blip while
        waiting on a real settlement window is expected. Five consecutive ones
        do. A 404 is different: the id is wrong, so it surfaces immediately. A
        node that asks for a pause (503 or 429 with `Retry-After`, a restart) is
        waited out without counting it as a failure.

        `on_progress` is called before each sleep with a `WaitProgress`; an
        exception it raises is swallowed, so reporting never breaks the wait.
        Without it, a sleep of 10 s or more, or an overdue window, is logged at
        INFO on the ``certcrypt`` logger. Each poll is one request; the wait
        owns the retrying. Time is read from the client's clock.
        """
        explicitly_fixed = interval_ms is not None or max_attempts is not None
        mode = strategy or ("fixed" if explicitly_fixed else "auto")
        interval = interval_ms if interval_ms is not None else 1000
        base_ms = backoff_base_ms if backoff_base_ms is not None else 1000
        cap_ms = backoff_cap_ms if backoff_cap_ms is not None else 30_000
        # In fixed mode the attempt cap has a default; in auto mode the wall
        # clock is the real bound and attempts are effectively unlimited.
        attempts_cap = (
            max_attempts
            if max_attempts is not None
            else (60 if mode == "fixed" else math.inf)
        )
        wait_bound = (
            max_wait_ms
            if max_wait_ms is not None
            else (math.inf if mode == "fixed" else DEFAULT_MAX_WAIT_MS)
        )

        started = self._now_ms()
        last: OperationRecord | None = None
        poll_errors = 0  # consecutive transient poll failures
        last_window: SettlementWindowEstimate | None = None
        # Sticky like `last_window`: a tick whose response omitted it keeps
        # reporting the last thing actually known rather than regressing.
        last_settlement: SettlementProgress | None = None

        attempt = 0
        while attempt < attempts_cap:
            try:
                last = self._read_operation(operation_id, idempotent=False)
                poll_errors = 0
                # Remember the last window reported: once terminal the field is
                # gone, and a blip should not lose the schedule we were waiting on.
                if last.settlement_window:
                    last_window = last.settlement_window
                if last.settlement_progress:
                    last_settlement = last.settlement_progress
                if last.is_terminal:
                    return last
            except CertcryptNodeError as exc:
                if exc.status == 404:
                    raise
                # The node asked for a pause (a restart): wait it out without
                # counting it as a failure — the same rule the submit path follows.
                if exc.retry_after_ms is not None:
                    asked = min(max(exc.retry_after_ms, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS)
                    left = wait_bound - (self._now_ms() - started)
                    if left <= 0:
                        break
                    self._sleep(min(asked, left) / 1000)
                    attempt += 1
                    continue
                poll_errors += 1
                if poll_errors >= 5:
                    raise

            now = self._now_ms()
            elapsed = now - started
            if mode == "fixed":
                delay_ms, overdue = interval, False
            else:
                delay_ms, overdue = next_poll_delay_ms(
                    attempt=attempt + 1,
                    now_ms=now,
                    window=last_window,
                    backoff_base_ms=base_ms,
                    backoff_cap_ms=cap_ms,
                    rand=self._rand,
                )

            # Stop at the wall-clock bound rather than sleeping past it.
            remaining = wait_bound - elapsed
            if remaining <= 0:
                break
            sleep_ms = int(min(delay_ms, remaining))

            state = last.state_name if last else "unknown"
            message = _describe_wait(
                node_state=state,
                elapsed_ms=elapsed,
                next_check_in_ms=sleep_ms,
                overdue=overdue,
                window=last_window,
                settlement=last_settlement,
            )
            if on_progress is not None:
                try:
                    on_progress(
                        WaitProgress(
                            attempt=attempt + 1,
                            node_state=state,
                            next_check_in_ms=sleep_ms,
                            elapsed_ms=int(elapsed),
                            overdue=overdue,
                            window=last_window,
                            message=message,
                            settlement=last_settlement,
                        )
                    )
                except Exception:
                    pass  # a reporting callback must never break the wait
            elif sleep_ms >= QUIET_WAIT_WARN_MS or overdue:
                # NOBODY is listening and the wait is about to sleep for a long
                # time (or is already late). An unannounced multi-minute sleep is
                # indistinguishable from a hang; say so once per tick.
                _log.info("[certcrypt] operation %s: %s", operation_id, message)

            self._sleep(sleep_ms / 1000)
            attempt += 1

        waited = self._now_ms() - started
        message = (
            f"operation {operation_id} did not reach a terminal state after "
            f"{_js_round(waited / 1000)}s"
        )
        if last is not None:
            message += f" (last state: {last.state_name})"
        if last_window is not None and last_window.expected_settled_by:
            message += (
                f"; operator expected window {last_window.window_profile} to be settled "
                f"by {last_window.expected_settled_by}"
            )
            _, due_ms = _window_checkpoints(last_window)
            if due_ms is not None and self._now_ms() > due_ms:
                message += (
                    " — it is OVERDUE: settlement is past the operator's expected instant"
                )
        elif last_window is not None and last_window.target_close_by:
            message += (
                f"; node expected window {last_window.window_profile} to close by "
                f"{last_window.target_close_by} — it is OVERDUE: settlement is taking "
                "longer than the window allows"
            )
        raise CertcryptNodeError(message)

    def build_verification_package(
        self,
        operation_id: str,
        *,
        commitment_index: int,
        rules_version: str,
        system_id: str,
        base_certificate: dict,
        capacity_evidence: dict | None = None,
        **wait_kwargs: Any,
    ) -> dict:
        """Assemble the `verification_package` an offline verifier consumes.

        The package has a closed member set (verification-package/1):
        `base_certificate` and `verification_context` are always present, so the
        certificate is a required argument.

        Waits for the operation first, with `wait_for_operation` and the wait
        options passed here, so it raises the same "did not reach a terminal
        state" error when the wait ends without one. It also raises when the
        operation ended anywhere but `independent_ready`, or without its proof
        artifacts.

        The commitment inclusion proof is derived HERE, client-side, from
        `consumed_commitment_ids` in the `independence_proof` — the node never
        returns it.
        """
        record = self.wait_for_operation(operation_id, **wait_kwargs)
        if record.state_name != "independent_ready":
            raise CertcryptNodeError(
                f"operation {operation_id} is not independent_ready "
                f"(state: {record.state_name}) — no proof to package"
            )
        if not record.independence_proof or not record.settlement_material:
            raise CertcryptNodeError(
                f"operation {operation_id} reached independent_ready but the node "
                "returned no proof/settlement material"
            )

        import base64

        independence_proof = json.loads(
            base64.b64decode(record.independence_proof).decode("utf-8")
        )
        settlement_material = json.loads(
            base64.b64decode(record.settlement_material).decode("utf-8")
        )

        consumed = independence_proof.get("consumed_commitment_ids")
        if not isinstance(consumed, list) or not consumed:
            raise CertcryptNodeError(
                f"independence_proof for {operation_id} has no "
                "consumed_commitment_ids — cannot derive the inclusion proof"
            )

        package: dict[str, Any] = {
            "base_certificate": base_certificate,
            "independence_proof": independence_proof,
            "verification_context": {
                "rules_version": rules_version,
                "system_id": system_id,
            },
            "commitment_inclusion_proof": build_commitment_inclusion_proof(
                consumed, commitment_index
            ),
            "settlement_material": settlement_material,
        }
        if capacity_evidence is not None:
            package["capacity_evidence"] = capacity_evidence
        return package

    def assemble_verification_package_from_proof(
        self,
        *,
        independence_proof_b64: str,
        settlement_material_b64: str,
        base_certificate: Any,
        capacity_evidence: Any,
        commitment_index: int,
        rules_version: str,
        system_id: str,
    ) -> dict[str, Any]:
        """Assemble a `verification_package` from artifacts already in hand.

        Same shaping as :meth:`build_verification_package`, without the polling:
        the caller recovered the proof and the settlement material some other way —
        by the capacity-evidence digest, typically, when the node that emitted no
        longer has the operation.

        The package is identical either way. Nothing here is node-supplied: the
        inclusion proof is derived from the proof's own ``consumed_commitment_ids``,
        and the rest comes from the handle the issuer kept.
        """
        import base64

        independence_proof = json.loads(
            base64.b64decode(independence_proof_b64).decode("utf-8")
        )
        settlement_material = json.loads(
            base64.b64decode(settlement_material_b64).decode("utf-8")
        )

        consumed = independence_proof.get("consumed_commitment_ids")
        if not isinstance(consumed, list) or not consumed:
            raise CertcryptNodeError(
                "independence_proof has no consumed_commitment_ids — "
                "cannot derive the inclusion proof"
            )

        package: dict[str, Any] = {
            "base_certificate": base_certificate,
            "independence_proof": independence_proof,
            "verification_context": {
                "rules_version": rules_version,
                "system_id": system_id,
            },
            "commitment_inclusion_proof": build_commitment_inclusion_proof(
                consumed, commitment_index
            ),
            "settlement_material": settlement_material,
        }
        if capacity_evidence is not None:
            package["capacity_evidence"] = capacity_evidence
        return package


def _urllib_transport(
    method: str, url: str, headers: dict, body: bytes | None, timeout: float
) -> tuple[int, str, dict]:
    """Default transport: stdlib only, so the SDK carries no HTTP dependency.

    Response headers are returned because the node's `Retry-After` decides how
    long a client waits.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8"), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read().decode("utf-8", errors="replace"),
            dict(exc.headers.items()) if exc.headers else {},
        )
