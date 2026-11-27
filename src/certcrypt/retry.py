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

"""The transport-retry policy: after a failed request to the node, wait as long
as the node asked, back off, or give up.

Every client of a node or of the issuance service applies the following rules
identically. Two clients that decided differently would turn a node's planned
pause — a restart, an outbox it cannot write — into one client's lost
submission.

- `Retry-After` is read as a whole number of seconds only.
- A `Retry-After` the node sends with 503 or 429 is honored exactly
  (clamped to 1 s – 15 min) and is NOT a failed attempt.
- Everything else retryable is a counted attempt with full-jitter backoff.
- An attempt limit applies only when the caller sets one.
- Retrying ends on a TIME budget (default 120 s), not a count of quick
  failures: a node that restarts in 20 s is waited out, however many times the
  connection was refused meanwhile.
- A 4xx other than 408/425/429 is about the request, not the transport, and
  is handed back rather than retried.
"""

import random
import re
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "RetryPolicy",
    "RETRY_DEFAULTS",
    "RETRY_AFTER_MIN_MS",
    "RETRY_AFTER_MAX_MS",
    "TransportOutcome",
    "RetryDecision",
    "parse_retry_after",
    "decide_retry",
    "draw_backoff_ms",
]


@dataclass(frozen=True)
class RetryPolicy:
    """The policy a client runs under. ``None`` = no limit."""

    max_elapsed_ms: int | None
    max_attempts: int | None
    backoff_base_ms: int
    backoff_cap_ms: int


#: What a client does when the caller configures nothing.
RETRY_DEFAULTS = RetryPolicy(
    max_elapsed_ms=120_000,
    max_attempts=None,
    backoff_base_ms=200,
    backoff_cap_ms=30_000,
)

#: Bounds on an honored ``Retry-After``.
RETRY_AFTER_MIN_MS = 1_000
RETRY_AFTER_MAX_MS = 900_000


@dataclass(frozen=True)
class TransportOutcome:
    """One failed request, as the policy sees it.

    ``kind="transport"`` is no HTTP answer at all; ``kind="http"`` carries the
    status and the raw ``Retry-After`` header, if any.
    """

    kind: Literal["transport", "http"]
    status: int | None = None
    retry_after: str | None = None

    @classmethod
    def transport(cls) -> "TransportOutcome":
        return cls(kind="transport")

    @classmethod
    def http(cls, status: int, retry_after: str | None = None) -> "TransportOutcome":
        return cls(kind="http", status=status, retry_after=retry_after)


@dataclass(frozen=True)
class RetryDecision:
    """What to do next: ``return``, ``give_up`` or ``retry``.

    A retry carries EITHER ``wait_ms`` (an honored ``Retry-After``,
    ``counts_attempt=False``) OR ``wait_ms_max`` (a backoff ceiling the wait is
    drawn under, ``counts_attempt=True``).
    """

    action: Literal["return", "give_up", "retry"]
    wait_ms: int | None = None
    wait_ms_max: int | None = None
    counts_attempt: bool | None = None


# Exactly the ECMAScript WhiteSpace and LineTerminator code points
# (ECMA-262 `String.prototype.trim`) used by the transport-retry policy.
# Python's str.strip() differs at the
# edges (it strips U+001C–U+001F and U+0085, and keeps U+FEFF).
_JS_TRIM = (
    "\t\n\v\f\r           "
    "       　﻿"
)
_WHOLE_SECONDS = re.compile(r"[0-9]+")
# Past this many digits the value is "as long as anyone could mean" and the
# clamp brings it to the ceiling; converting it exactly is pointless and, on
# recent Pythons, refused outright.
_MAX_DIGITS = 300
_AS_LONG_AS_ANYONE_COULD_MEAN = 2**53 - 1


def parse_retry_after(raw: str | None) -> int | None:
    """Read a whole number of seconds, trimmed, and return milliseconds.

    Anything else — an HTTP date, a sign, a fraction, text — is treated as absent.
    """
    if raw is None:
        return None
    t = raw.strip(_JS_TRIM)
    if not _WHOLE_SECONDS.fullmatch(t):
        return None
    if len(t) > _MAX_DIGITS:
        return _AS_LONG_AS_ANYONE_COULD_MEAN
    return int(t) * 1000


def _is_transient(status: int) -> bool:
    return status in (408, 425, 429) or 500 <= status <= 599


def decide_retry(
    policy: RetryPolicy,
    outcome: TransportOutcome,
    counted_before: int,
    elapsed_ms: int | float,
) -> RetryDecision:
    """The decision after one failure.

    ``counted_before`` is the number of counted attempts before this failure;
    ``elapsed_ms`` the time since the first attempt.
    """
    is_http = outcome.kind == "http" and outcome.status is not None
    if is_http and not _is_transient(outcome.status):
        return RetryDecision("return")
    if policy.max_elapsed_ms is not None and elapsed_ms >= policy.max_elapsed_ms:
        return RetryDecision("give_up")
    if is_http and outcome.status in (503, 429):
        asked = parse_retry_after(outcome.retry_after)
        if asked is not None:
            wait_ms = min(max(asked, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS)
            if policy.max_elapsed_ms is not None and elapsed_ms + wait_ms > policy.max_elapsed_ms:
                return RetryDecision("give_up")  # A shorter wait cannot succeed.
            return RetryDecision("retry", wait_ms=wait_ms, counts_attempt=False)
    n = counted_before + 1
    if policy.max_attempts is not None and n >= policy.max_attempts:
        return RetryDecision("give_up")
    wait_ms_max = min(policy.backoff_cap_ms, policy.backoff_base_ms * 2 ** (n - 1))
    if policy.max_elapsed_ms is not None:
        # Never exceed the configured time budget.
        wait_ms_max = min(wait_ms_max, policy.max_elapsed_ms - elapsed_ms)
    return RetryDecision("retry", wait_ms_max=wait_ms_max, counts_attempt=True)


def draw_backoff_ms(wait_ms_max: int | float) -> int:
    """A full-jitter draw under a backoff ceiling."""
    # Uniform over the WHOLE window: under a thundering herd the halved variant
    # leaves every client's retries clustered in the back half, colliding again.
    return int(random.random() * (wait_ms_max + 1))
