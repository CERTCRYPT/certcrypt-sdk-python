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

"""The transport-retry policy's reading of `Retry-After`, with inline data.

The full decision table is held to the issuance service's own retry contract
outside this repository; these are the parser edges that are this SDK's alone.
"""

from certcrypt.retry import (
    RETRY_AFTER_MAX_MS,
    RetryDecision,
    RetryPolicy,
    TransportOutcome,
    decide_retry,
    parse_retry_after,
)


def test_retry_after_is_read_as_whole_seconds_only():
    """Retry-After parsing."""
    assert parse_retry_after("30") == 30_000
    assert parse_retry_after(" 7 ") == 7_000
    assert parse_retry_after("+5") is None
    assert parse_retry_after("1.5") is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") is None
    assert parse_retry_after(None) is None


def test_an_absurd_retry_after_is_clamped_not_refused():
    """However many digits, it means "a long time": the clamp brings it to the
    ceiling rather than the parser treating it as absent."""
    huge = "9" * 5000
    assert parse_retry_after(huge) is not None
    d = decide_retry(
        RetryPolicy(max_elapsed_ms=None, max_attempts=None, backoff_base_ms=200, backoff_cap_ms=30_000),
        TransportOutcome.http(503, huge),
        0,
        0,
    )
    assert d == RetryDecision("retry", wait_ms=RETRY_AFTER_MAX_MS, counts_attempt=False)
