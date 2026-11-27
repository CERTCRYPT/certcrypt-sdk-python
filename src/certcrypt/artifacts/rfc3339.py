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

"""RFC 3339 second-precision UTC timestamp normalization.

The server canonicalizes timestamps with zero subseconds stripped, so the
canonical bytes carry no fractional part. A sub-second input is **rejected
rather than truncated**: silently dropping the milliseconds would change the
instant the caller meant to record, and the certificate would attest to a time
nobody chose.
"""

import re
from datetime import datetime, timedelta, timezone

__all__ = ["RFC3339_SECONDS_RE", "to_rfc3339_seconds", "add_seconds"]

RFC3339_SECONDS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", re.ASCII)


def to_rfc3339_seconds(value: "datetime | str") -> str:
    """Normalize to `YYYY-MM-DDTHH:MM:SSZ`.

    A caller-supplied string is trusted only if it is already second-precision
    UTC; anything else raises rather than being reformatted, since reformatting
    would hide a timezone the caller believed was applied.
    """
    if isinstance(value, str):
        if not RFC3339_SECONDS_RE.fullmatch(value):
            raise ValueError(
                "timestamp string must be RFC 3339 UTC second precision "
                f"(…Z, no fractional seconds), got {value!r}"
            )
        return value

    if not isinstance(value, datetime):
        raise TypeError(f"timestamp must be a datetime or string, got {type(value).__name__}")

    if value.tzinfo is None:
        raise ValueError(
            "timestamp must be timezone-aware: a naive datetime would be "
            "interpreted as local time and silently shift the signed instant"
        )
    if value.microsecond != 0:
        raise ValueError(
            "timestamp must fall on a whole second (no sub-second precision is "
            "allowed in the canonical bytes)"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_seconds(issued_at: "datetime | str", seconds: int) -> str:
    """`issued_at + seconds`, keeping RFC 3339 second precision."""
    normalized = to_rfc3339_seconds(issued_at)
    parsed = datetime.strptime(normalized, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return to_rfc3339_seconds(parsed + timedelta(seconds=seconds))
