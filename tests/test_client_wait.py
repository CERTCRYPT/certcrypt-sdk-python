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

"""`wait_for_operation`: how a wait is scheduled, what it reports, and how it ends.

A wait for settlement can legitimately sleep for minutes, so what it says while
it sleeps matters as much as when it wakes: an unannounced long sleep is
indistinguishable from a hang. And a wait that ends without a terminal state is
an error, never a record that could be mistaken for an outcome.
"""

import json
import logging
from datetime import datetime, timezone

import pytest

from certcrypt.client import CertcryptNodeClient, CertcryptNodeError

_T0 = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000
_OP = "01J0000000000000000000000A"


def _win(target=None, expected=None):
    w = {"window_profile": "profile_a", "window_profile_version": "2026-07-02"}
    if target is not None:
        w["target_close_by"] = target
    if expected is not None:
        w["expected_settled_by"] = expected
    return w


def _processing(target="2020-01-01T00:00:00.000Z", progress=None, expected=None):
    body = {
        "operation_id": _OP,
        "status": "processing",
        "settlement_window": _win(target, expected),
    }
    if progress is not None:
        body["settlement_progress"] = progress
    return body


_READY = {"operation_id": _OP, "status": "independent_ready"}


class _Node:
    """Plays `bodies` in order (the last repeats); a clock whose sleeps advance it."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = 0
        self.now = _T0
        self.slept = []

    def transport(self, method, url, headers, body, timeout):
        b = self.bodies[min(self.calls, len(self.bodies) - 1)]
        self.calls += 1
        return 200, json.dumps(b), {}

    def sleep(self, seconds):
        self.slept.append(seconds * 1000)
        self.now += seconds * 1000

    def client(self):
        return CertcryptNodeClient(
            "https://node.test",
            transport=self.transport,
            now_ms=lambda: self.now,
            sleep=self.sleep,
            rand=lambda: 0.0,
        )


_AUTO = {"strategy": "auto", "backoff_base_ms": 5, "backoff_cap_ms": 5}


def test_the_wait_reports_progress_so_a_long_sleep_is_not_mistaken_for_a_hang():
    node = _Node([_processing(), _READY])
    seen = []
    record = node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    assert record.state_name == "independent_ready"
    p = seen[0]
    assert p.overdue is True
    assert p.window.window_profile == "profile_a"
    assert "OVERDUE" in p.message
    assert "profile_a" in p.message


def test_interval_and_max_attempts_select_the_fixed_schedule():
    node = _Node([_processing()])
    with pytest.raises(CertcryptNodeError, match="did not reach a terminal state"):
        node.client().wait_for_operation(_OP, interval_ms=1, max_attempts=3)
    assert node.calls == 3


def test_max_attempts_alone_also_selects_the_fixed_schedule():
    node = _Node([_processing()])
    with pytest.raises(CertcryptNodeError):
        node.client().wait_for_operation(_OP, max_attempts=2)
    # Fixed schedule: a 1 s interval, never the window-aware sleep.
    assert node.slept == [1000, 1000]


def test_an_explicit_strategy_wins_over_the_inferred_one():
    node = _Node([_processing()])
    with pytest.raises(CertcryptNodeError):
        node.client().wait_for_operation(_OP, max_attempts=2, strategy="auto",
                                         backoff_base_ms=5, backoff_cap_ms=5)
    assert node.slept == [5, 5]


def test_max_wait_ms_bounds_the_wait_by_wall_clock():
    node = _Node([_processing()])
    with pytest.raises(CertcryptNodeError, match="did not reach a terminal state"):
        node.client().wait_for_operation(_OP, max_wait_ms=60, **_AUTO)
    assert node.now - _T0 == 60


def test_a_wait_that_runs_out_names_the_last_state_and_the_window():
    node = _Node([_processing(target="2026-08-16T12:00:00Z")])
    with pytest.raises(CertcryptNodeError) as excinfo:
        node.client().wait_for_operation(_OP, interval_ms=1000, max_attempts=2)
    assert str(excinfo.value) == (
        f"operation {_OP} did not reach a terminal state after 2s (last state: processing); "
        "node expected window profile_a to close by 2026-08-16T12:00:00Z — it is OVERDUE: "
        "settlement is taking longer than the window allows"
    )


def test_the_parsed_window_carries_only_scheduling_fields():
    body = {
        "operation_id": _OP,
        "status": "processing",
        "settlement_window": {
            **_win("2026-08-16T12:00:40.000Z", "2026-08-16T12:00:55.000Z"),
            "extra_field_a": "value-a",
            "extra_field_b": "value-b",
            "vendor_note": "unexpected",
        },
    }
    record = _Node([body]).client().get_operation(_OP)
    assert sorted(vars(record.settlement_window)) == [
        "expected_settled_by",
        "target_close_by",
        "window_profile",
        "window_profile_version",
    ]


def test_the_parsed_progress_carries_only_its_three_fields():
    body = _processing(
        progress={
            "phase": "finality_pending",
            "progress_ppm": 743_000,
            "observed_at": "2026-08-16T12:00:05Z",
            "block_height": 99_999,
            "finality_lag": 3,
        }
    )
    record = _Node([body]).client().get_operation(_OP)
    progress = record.settlement_progress
    assert sorted(vars(progress)) == ["observed_at", "phase", "progress_ppm"]
    assert (progress.phase, progress.progress_ppm, progress.observed_at) == (
        "finality_pending",
        743_000,
        "2026-08-16T12:00:05Z",
    )


def test_progress_without_a_string_phase_is_no_progress():
    record = _Node([_processing(progress={"progress_ppm": 5})]).client().get_operation(_OP)
    assert record.settlement_progress is None


def test_a_settlement_waiting_on_the_chain_says_so_instead_of_blaming_the_window():
    node = _Node([_processing(progress={"phase": "finality_pending", "progress_ppm": 743_000}), _READY])
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    p = seen[0]
    assert p.settlement.phase == "finality_pending"
    assert p.settlement.progress_ppm == 743_000
    assert "irreversibility" in p.message
    assert "74%" in p.message
    assert "OVERDUE" not in p.message


def test_a_missing_progress_bar_still_reports_the_phase_without_a_percentage():
    node = _Node([_processing(progress={"phase": "finality_pending"}), _READY])
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    p = seen[0]
    assert p.settlement.progress_ppm is None
    assert "irreversibility" in p.message
    assert "%" not in p.message


def test_an_operation_still_queued_keeps_the_window_oriented_message():
    node = _Node([_processing(progress={"phase": "queued"}), _READY])
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    p = seen[0]
    assert p.settlement.phase == "queued"
    assert "OVERDUE" in p.message
    assert "irreversibility" not in p.message


def test_the_progress_reported_is_sticky():
    node = _Node(
        [
            _processing(progress={"phase": "finality_pending", "progress_ppm": 500_000}),
            _processing(),
            _READY,
        ]
    )
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    assert len(seen) >= 2
    assert seen[1].settlement.phase == "finality_pending"
    assert seen[1].settlement.progress_ppm == 500_000


def test_the_progress_message_reads_the_same_in_every_sdk():
    """Pinned verbatim: the line an integrator greps its logs for."""
    node = _Node([_processing(target="2026-08-16T12:01:00Z"), _READY])
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, backoff_cap_ms=30_000)
    assert seen[0].message == (
        "still processing after 1s — waiting for settlement window profile_a to close "
        "(~2026-08-16T12:01:00Z); next check in 63s"
    )


def test_a_window_without_an_expected_settlement_instant_parses_without_one():
    record = _Node([_processing(target="2026-08-16T12:00:20Z")]).client().get_operation(_OP)
    assert record.settlement_window.target_close_by == "2026-08-16T12:00:20Z"
    assert record.settlement_window.expected_settled_by is None


def test_while_settlement_is_expected_later_the_message_names_the_expected_instant():
    node = _Node(
        [_processing(target="2026-08-16T12:00:20Z", expected="2026-08-16T12:00:35Z"), _READY]
    )
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, backoff_cap_ms=60_000)
    assert node.slept == [29_000]
    assert seen[0].overdue is False
    assert seen[0].window.expected_settled_by == "2026-08-16T12:00:35Z"
    assert seen[0].message == (
        "still processing after 1s — waiting for settlement window profile_a to close "
        "(~2026-08-16T12:00:20Z), settlement expected by ~2026-08-16T12:00:35Z; "
        "next check in 29s"
    )


def test_a_closed_window_still_settling_before_the_expected_instant_is_not_overdue():
    node = _Node(
        [_processing(target="2026-08-16T11:59:50Z", expected="2026-08-16T12:00:05Z"), _READY]
    )
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, backoff_cap_ms=30_000)
    assert seen[0].overdue is False
    assert "OVERDUE" not in seen[0].message


def test_past_the_expected_instant_the_message_says_settlement_is_overdue():
    node = _Node(
        [_processing(target="2026-08-16T11:59:00Z", expected="2026-08-16T11:59:15Z"), _READY]
    )
    seen = []
    node.client().wait_for_operation(_OP, on_progress=seen.append, **_AUTO)
    assert seen[0].overdue is True
    assert seen[0].message == (
        "still processing after 1s — OVERDUE: settlement is past the operator's expected "
        "instant 2026-08-16T11:59:15Z (window profile_a); retrying in 1s"
    )


def test_a_wait_that_runs_out_past_the_expected_instant_names_it():
    node = _Node([_processing(target="2026-08-16T11:59:00Z", expected="2026-08-16T11:59:15Z")])
    with pytest.raises(CertcryptNodeError) as excinfo:
        node.client().wait_for_operation(_OP, interval_ms=1000, max_attempts=2)
    assert str(excinfo.value) == (
        f"operation {_OP} did not reach a terminal state after 2s (last state: processing); "
        "operator expected window profile_a to be settled by 2026-08-16T11:59:15Z — it is "
        "OVERDUE: settlement is past the operator's expected instant"
    )


def test_a_wait_that_runs_out_before_the_expected_instant_does_not_call_it_overdue():
    node = _Node([_processing(target="2026-08-16T12:00:20Z", expected="2026-08-16T12:00:35Z")])
    with pytest.raises(CertcryptNodeError) as excinfo:
        node.client().wait_for_operation(_OP, interval_ms=1000, max_attempts=2)
    assert str(excinfo.value) == (
        f"operation {_OP} did not reach a terminal state after 2s (last state: processing); "
        "operator expected window profile_a to be settled by 2026-08-16T12:00:35Z"
    )


def test_a_callback_that_raises_never_breaks_the_wait():
    def boom(_p):
        raise RuntimeError("the integrator's logger is broken")

    node = _Node([_processing(), _processing(), _READY])
    record = node.client().wait_for_operation(_OP, on_progress=boom, **_AUTO)
    assert record.state_name == "independent_ready"
    assert node.calls == 3


def test_a_long_sleep_with_no_listener_is_logged_at_info(caplog):
    node = _Node([_processing(target="2026-08-16T12:01:00Z"), _READY])
    with caplog.at_level(logging.INFO, logger="certcrypt"):
        node.client().wait_for_operation(_OP, backoff_cap_ms=30_000)
    lines = [r.getMessage() for r in caplog.records if r.name == "certcrypt"]
    assert lines == [
        f"[certcrypt] operation {_OP}: still processing after 1s — waiting for settlement "
        "window profile_a to close (~2026-08-16T12:01:00Z); next check in 63s"
    ]
    assert all(r.levelno == logging.INFO for r in caplog.records if r.name == "certcrypt")


def test_a_short_sleep_with_no_listener_is_not_logged(caplog):
    node = _Node([{"operation_id": _OP, "status": "processing"}, _READY])
    with caplog.at_level(logging.INFO, logger="certcrypt"):
        node.client().wait_for_operation(_OP, backoff_base_ms=5, backoff_cap_ms=5)
    assert [r for r in caplog.records if r.name == "certcrypt"] == []
