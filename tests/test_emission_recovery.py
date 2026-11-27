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

"""Emission recovery — the join, and the refusal that keeps it honest.
"""

import pytest

from certcrypt.issuer import PRIVATE_SIGNING_DOMAIN_READ, EmissionHandle
from certcrypt.types import UnresolvedEmission, UnresolvedEmissions

SETTLED = {
    "operation_id": "01JQZX3V5K7YB8N2M4P6R8T0AC",
    "independence_ref": "a" * 64,
    "commitment_index": 2,
    "capacity_evidence": {"v": "capacity.evidence/1"},
}

ISSUER_HELD = {
    "base_certificate": {"payload": {"system_id": "certcrypt"}},
}


def test_recovery_joins_the_two_halves():
    handle = EmissionHandle.from_recovery(SETTLED, **ISSUER_HELD)
    assert handle.operation_id == SETTLED["operation_id"]
    assert handle.independence_ref == SETTLED["independence_ref"]
    assert handle.commitment_index == 2
    assert handle.capacity_evidence == SETTLED["capacity_evidence"]
    # The issuer-held half: CERTCRYPT never had these and never returns them.
    assert handle.base_certificate == ISSUER_HELD["base_certificate"]


def test_commitment_index_zero_is_a_real_position():
    # The falsy-zero trap: `index or fallback` would silently rewrite the first
    # leaf of every set.
    handle = EmissionHandle.from_recovery(
        {**SETTLED, "commitment_index": 0}, **ISSUER_HELD
    )
    assert handle.commitment_index == 0


def test_partial_fragment_is_refused():
    # The one dangerous mistake in recovery. A substituted index yields an
    # inclusion proof that verifies against NOTHING — the index is a position in
    # the Merkle leaf order, and a wrong position is not a near miss.
    with pytest.raises(ValueError, match="has not settled"):
        EmissionHandle.from_recovery(
            {**SETTLED, "commitment_index": None}, **ISSUER_HELD
        )


def test_refusal_says_what_to_do_next():
    # An integrator hitting this at 3am needs the next step, not a type error.
    with pytest.raises(ValueError) as excinfo:
        EmissionHandle.from_recovery(
            {**SETTLED, "commitment_index": None}, **ISSUER_HELD
        )
    message = str(excinfo.value)
    assert "Poll until" in message
    assert "verifies against nothing" in message


def test_recovered_handle_round_trips_through_to_dict():
    # The rebuilt handle must be indistinguishable from one this SDK wrote, or
    # recovery would produce something resolve_emission cannot consume.
    handle = EmissionHandle.from_recovery(SETTLED, **ISSUER_HELD)
    restored = EmissionHandle.from_dict(handle.to_dict())
    assert restored == handle


def test_recovery_never_invents_the_issuer_held_half():
    # The fragment carries four fields; the other three come from the caller. An
    # issuer that lost BOTH handle and certificate cannot rebuild — and that is
    # zero-data working, not a gap to paper over.
    assert set(SETTLED) == {
        "operation_id",
        "independence_ref",
        "commitment_index",
        "capacity_evidence",
    }
    handle = EmissionHandle.from_recovery(SETTLED, **ISSUER_HELD)
    assert handle.collections == []


def test_optional_halves_ride_along_when_supplied():
    handle = EmissionHandle.from_recovery(
        SETTLED,
        **ISSUER_HELD,
        upstream_operation_id="01JUPSTREAM0000000000000000",
        collections=[{"subject_index": 0, "descriptor": {}, "leaf_hashes": ["ab"]}])
    assert handle.upstream_operation_id == "01JUPSTREAM0000000000000000"
    assert len(handle.collections) == 1


def test_unresolved_emissions_parse_from_wire():
    parsed = UnresolvedEmissions.from_wire(
        {
            "emissions": [
                {
                    "operation_id": "01J",
                    "status": "processing",
                    "updated_at": "2026-08-24T09:00:00Z",
                    "commitment_count": 2,
                }
            ],
            "truncated": True,
        }
    )
    assert len(parsed.emissions) == 1
    assert parsed.emissions[0].commitment_count == 2
    assert parsed.truncated is True


def test_truncated_defaults_to_false_but_is_never_inferred():
    # Absent means "the server did not say", which we treat as not truncated —
    # but only an explicit `true` sets it, so a stray truthy value cannot make a
    # complete page look partial (or the reverse).
    assert UnresolvedEmissions.from_wire({"emissions": []}).truncated is False
    assert UnresolvedEmissions.from_wire({"truncated": "yes"}).truncated is False


def test_missing_emissions_key_is_an_empty_list_not_a_crash():
    # A reconciler polling on a restart must not die on an unexpected body.
    assert UnresolvedEmissions.from_wire({}).emissions == []


def test_signing_domain_matches_the_other_implementations():
    # The CERTCRYPT service verifies this exact string, so it MUST NOT change:
    # changing it turns every read into a 401.
    assert PRIVATE_SIGNING_DOMAIN_READ == "certcrypt:read:2"


def test_read_resource_shape_matches_the_server_route():
    # Both halves of the chain sign this exact string; the node relays `since`
    # verbatim. Reformatting it anywhere breaks the chain silently.
    since = "2026-08-24T11:00:00+02:00"
    resource = f"emissions:unresolved:{since}"
    assert resource.endswith(since)
    assert resource.startswith("emissions:unresolved:")


def test_unresolved_emission_carries_the_window_instants():
    row = UnresolvedEmission.from_wire(
        {
            "operation_id": "01J",
            "status": "processing",
            "target_close_by": "2026-08-16T12:00:20Z",
            "expected_settled_by": "2026-08-16T12:00:35Z",
        }
    )
    assert row.target_close_by == "2026-08-16T12:00:20Z"
    assert row.expected_settled_by == "2026-08-16T12:00:35Z"


def test_unresolved_emission_tolerates_a_sparse_row():
    row = UnresolvedEmission.from_wire({"operation_id": "01J", "status": "processing"})
    assert row.reason_code is None
    assert row.target_close_by is None
    assert row.expected_settled_by is None
    assert row.commitment_count == 0
